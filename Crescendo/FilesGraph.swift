import Cocoa

//= FilesGraph.swift  version 0.1.0 (2026-11-09)
//= Graph view of file activity, drawn natively, with two layouts:
//=   Horizontal tree  root on the left, branches to the right; files carry a badge with their change count, deleted files a red cross.
//=   Sunburst         concentric rings, one per folder level; the angle of an arc is the share of changes below that path.
//= Scale: a busy capture has thousands of paths, so the graph starts with default filters (each can be switched off):
//=   - the busiest N paths only (default 200; folders on the way are added so the structure stays connected)
//=   - only changes by processes of the current user (default on)
//=   - hide changes by Apple platform binaries (system-signed by the OS) (default on)
//= The status line always says how many paths and rows are hidden. Single-child folder chains are shown as one node ("Users/me/Library").

enum GraphLayout: Int { case tree, sunburst }

struct GraphOptions {
    var layout = GraphLayout.tree
    var cap = 200                  //= 0 = no limit
    var userMode = 1               //= 0 all users, 1 only me, 2 only root
    var hideApple = true

    func passes(_ row: FileRow) -> Bool {
        if hideApple && row.platform { return false }
        switch userMode {
        case 1: return row.actorUid == Int(getuid())
        case 2: return row.actorUid == 0
        default: return true
        }
    }
}

//= one drawn node
final class GNode {
    var name: String
    let path: String
    var children = [GNode]()
    weak var parent: GNode?
    var total = 0, own = 0, other = 0          //= other: changes below this node that are not drawn
    var counts = [String: Int]()
    var lastCategory = ""
    var isDirectory = false
    var source: PathNode?
    var depth = 0
    var x: CGFloat = 0, y: CGFloat = 0, boxWidth: CGFloat = 0     //= tree layout
    var a0 = 0.0, a1 = 0.0                                          //= sunburst angles in radians
    var colorIndex = 0

    init(name: String, path: String) {
        self.name = name
        self.path = path
    }

    var isLeaf: Bool { children.isEmpty }
}

struct GraphResult {
    var root: GNode
    var shown = 0
    var totalPaths = 0
    var rowsKept = 0
    var rowsHidden = 0
}

enum GraphModel {
    static func build(_ rows: [FileRow], _ options: GraphOptions) -> GraphResult {
        let tree = PathTree()
        var kept = 0, hidden = 0
        for row in rows where row.category != "meta" {
            if options.passes(row) { tree.add(row); kept += 1 } else { hidden += 1 }
        }
        //= candidates: paths that changed themselves, busiest first
        var all = [PathNode]()
        collect(tree.root, &all)
        let candidates = all.filter { $0.ownCount > 0 }.sorted {
            $0.ownCount != $1.ownCount ? $0.ownCount > $1.ownCount : $0.total > $1.total
        }
        //= take candidates until the cap is reached; the folders leading to them are added (and counted) so the graph stays connected
        var selected = Set<ObjectIdentifier>()
        var count = 0
        for node in candidates {
            if options.cap > 0 && count >= options.cap { break }
            var chain = [PathNode]()
            var cursor: PathNode? = node
            while let current = cursor, current !== tree.root {
                if !selected.contains(ObjectIdentifier(current)) { chain.append(current) }
                cursor = current.parent
            }
            if options.cap > 0 && count + chain.count > options.cap { continue }
            for member in chain { selected.insert(ObjectIdentifier(member)) }
            count += chain.count
        }
        let root = make(tree.root, parent: nil, tree: tree, selected: selected, isRoot: true)
        compact(root)
        finish(root, depth: 0)
        var top = 0
        for child in root.children { assignColors(child, top); top += 1 }
        return GraphResult(root: root, shown: count, totalPaths: all.count, rowsKept: kept, rowsHidden: hidden)
    }

    private static func collect(_ node: PathNode, _ out: inout [PathNode]) {
        for child in node.children.values {
            out.append(child)
            collect(child, &out)
        }
    }

    private static func make(_ p: PathNode, parent: GNode?, tree: PathTree, selected: Set<ObjectIdentifier>, isRoot: Bool = false) -> GNode {
        let node = GNode(name: isRoot ? "/" : p.name, path: p.path)
        node.parent = parent
        node.total = p.total
        node.own = p.ownCount
        node.counts = p.counts
        node.lastCategory = p.lastCategory
        node.isDirectory = p.isDirectory || !p.children.isEmpty
        node.source = p
        for child in tree.children(of: p) where selected.contains(ObjectIdentifier(child)) {
            node.children.append(make(child, parent: node, tree: tree, selected: selected))
        }
        return node
    }

    //= a folder without changes of its own and with a single drawn child is merged into that child: "Users" + "me" -> "Users/me"
    private static func compact(_ node: GNode) {
        for index in node.children.indices {
            var child = node.children[index]
            while child.own == 0, child.children.count == 1 {
                let only = child.children[0]
                only.name = child.name + "/" + only.name
                only.parent = node
                child = only
            }
            node.children[index] = child
            compact(child)
        }
    }

    private static func finish(_ node: GNode, depth: Int) {
        node.depth = depth
        node.other = max(0, node.total - node.own - node.children.reduce(0) { $0 + $1.total })
        for child in node.children { finish(child, depth: depth + 1) }
    }

    private static func assignColors(_ node: GNode, _ index: Int) {
        node.colorIndex = index
        for child in node.children { assignColors(child, index) }
    }
}

//= the drawing surface (flipped: origin at the top left)
final class GraphCanvas: NSView {
    override var isFlipped: Bool { true }

    var root: GNode?
    var layout = GraphLayout.tree
    var selected: GNode?
    var onSelect: ((GNode?) -> Void)?
    var iconFor: ((GNode) -> NSImage)?
    var topCount = 1

    private var nodes = [GNode]()
    private let labelFont = NSFont.systemFont(ofSize: 12)
    private let smallFont = NSFont.systemFont(ofSize: 10)
    private let rowHeight: CGFloat = 26
    private let margin: CGFloat = 24
    private let ringWidth: CGFloat = 70
    private let centerRadius: CGFloat = 46
    private var center = CGPoint.zero
    private var trackingAreaRef: NSTrackingArea?

    //= after a refresh the nodes are new objects: select the one with the same path again (no callback)
    func reselect(_ path: String?) {
        selected = path.flatMap { wanted in nodes.first { $0.path == wanted } }
    }

    //= computes positions for the current layout and resizes the canvas; returns the size
    @discardableResult
    func relayout() -> CGSize {
        nodes = []
        guard let root = root else { setFrameSize(NSSize(width: 100, height: 100)); needsDisplay = true; return .zero }
        flatten(root)
        topCount = max(1, root.children.count)
        let size = layout == .tree ? layoutTree(root) : layoutSunburst(root)
        setFrameSize(NSSize(width: max(size.width, 200), height: max(size.height, 200)))
        needsDisplay = true
        return size
    }

    private func flatten(_ node: GNode) {
        nodes.append(node)
        for child in node.children { flatten(child) }
    }

    //= ---- horizontal tree layout ----------------------------------------------------------------------------
    private func nodeWidth(_ node: GNode) -> CGFloat {
        let text = (node.name as NSString).size(withAttributes: [.font: labelFont]).width
        return 16 + 6 + min(text, 300) + 14           //= icon, gap, label, room for the badge
    }

    private func layoutTree(_ root: GNode) -> CGSize {
        var depthWidth = [CGFloat]()
        for node in nodes {
            node.boxWidth = nodeWidth(node)
            while depthWidth.count <= node.depth { depthWidth.append(0) }
            depthWidth[node.depth] = max(depthWidth[node.depth], node.boxWidth)
        }
        var xs = [CGFloat]()
        var cursor = margin
        for width in depthWidth {
            xs.append(cursor)
            cursor += width + 70
        }
        var nextLeaf: CGFloat = 0
        func place(_ node: GNode) {
            node.x = xs[node.depth]
            if node.isLeaf {
                node.y = margin + nextLeaf * rowHeight
                nextLeaf += 1
            } else {
                for child in node.children { place(child) }
                node.y = ((node.children.first?.y ?? 0) + (node.children.last?.y ?? 0)) / 2
            }
        }
        place(root)
        return CGSize(width: cursor - 70 + margin, height: margin * 2 + max(1, nextLeaf) * rowHeight)
    }

    //= ---- sunburst layout -----------------------------------------------------------------------------------
    private func layoutSunburst(_ root: GNode) -> CGSize {
        root.a0 = 0
        root.a1 = 2 * Double.pi
        func spread(_ node: GNode) {
            var start = node.a0
            let span = node.a1 - node.a0
            let denominator = Double(max(1, node.total))
            for child in node.children {
                let share = span * Double(child.total) / denominator
                child.a0 = start
                child.a1 = start + share
                start += share
                spread(child)
            }
        }
        spread(root)
        let maxDepth = nodes.map { $0.depth }.max() ?? 0
        let radius = centerRadius + CGFloat(maxDepth) * ringWidth + margin
        center = CGPoint(x: radius, y: radius)
        return CGSize(width: radius * 2, height: radius * 2)
    }

    private func ringRadii(_ node: GNode) -> (inner: CGFloat, outer: CGFloat) {
        let inner = centerRadius + CGFloat(node.depth - 1) * ringWidth
        return (inner, inner + ringWidth)
    }

    private func point(_ radius: CGFloat, _ angle: Double) -> CGPoint {
        CGPoint(x: center.x + radius * CGFloat(cos(angle)), y: center.y + radius * CGFloat(sin(angle)))
    }

    private func arcPath(_ node: GNode) -> NSBezierPath {
        let (inner, outer) = ringRadii(node)
        let path = NSBezierPath()
        let steps = max(2, Int((node.a1 - node.a0) / (Double.pi / 90)))
        path.move(to: point(outer, node.a0))
        for i in 1 ... steps { path.line(to: point(outer, node.a0 + (node.a1 - node.a0) * Double(i) / Double(steps))) }
        for i in (0 ... steps).reversed() { path.line(to: point(inner, node.a0 + (node.a1 - node.a0) * Double(i) / Double(steps))) }
        path.close()
        return path
    }

    //= ---- drawing -------------------------------------------------------------------------------------------
    override func draw(_ dirtyRect: NSRect) {
        NSColor.textBackgroundColor.setFill()
        dirtyRect.fill()
        guard root != nil else { return }
        if layout == .tree { drawTree() } else { drawSunburst() }
    }

    private func drawTree() {
        NSColor.tertiaryLabelColor.setStroke()
        for node in nodes {
            for child in node.children {
                let line = NSBezierPath()
                line.lineWidth = 1
                line.move(to: CGPoint(x: node.x + node.boxWidth - 8, y: node.y))
                line.line(to: CGPoint(x: child.x - 2, y: child.y))
                line.stroke()
            }
        }
        for node in nodes {
            let box = NSRect(x: node.x - 4, y: node.y - 11, width: node.boxWidth + 2, height: 22)
            if node === selected {
                NSColor.selectedContentBackgroundColor.setFill()
                NSBezierPath(roundedRect: box, xRadius: 5, yRadius: 5).fill()
            }
            let icon = iconFor?(node)
            icon?.draw(in: NSRect(x: node.x, y: node.y - 8, width: 16, height: 16))
            let deleted = node.isLeaf && node.lastCategory == "deleted"
            let color: NSColor = deleted ? .systemRed : (node === selected ? .alternateSelectedControlTextColor : .labelColor)
            let label = node.name as NSString
            label.draw(in: NSRect(x: node.x + 22, y: node.y - 8, width: min(node.boxWidth - 22, 320), height: 16),
                       withAttributes: [.font: labelFont, .foregroundColor: color, .paragraphStyle: truncating()])
            if node.isLeaf || node.own > 0 {                   //= the badge: how many changes this very path had
                let n = node.own > 0 ? node.own : node.total
                if n > 1 { badge(String(n), at: CGPoint(x: node.x + 14, y: node.y - 9)) }
            }
        }
    }

    private func truncating() -> NSParagraphStyle {
        let style = NSMutableParagraphStyle()
        style.lineBreakMode = .byTruncatingMiddle
        return style
    }

    private func badge(_ text: String, at origin: CGPoint) {
        let size = (text as NSString).size(withAttributes: [.font: smallFont])
        let box = NSRect(x: origin.x, y: origin.y, width: max(14, size.width + 6), height: 13)
        NSColor.systemOrange.setFill()
        NSBezierPath(roundedRect: box, xRadius: 6.5, yRadius: 6.5).fill()
        (text as NSString).draw(at: CGPoint(x: box.minX + (box.width - size.width) / 2, y: box.minY), withAttributes: [.font: smallFont, .foregroundColor: NSColor.white])
    }

    private func drawSunburst() {
        guard let root = root else { return }
        for node in nodes where node !== root {
            guard node.a1 - node.a0 > 0.002 else { continue }
            let hue = CGFloat(node.colorIndex) / CGFloat(max(1, topCount))
            let brightness = max(0.55, 0.97 - 0.08 * CGFloat(node.depth))
            let fill = node.isLeaf && node.lastCategory == "deleted"
                ? NSColor(calibratedHue: 0, saturation: 0.55, brightness: 0.95, alpha: 1)
                : NSColor(calibratedHue: hue, saturation: 0.5, brightness: brightness, alpha: 1)
            let path = arcPath(node)
            fill.setFill()
            path.fill()
            (node === selected ? NSColor.labelColor : NSColor.textBackgroundColor).setStroke()
            path.lineWidth = node === selected ? 2.5 : 0.7
            path.stroke()
            let (inner, outer) = ringRadii(node)
            let mid = (inner + outer) / 2
            let arcLength = mid * CGFloat(node.a1 - node.a0)
            if arcLength > 46 {
                let spot = point(mid, (node.a0 + node.a1) / 2)
                let width = min(arcLength - 6, ringWidth + 20)
                (node.name as NSString).draw(in: NSRect(x: spot.x - width / 2, y: spot.y - 7, width: width, height: 14),
                                             withAttributes: [.font: smallFont, .foregroundColor: NSColor.black, .paragraphStyle: truncatingCentered()])
            }
        }
        //= the centre: the root and its total
        let hub = NSBezierPath(ovalIn: NSRect(x: center.x - centerRadius + 4, y: center.y - centerRadius + 4, width: (centerRadius - 4) * 2, height: (centerRadius - 4) * 2))
        NSColor.controlBackgroundColor.setFill()
        hub.fill()
        NSColor.separatorColor.setStroke()
        hub.stroke()
        let title = "\(root.total)\nchanges" as NSString
        let style = NSMutableParagraphStyle()
        style.alignment = .center
        title.draw(in: NSRect(x: center.x - 38, y: center.y - 14, width: 76, height: 30),
                   withAttributes: [.font: smallFont, .foregroundColor: NSColor.labelColor, .paragraphStyle: style])
    }

    private func truncatingCentered() -> NSParagraphStyle {
        let style = NSMutableParagraphStyle()
        style.alignment = .center
        style.lineBreakMode = .byTruncatingTail
        return style
    }

    //= ---- hit testing, selection, tooltip -------------------------------------------------------------------
    private func node(at location: CGPoint) -> GNode? {
        if layout == .tree {
            return nodes.first { NSRect(x: $0.x - 4, y: $0.y - 11, width: $0.boxWidth + 2, height: 22).contains(location) }
        }
        let dx = Double(location.x - center.x), dy = Double(location.y - center.y)
        let radius = CGFloat((dx * dx + dy * dy).squareRoot())
        var angle = atan2(dy, dx)
        if angle < 0 { angle += 2 * Double.pi }
        return nodes.first { node in
            guard node.depth > 0 else { return false }
            let (inner, outer) = ringRadii(node)
            return radius >= inner && radius < outer && angle >= node.a0 && angle < node.a1
        }
    }

    override func mouseDown(with event: NSEvent) {
        let hit = node(at: convert(event.locationInWindow, from: nil))
        selected = hit
        needsDisplay = true
        onSelect?(hit)
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let existing = trackingAreaRef { removeTrackingArea(existing) }
        let area = NSTrackingArea(rect: bounds, options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect], owner: self, userInfo: nil)
        addTrackingArea(area)
        trackingAreaRef = area
    }

    override func mouseMoved(with event: NSEvent) {
        guard let hit = node(at: convert(event.locationInWindow, from: nil)) else { toolTip = nil; return }
        var text = "\(hit.path)\n\(hit.total) change(s) at or below"
        let parts = [("created", "created"), ("deleted", "deleted"), ("modified", "modified"), ("attributes", "attributes")]
            .compactMap { pair in hit.counts[pair.0].map { "\($0) \(pair.1)" } }
        if !parts.isEmpty { text += ": " + parts.joined(separator: ", ") }
        if hit.other > 0 { text += "\n\(hit.other) more change(s) below are not drawn (cap)" }
        toolTip = text
    }
}

//= the graph with its toolbar (layout, caps, filters, zoom, image export)
final class FilesGraphView: NSObject {
    let view = NSStackView()
    var onSelect: ((PathNode?) -> Void)?
    var iconFor: ((PathNode) -> NSImage)?

    private let canvas = GraphCanvas()
    private let scroll = NSScrollView()
    private let layoutPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let capPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let userPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let appleCheck = NSButton(checkboxWithTitle: "Hide Apple system processes", target: nil, action: nil)
    private let infoLabel = NSTextField(labelWithString: "")
    private var lastRows = [FileRow]()
    private var firstFit = true
    private static let caps = [50, 100, 200, 500, 1000, 0]

    override init() {
        super.init()
        let defaults = UserDefaults.standard
        layoutPopup.addItems(withTitles: ["Horizontal Tree", "Sunburst"])
        layoutPopup.selectItem(at: defaults.integer(forKey: "graph.layout") == 1 ? 1 : 0)
        layoutPopup.toolTip = "Horizontal tree: root on the left, branches to the right. Sunburst: one ring per folder level, arc size = share of changes."
        capPopup.addItems(withTitles: FilesGraphView.caps.map { $0 == 0 ? "All paths" : "Busiest \($0) paths" })
        let savedCap = defaults.object(forKey: "graph.cap") as? Int ?? 200
        capPopup.selectItem(at: FilesGraphView.caps.firstIndex(of: savedCap) ?? 2)
        capPopup.toolTip = "How many paths to draw: the busiest ones (folders leading to them are added). Everything else is summarised in the tooltips."
        userPopup.addItems(withTitles: ["All users", "Only my processes (uid \(getuid()))", "Only root (uid 0)"])
        userPopup.selectItem(at: defaults.object(forKey: "graph.user") as? Int ?? 1)
        userPopup.toolTip = "Show only changes made by processes running as this user"
        appleCheck.state = (defaults.object(forKey: "graph.hideApple") as? Bool ?? true) ? .on : .off
        appleCheck.toolTip = "Hide changes made by Apple platform binaries (programs signed by the operating system itself)"
        for control in [layoutPopup, capPopup, userPopup] as [NSControl] {
            control.target = self
            control.action = #selector(optionsChanged)
        }
        appleCheck.target = self
        appleCheck.action = #selector(optionsChanged)
        let fit = NSButton(title: "Fit", target: self, action: #selector(fitToWindow))
        fit.toolTip = "Zoom so the whole graph fits (pinch or Command-scroll zooms freely)"
        let actual = NSButton(title: "100%", target: self, action: #selector(actualSize))
        actual.toolTip = "Zoom to actual size"
        let save = NSButton(title: "Save Image...", target: self, action: #selector(saveImage))
        save.toolTip = "Save the graph as a PNG picture"
        infoLabel.textColor = .secondaryLabelColor
        infoLabel.lineBreakMode = .byTruncatingTail
        infoLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        infoLabel.setContentCompressionResistancePriority(NSLayoutConstraint.Priority(1), for: .horizontal)
        let bar = NSStackView(views: [layoutPopup, capPopup, userPopup, appleCheck, fit, actual, save])
        bar.orientation = .horizontal
        let status = NSStackView(views: [infoLabel])

        canvas.onSelect = { [weak self] node in self?.onSelect?(node?.source) }
        canvas.iconFor = { [weak self] node in
            guard let source = node.source, let icon = self?.iconFor?(source) else { return NSImage() }
            return icon
        }
        scroll.documentView = canvas
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.allowsMagnification = true
        scroll.minMagnification = 0.15
        scroll.maxMagnification = 4
        scroll.borderType = .noBorder
        scroll.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)

        view.orientation = .vertical
        view.alignment = .leading
        view.spacing = 6
        for sub in [bar, status, scroll] as [NSView] { view.addArrangedSubview(sub) }
        scroll.widthAnchor.constraint(equalTo: view.widthAnchor).isActive = true
        status.widthAnchor.constraint(equalTo: view.widthAnchor).isActive = true
    }

    private var options: GraphOptions {
        GraphOptions(layout: layoutPopup.indexOfSelectedItem == 1 ? .sunburst : .tree,
                     cap: FilesGraphView.caps[max(0, capPopup.indexOfSelectedItem)],
                     userMode: max(0, userPopup.indexOfSelectedItem), hideApple: appleCheck.state == .on)
    }

    //= ---- feeding -------------------------------------------------------------------------------------------
    func update(_ rows: [FileRow]) {
        lastRows = rows
        let opts = options
        let result = GraphModel.build(rows, opts)
        let keep = canvas.selected?.path
        canvas.layout = opts.layout
        canvas.root = result.root
        canvas.relayout()
        canvas.reselect(keep)
        if firstFit, !rows.isEmpty {                         //= the first picture is zoomed to fit the window
            firstFit = false
            DispatchQueue.main.async { [weak self] in self?.fitToWindow() }
        }
        var text = "showing \(result.shown) of \(result.totalPaths) changed paths"
        if result.rowsHidden > 0 { text += " - \(result.rowsHidden) of \(result.rowsKept + result.rowsHidden) rows hidden by the graph filters (user / Apple)" }
        infoLabel.stringValue = text
        infoLabel.toolTip = "Badge = number of changes of that path; red = deleted. Change the caps and filters above to see more."
    }

    @objc private func optionsChanged() {
        let defaults = UserDefaults.standard
        defaults.set(layoutPopup.indexOfSelectedItem, forKey: "graph.layout")
        defaults.set(FilesGraphView.caps[max(0, capPopup.indexOfSelectedItem)], forKey: "graph.cap")
        defaults.set(userPopup.indexOfSelectedItem, forKey: "graph.user")
        defaults.set(appleCheck.state == .on, forKey: "graph.hideApple")
        update(lastRows)
    }

    //= ---- zoom and export -----------------------------------------------------------------------------------
    @objc private func fitToWindow() {
        let content = scroll.contentSize
        let size = canvas.frame.size
        guard size.width > 0, size.height > 0 else { return }
        scroll.magnification = max(scroll.minMagnification, min(scroll.maxMagnification, min(content.width / size.width, content.height / size.height, 1)))
        canvas.scroll(.zero)
    }

    @objc private func actualSize() { scroll.magnification = 1 }

    @objc private func saveImage() {
        guard let rep = canvas.bitmapImageRepForCachingDisplay(in: canvas.bounds) else { return }
        canvas.cacheDisplay(in: canvas.bounds, to: rep)
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "file-activity-graph.png"
        guard panel.runModal() == .OK, let url = panel.url, let data = rep.representation(using: .png, properties: [:]) else { return }
        do { try data.write(to: url) } catch { NSLog("cannot save the image: %@", error.localizedDescription) }
    }
}
