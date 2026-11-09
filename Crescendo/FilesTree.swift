import Cocoa

//= FilesTree.swift  version 0.1.0 (2026-11-09)
//= Tree view of file activity: the changed paths as a folder hierarchy with change counts rolled up through the folders, so busy
//= places stand out. It is fed with the same filtered rows as the list (filters and hidden folders apply).
//= Model: PathNode / PathTree (plain Swift). View: FilesTreeView (an NSOutlineView with a small toolbar).

final class PathNode {
    let name: String
    let path: String
    weak var parent: PathNode?
    var children = [String: PathNode]()
    var sorted: [PathNode]?                 //= cache of the children in display order; nil = must be rebuilt
    var counts = [String: Int]()            //= per category, for this path and everything below it
    var total = 0                           //= all changes at or below this path
    var ownCount = 0                        //= changes of exactly this path
    var firstTs = "", lastTs = "", lastCategory = ""
    var lastRow: FileRow?                   //= newest change of exactly this path
    var processes = [String: Int]()         //= process name -> changes at or below this path
    var isDirectory = false

    init(name: String, path: String, parent: PathNode?) {
        self.name = name
        self.path = path
        self.parent = parent
    }
}

enum TreeSort: Int {
    case name, recent, active

    var title: String {
        switch self {
        case .name: return "Sort by Name"
        case .recent: return "Most Recent First"
        case .active: return "Most Active First"
        }
    }
}

final class PathTree {
    private(set) var root = PathNode(name: "/", path: "/", parent: nil)
    var sort = TreeSort.name {
        didSet { invalidate(root) }
    }

    func reset() { root = PathNode(name: "/", path: "/", parent: nil) }

    func rebuild(_ rows: [FileRow]) {
        reset()
        for row in rows { add(row) }
    }

    //= adds one change: every folder on the way gets its counts updated, the last node remembers the change itself
    func add(_ row: FileRow) {
        guard row.category != "meta", row.path.hasPrefix("/") else { return }
        let parts = row.path.split(separator: "/").map { String($0) }
        guard !parts.isEmpty else { return }
        var node = root
        bump(node, row)
        var path = ""
        for (index, part) in parts.enumerated() {
            path += "/" + part
            let child: PathNode
            if let existing = node.children[part] {
                child = existing
            } else {
                child = PathNode(name: part, path: path, parent: node)
                node.children[part] = child
                node.isDirectory = true
                node.sorted = nil
            }
            bump(child, row)
            if sort != .name { node.sorted = nil }      //= counts or times changed the order
            node = child
            if index == parts.count - 1 {
                node.ownCount += 1
                node.lastRow = row
                if node.children.isEmpty, ((row.mode ?? 0) & 0o170000) == 0o040000 { node.isDirectory = true }
            }
        }
    }

    private func bump(_ node: PathNode, _ row: FileRow) {
        node.counts[row.category, default: 0] += 1
        node.total += 1
        if node.firstTs.isEmpty || row.ts < node.firstTs { node.firstTs = row.ts }
        if row.ts >= node.lastTs { node.lastTs = row.ts; node.lastCategory = row.category }
        if !row.process.isEmpty { node.processes[row.process, default: 0] += 1 }
    }

    private func invalidate(_ node: PathNode) {
        node.sorted = nil
        for child in node.children.values { invalidate(child) }
    }

    func children(of node: PathNode) -> [PathNode] {
        if let cached = node.sorted { return cached }
        let list: [PathNode]
        switch sort {
        case .name: list = node.children.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case .recent: list = node.children.values.sorted { $0.lastTs > $1.lastTs }
        case .active: list = node.children.values.sorted { $0.total > $1.total }
        }
        node.sorted = list
        return list
    }
}

//= Delete in the tree hides the selected folder, like in the list
final class FilesOutline: NSOutlineView {
    var onHide: (() -> Void)?
    var onRestore: (() -> Void)?

    override func keyDown(with event: NSEvent) {
        if event.keyCode == 51 || event.keyCode == 117 {
            if event.modifierFlags.contains(.command) { onRestore?() } else { onHide?() }
        } else {
            super.keyDown(with: event)
        }
    }
}

final class FilesTreeView: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate {
    let view = NSStackView()
    let tree = PathTree()

    var onSelect: ((PathNode?) -> Void)?
    var iconFor: ((PathNode) -> NSImage)?
    var onHideFolder: ((String) -> Void)?
    var onOnlyFolder: ((String) -> Void)?
    var onRestoreHidden: (() -> Void)?

    private let outline = FilesOutline()
    private let scroll = NSScrollView()
    private let sortPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private var firstFill = true

    private let columns: [(id: String, title: String, width: CGFloat, tip: String)] = [
        ("name", "Path", 380, "Folders and files that changed. The disclosure triangle opens a folder."),
        ("total", "Changes", 70, "All changes at or below this path"),
        ("created", "Created", 62, "Files and folders created at or below this path"),
        ("deleted", "Deleted", 62, "Deleted at or below this path"),
        ("modified", "Modified", 66, "Content modified at or below this path"),
        ("attributes", "Attr.", 52, "Attributes, permissions, owner, flags or extended attributes changed"),
        ("moved", "Moved", 56, "Moved or renamed (counts both halves of a rename)"),
        ("last", "Last Change", 110, "Local time of the newest change at or below this path"),
    ]

    override init() {
        super.init()
        for col in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(col.id))
            column.title = col.title
            column.width = col.width
            column.minWidth = 40
            column.headerToolTip = col.tip
            outline.addTableColumn(column)
            if col.id == "name" { outline.outlineTableColumn = column }
        }
        outline.dataSource = self
        outline.delegate = self
        outline.allowsMultipleSelection = true
        outline.usesAlternatingRowBackgroundColors = true
        outline.rowHeight = 20
        outline.toolTip = "The changed paths as a tree. Delete hides the selected folder; Command-Delete brings the last one back."
        outline.onHide = { [weak self] in self?.hideSelected() }
        outline.onRestore = { [weak self] in self?.onRestoreHidden?() }
        let menu = NSMenu()
        menu.delegate = self
        outline.menu = menu
        scroll.documentView = outline
        scroll.hasVerticalScroller = true
        scroll.borderType = .noBorder

        let expand = NSButton(title: "Expand All", target: self, action: #selector(expandAll))
        expand.toolTip = "Open every folder"
        let collapse = NSButton(title: "Collapse All", target: self, action: #selector(collapseAll))
        collapse.toolTip = "Close every folder"
        sortPopup.addItems(withTitles: [TreeSort.name, .recent, .active].map { $0.title })
        sortPopup.target = self
        sortPopup.action = #selector(sortChanged)
        sortPopup.toolTip = "Order of the entries inside each folder"
        let bar = NSStackView(views: [expand, collapse, sortPopup])
        bar.orientation = .horizontal
        view.orientation = .vertical
        view.alignment = .leading
        view.spacing = 6
        view.addArrangedSubview(bar)
        view.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: view.widthAnchor).isActive = true
        scroll.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
    }

    //= ---- feeding -------------------------------------------------------------------------------------------
    func rebuild(_ rows: [FileRow]) {
        tree.rebuild(rows)
        reload()
    }

    //= the selection survives a reload because nodes keep their identity while the tree grows
    func reload() {
        let selected = outline.selectedRowIndexes.compactMap { outline.item(atRow: $0) as? PathNode }
        outline.reloadData()
        if firstFill, !tree.root.children.isEmpty {
            outline.expandItem(nil, expandChildren: false)
            for top in tree.children(of: tree.root) { outline.expandItem(top) }          //= the first two levels open by themselves
            firstFill = false
        }
        var indexes = IndexSet()
        for node in selected {
            let row = outline.row(forItem: node)
            if row >= 0 { indexes.insert(row) }
        }
        if !indexes.isEmpty { outline.selectRowIndexes(indexes, byExtendingSelection: false) }
    }

    func clear() {
        tree.reset()
        firstFill = true
        outline.reloadData()
    }

    //= ---- actions -------------------------------------------------------------------------------------------
    @objc private func expandAll() { outline.expandItem(nil, expandChildren: true) }
    @objc private func collapseAll() { outline.collapseItem(nil, collapseChildren: true) }

    @objc private func sortChanged() {
        tree.sort = TreeSort(rawValue: sortPopup.indexOfSelectedItem) ?? .name
        outline.reloadData()
    }

    private func selectedNodes() -> [PathNode] {
        outline.selectedRowIndexes.compactMap { outline.item(atRow: $0) as? PathNode }
    }

    private func folder(of node: PathNode) -> String {
        if node.isDirectory || !node.children.isEmpty { return node.path }
        return node.parent?.path ?? node.path
    }

    private func hideSelected() {
        for node in selectedNodes() {
            let dir = folder(of: node)
            if dir != "/" { onHideFolder?(dir) }
        }
    }

    //= ---- data source ---------------------------------------------------------------------------------------
    func outlineView(_: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        tree.children(of: (item as? PathNode) ?? tree.root).count
    }

    func outlineView(_: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        tree.children(of: (item as? PathNode) ?? tree.root)[index]
    }

    func outlineView(_: NSOutlineView, isItemExpandable item: Any) -> Bool {
        !((item as? PathNode)?.children.isEmpty ?? true)
    }

    func outlineView(_ outlineView: NSOutlineView, viewFor column: NSTableColumn?, item: Any) -> NSView? {
        guard let node = item as? PathNode, let column = column else { return nil }
        let id = column.identifier.rawValue
        let cell = (outlineView.makeView(withIdentifier: column.identifier, owner: self) as? NSTableCellView) ?? makeCell(column.identifier)
        switch id {
        case "name":
            cell.textField?.stringValue = node.name
            cell.textField?.textColor = node.lastCategory == "deleted" && node.children.isEmpty ? .systemRed : .labelColor
            cell.textField?.toolTip = node.path
            cell.imageView?.image = iconFor?(node)
        case "total": cell.textField?.stringValue = String(node.total)
        case "created": cell.textField?.stringValue = count(node, "created")
        case "deleted": cell.textField?.stringValue = count(node, "deleted")
        case "modified": cell.textField?.stringValue = count(node, "modified")
        case "attributes": cell.textField?.stringValue = count(node, "attributes")
        case "moved":
            let moved = (node.counts["moved_from"] ?? 0) + (node.counts["moved_to"] ?? 0)
            cell.textField?.stringValue = moved > 0 ? String(moved) : ""
        case "last": cell.textField?.stringValue = FileFormat.time(node.lastTs)
        default: break
        }
        return cell
    }

    private func count(_ node: PathNode, _ category: String) -> String {
        let n = node.counts[category] ?? 0
        return n > 0 ? String(n) : ""
    }

    private func makeCell(_ identifier: NSUserInterfaceItemIdentifier) -> NSTableCellView {
        let cell = NSTableCellView()
        cell.identifier = identifier
        let label = NSTextField(labelWithString: "")
        label.translatesAutoresizingMaskIntoConstraints = false
        label.lineBreakMode = .byTruncatingMiddle
        cell.addSubview(label)
        cell.textField = label
        if identifier.rawValue == "name" {
            let image = NSImageView()
            image.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(image)
            cell.imageView = image
            NSLayoutConstraint.activate([
                image.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                image.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
                image.widthAnchor.constraint(equalToConstant: 16), image.heightAnchor.constraint(equalToConstant: 16),
                label.leadingAnchor.constraint(equalTo: image.trailingAnchor, constant: 5),
            ])
            label.font = NSFont.systemFont(ofSize: 12)
        } else {
            label.alignment = identifier.rawValue == "last" ? .left : .right
            label.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .regular)
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2).isActive = true
        }
        NSLayoutConstraint.activate([
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
        return cell
    }

    func outlineViewSelectionDidChange(_: Notification) {
        onSelect?(selectedNodes().first)
    }

    //= ---- right-click menu ----------------------------------------------------------------------------------
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let row = outline.clickedRow
        guard row >= 0, let node = outline.item(atRow: row) as? PathNode else { return }
        func add(_ title: String, _ action: Selector) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.target = self
            item.representedObject = node.path
            menu.addItem(item)
        }
        add("Reveal in Finder", #selector(menuReveal(_:)))
        add("Copy Path", #selector(menuCopy(_:)))
        menu.addItem(NSMenuItem.separator())
        add("Show Only This Folder", #selector(menuOnly(_:)))
        add("Hide This Folder", #selector(menuHide(_:)))
    }

    @objc private func menuReveal(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String, FileManager.default.fileExists(atPath: path) else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    @objc private func menuCopy(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(path, forType: .string)
    }

    private func menuFolder(_ sender: NSMenuItem) -> String? {
        guard let path = sender.representedObject as? String else { return nil }
        var node = tree.root
        for part in path.split(separator: "/") {
            guard let next = node.children[String(part)] else { return path }
            node = next
        }
        return folder(of: node)
    }

    @objc private func menuOnly(_ sender: NSMenuItem) {
        if let dir = menuFolder(sender) { onOnlyFolder?(dir) }
    }

    @objc private func menuHide(_ sender: NSMenuItem) {
        if let dir = menuFolder(sender), dir != "/" { onHideFolder?(dir) }
    }
}
