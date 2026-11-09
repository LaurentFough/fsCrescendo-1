import Cocoa
import UniformTypeIdentifiers

//= FilesViewController.swift  version 0.2.0 (2026-11-09)
//= File activity in the style of a file-system monitor, shown inside the main window when the "File" segment is selected.
//= Source: the cresc engine (`watch.start` with view "files"), fed by the event daemon (eslogger). Rows are
//= cresc.filechange/1: created, deleted, modified, attributes, moved from / moved to, meta.
//= List view (kind icon, PID, process, path, inode, date) or text view, a legend bar, a read-only inspector, a cleanup
//= popup (none / coalesce / prune) and pause/resume. Space toggles pause while the list has focus.
//= This is a live monitor: a rolling buffer of the newest rows. Saving recordings comes in a later phase.

//= one displayed change
struct FileRow {
    var id = 0 //= ascending; lets the selection survive refreshes
    var category = "", eventType = "", ts = "", path = "", source = ""
    var pid = -1, ppid = -1, actorUid = -1, actorGid = -1, count = 1
    var process = "", processPath = "", signingId = ""
    var inode: Int64?, device: Int64?, mode: Int?, uid: Int?, gid: Int?, size: Int64?
    var created = "", modified = ""
    var raw = [String: Any]()

    init(_ change: [String: Any]) {
        raw = change
        category = change["category"] as? String ?? ""
        eventType = change["event_type"] as? String ?? ""
        ts = change["ts"] as? String ?? ""
        path = change["path"] as? String ?? ""
        source = change["source_path"] as? String ?? ""
        count = change["count"] as? Int ?? 1
        let file = change["file"] as? [String: Any] ?? [:]
        inode = (file["inode"] as? NSNumber)?.int64Value
        device = (file["device"] as? NSNumber)?.int64Value
        size = (file["size"] as? NSNumber)?.int64Value
        mode = file["mode"] as? Int
        uid = file["uid"] as? Int
        gid = file["gid"] as? Int
        created = file["created"] as? String ?? ""
        modified = file["modified"] as? String ?? ""
        let proc = change["process"] as? [String: Any] ?? [:]
        pid = proc["pid"] as? Int ?? -1
        ppid = proc["ppid"] as? Int ?? -1
        process = proc["name"] as? String ?? ""
        processPath = proc["path"] as? String ?? ""
        signingId = proc["signing_id"] as? String ?? ""
        actorUid = proc["uid"] as? Int ?? -1
        actorGid = proc["gid"] as? Int ?? -1
    }
}

//= helpers for dates and permission strings
enum FileFormat {
    private static let utc: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return f
    }()
    private static let local: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
    private static let localDate: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    //= "2026-11-09T02:42:37.168394523Z" -> "21:42:37.168" in local time (falls back to the raw text)
    static func time(_ ts: String, withDate: Bool = false) -> String {
        guard ts.count >= 19, let date = utc.date(from: String(ts.prefix(19))) else { return ts }
        var millis = "000"
        if ts.count >= 23, ts[ts.index(ts.startIndex, offsetBy: 19)] == "." {
            let start = ts.index(ts.startIndex, offsetBy: 20)
            millis = String(ts[start...].prefix(3))
            while millis.count < 3 { millis += "0" }
        }
        return (withDate ? localDate : local).string(from: date) + "." + millis
    }

    //= 33152 -> "-rw-------"
    static func mode(_ mode: Int) -> String {
        let kinds: [Int: Character] = [0o040000: "d", 0o120000: "l", 0o010000: "p", 0o020000: "c", 0o060000: "b", 0o140000: "s"]
        var text = String(kinds[mode & 0o170000] ?? "-")
        for shift in [6, 3, 0] {
            let bits = (mode >> shift) & 7
            text += (bits & 4 != 0 ? "r" : "-") + (bits & 2 != 0 ? "w" : "-") + (bits & 1 != 0 ? "x" : "-")
        }
        return text
    }
}

//= the list needs to react to the space bar (pause / resume)
final class FilesTable: NSTableView {
    var onSpace: (() -> Void)?

    override func keyDown(with event: NSEvent) {
        if event.charactersIgnoringModifiers == " " { onSpace?() } else { super.keyDown(with: event) }
    }
}

final class FilesViewController: NSViewController, NSTableViewDataSource, NSTableViewDelegate {
    //= called when capturing starts or stops, so the window's own Start/Stop buttons can follow
    var onCapturingChanged: ((Bool) -> Void)?
    //= asked to open the setup help (event daemon installation, Full Disk Access)
    var onNeedSetup: (() -> Void)?

    private let engine = EngineClient.shared
    private static let daemonSocket = "/var/run/com.loff.crescendo.esd.sock"
    private static let maxRows = 20000

    private var watchId: String?
    private var capturing = false
    private var restartAfterStop = false
    private var rows = [FileRow]()
    private var visible = [FileRow]()
    private var search = ""
    private var reloadPending = false
    private var nextRowId = 0
    //= asked before scrolling to the newest row; the main window answers with its Auto-scroll checkbox
    var autoscroll: () -> Bool = { true }
    private static var iconCache = [String: NSImage]()

    //= widgets
    private let bannerLabel = NSTextField(wrappingLabelWithString: "")
    private let bannerButton = NSButton(title: "Open setup", target: nil, action: nil)
    private let bannerBox = NSStackView()
    private let modeControl = NSSegmentedControl(labels: ["List", "Text"], trackingMode: .selectOne, target: nil, action: nil)
    private let cleanupPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let pauseButton = NSButton(title: "Pause", target: nil, action: nil)
    private let inspectorButton = NSButton(checkboxWithTitle: "Inspector", target: nil, action: nil)
    private let statusLabel = NSTextField(labelWithString: "stopped")
    private let table = FilesTable()
    private let listScroll = NSScrollView()
    private let textView = NSTextView()
    private let textScroll = NSScrollView()
    private let inspectorView = NSTextView()
    private let inspectorScroll = NSScrollView()
    private let split = NSSplitView()

    private let columns: [(id: String, title: String, width: CGFloat, tip: String)] = [
        ("kind", "Kind", 44, "What happened to the file: created, deleted, content modified, attributes modified, moved from, moved to"),
        ("pid", "PID", 64, "Process id of the process that did it"),
        ("process", "Process", 150, "Name of that process (the full path is in the inspector)"),
        ("path", "Path", 560, "The file or folder"),
        ("inode", "Inode", 120, "Inode number of the file"),
        ("date", "Date", 110, "Local time of the change"),
    ]

    //= category -> (SF Symbol, colour, label)
    private static let kinds: [(category: String, symbol: String, color: NSColor, label: String)] = [
        ("created", "plus.circle.fill", .systemGreen, "Created"),
        ("deleted", "xmark.circle.fill", .systemRed, "Deleted"),
        ("modified", "pencil.circle.fill", .systemOrange, "Content Modified"),
        ("attributes", "wrench.and.screwdriver.fill", .systemGray, "Attributes Modified"),
        ("moved_from", "arrow.up.right.circle.fill", .systemBlue, "Moved From"),
        ("moved_to", "arrow.down.right.circle.fill", .systemBlue, "Moved To"),
        ("meta", "text.bubble.fill", .systemGray, "Meta Event"),
    ]

    private static func kind(_ category: String) -> (category: String, symbol: String, color: NSColor, label: String)? {
        kinds.first { $0.category == category }
    }

    //= ---- view ----------------------------------------------------------------------------------------------
    override func loadView() {
        view = NSView()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        buildUI()
        engine.addEventHandler { [weak self] name, data in self?.handle(name, data) }
    }

    private func buildUI() {
        bannerLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        bannerButton.target = self
        bannerButton.action = #selector(setupClicked)
        bannerBox.orientation = .horizontal
        bannerBox.addArrangedSubview(bannerLabel)
        bannerBox.addArrangedSubview(bannerButton)
        bannerBox.isHidden = true

        modeControl.selectedSegment = 0
        modeControl.target = self
        modeControl.action = #selector(modeChanged)
        modeControl.toolTip = "List: one row per change. Text: the same rows as plain text you can select and copy."
        cleanupPopup.addItems(withTitles: ["No Cleanup", "Coalesce Repeats", "Prune Redundant Events"])
        cleanupPopup.target = self
        cleanupPopup.action = #selector(cleanupChanged)
        cleanupPopup.toolTip = "No Cleanup: every change. Coalesce: repeated modifications of a file become one row. "
            + "Prune: also hides temporary files and turns write-temp-then-rename saves into one row. Cleaned rows appear about 2 seconds late."
        pauseButton.target = self
        pauseButton.action = #selector(togglePause)
        pauseButton.toolTip = "Stop capturing now and resume later (Space does the same while the list has focus)"
        inspectorButton.state = .on
        inspectorButton.target = self
        inspectorButton.action = #selector(toggleInspector)
        inspectorButton.toolTip = "Show or hide the details of the selected change"
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.setContentCompressionResistancePriority(NSLayoutConstraint.Priority(1), for: .horizontal)
        //= the status text changes width on every refresh, so it goes LAST: nothing to its left can move under the pointer
        let bar = NSStackView(views: [modeControl, cleanupPopup, pauseButton, inspectorButton, statusLabel])
        bar.orientation = .horizontal

        //= list
        for col in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(col.id))
            column.title = col.title
            column.width = col.width
            column.minWidth = 30
            column.headerToolTip = col.tip
            table.addTableColumn(column)
        }
        table.dataSource = self
        table.delegate = self
        table.allowsMultipleSelection = true
        table.usesAlternatingRowBackgroundColors = true
        table.rowHeight = 20
        table.onSpace = { [weak self] in self?.togglePause() }
        listScroll.documentView = table
        listScroll.hasVerticalScroller = true
        listScroll.borderType = .noBorder

        //= text
        textView.isEditable = false
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = true
        textView.font = NSFont.userFixedPitchFont(ofSize: 11)
        textView.textContainer?.widthTracksTextView = false
        textView.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.toolTip = "The visible rows as text: date, kind, pid, process, inode, path"
        textScroll.documentView = textView
        textScroll.hasVerticalScroller = true
        textScroll.hasHorizontalScroller = true
        textScroll.isHidden = true

        let left = NSView()
        for scroll in [listScroll, textScroll] {
            scroll.translatesAutoresizingMaskIntoConstraints = false
            left.addSubview(scroll)
            NSLayoutConstraint.activate([
                scroll.leadingAnchor.constraint(equalTo: left.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: left.trailingAnchor),
                scroll.topAnchor.constraint(equalTo: left.topAnchor), scroll.bottomAnchor.constraint(equalTo: left.bottomAnchor),
            ])
        }

        //= inspector
        inspectorView.isEditable = false
        inspectorView.isVerticallyResizable = true
        inspectorView.autoresizingMask = [.width]
        inspectorView.textContainer?.widthTracksTextView = true
        inspectorView.textContainerInset = NSSize(width: 8, height: 8)
        inspectorView.toolTip = "Details of the selected change: file, event and process information"
        inspectorScroll.documentView = inspectorView
        inspectorScroll.hasVerticalScroller = true
        inspectorScroll.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true

        split.isVertical = true
        split.dividerStyle = .thin
        split.arrangesAllSubviews = true
        split.addArrangedSubview(left)
        split.addArrangedSubview(inspectorScroll)
        split.setHoldingPriority(NSLayoutConstraint.Priority(250), forSubviewAt: 0)
        split.setHoldingPriority(NSLayoutConstraint.Priority(260), forSubviewAt: 1)

        let root = NSStackView(views: [bannerBox, bar, split, legend()])
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 8
        root.edgeInsets = NSEdgeInsets(top: 4, left: 20, bottom: 10, right: 20)
        root.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: view.leadingAnchor), root.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            root.topAnchor.constraint(equalTo: view.topAnchor), root.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        for sub in [bannerBox, bar, split] {
            sub.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -40).isActive = true
        }
        split.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
        showInspectorText(nil)
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.split.setPosition(max(300, self.split.bounds.width - 320), ofDividerAt: 0)
        }
    }

    //= the colour/label key under the list, like a monitor's legend
    private func legend() -> NSView {
        var items = [NSView]()
        for kind in FilesViewController.kinds {
            let image = NSImageView(image: symbol(kind.symbol, kind.color, kind.label))
            image.setContentHuggingPriority(.required, for: .horizontal)
            let label = NSTextField(labelWithString: kind.label)
            label.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
            let pair = NSStackView(views: [image, label])
            pair.spacing = 3
            items.append(pair)
        }
        let row = NSStackView(views: items)
        row.orientation = .horizontal
        row.spacing = 14
        row.toolTip = "Legend of the Kind column"
        return row
    }

    private func symbol(_ name: String, _ color: NSColor, _ description: String) -> NSImage {
        let base = NSImage(systemSymbolName: name, accessibilityDescription: description) ?? NSImage()
        let configuration = NSImage.SymbolConfiguration(paletteColors: [.white, color])
        return base.withSymbolConfiguration(configuration) ?? base
    }

    //= ---- file type icons -----------------------------------------------------------------------------------
    private func fileType(_ r: FileRow) -> UTType {
        if ((r.mode ?? 0) & 0o170000) == 0o040000 { return .folder }
        let ext = URL(fileURLWithPath: r.path).pathExtension.lowercased()
        return ext.isEmpty ? .data : (UTType(filenameExtension: ext) ?? .data)
    }

    //= the Finder icon for the file's type (cached per type), a red cross for a deleted file, a bubble for markers
    private func fileIcon(_ r: FileRow) -> NSImage {
        if r.category == "meta" { return symbol("text.bubble.fill", .systemGray, "Meta Event") }
        if r.category == "deleted" { return symbol("xmark.circle.fill", .systemRed, "Deleted") }
        let type = fileType(r)
        if let hit = FilesViewController.iconCache[type.identifier] { return hit }
        let icon = (NSWorkspace.shared.icon(for: type).copy() as? NSImage) ?? NSWorkspace.shared.icon(for: type)
        icon.size = NSSize(width: 16, height: 16)
        FilesViewController.iconCache[type.identifier] = icon
        return icon
    }

    //= ---- capturing -----------------------------------------------------------------------------------------
    var isCapturing: Bool { capturing }

    func startCapture() {
        guard !capturing, watchId == nil else { return }
        if let problem = engine.ensureStarted() {
            setStatus("engine: \(problem)")
            return
        }
        setStatus("checking the event daemon...")
        engine.call("esd.status", ["socket": FilesViewController.daemonSocket]) { [weak self] result in
            guard let self = self else { return }
            guard case let .success(info) = result, info["available"] as? Bool == true else {
                self.showBanner("The event daemon is not installed, so there is no source of file events yet. "
                    + "Open the setup in the Cresc Console (Events tab) to install it.")
                self.setStatus("no event source")
                return
            }
            if info["fda"] as? Bool == false {
                self.showBanner("The event daemon has no Full Disk Access yet. Open the setup in the Cresc Console (Events tab).")
                self.setStatus("needs Full Disk Access")
                return
            }
            self.bannerBox.isHidden = true
            self.sendWatchStart()
        }
    }

    private func sendWatchStart() {
        let cleanup = ["none", "coalesce", "prune"][max(0, cleanupPopup.indexOfSelectedItem)]
        let params: [String: Any] = ["source": ["socket": FilesViewController.daemonSocket], "view": "files",
                                     "cleanup": cleanup, "cleanup_window": 2.0]
        engine.call("watch.start", params) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case let .success(info):
                self.watchId = info["watch_id"] as? String
                self.setCapturing(true)
                self.setStatus("capturing")
            case let .failure(err):
                self.setStatus("cannot start: \(err.message)")
            }
        }
    }

    func stopCapture() {
        guard let id = watchId else { return }
        engine.call("watch.stop", ["watch_id": id])
    }

    private func setCapturing(_ on: Bool) {
        capturing = on
        pauseButton.title = on ? "Pause" : "Resume"
        onCapturingChanged?(on)
    }

    @objc private func togglePause() {
        if capturing { stopCapture() } else { startCapture() }
    }

    @objc private func cleanupChanged() {
        if capturing {
            restartAfterStop = true          //= the cleanup mode is a property of the running watch: restart it
            stopCapture()
        }
    }

    @objc private func setupClicked() { onNeedSetup?() }

    private func showBanner(_ text: String) {
        bannerLabel.stringValue = text
        bannerBox.isHidden = false
    }

    private func setStatus(_ text: String) {
        statusLabel.stringValue = text
    }

    //= ---- events from the engine ----------------------------------------------------------------------------
    private func handle(_ name: String, _ data: [String: Any]) {
        switch name {
        case "watch.change":
            guard data["watch_id"] as? String == watchId, let change = data["change"] as? [String: Any] else { return }
            append(FileRow(change))
        case "watch.ended":
            guard data["watch_id"] as? String == watchId else { return }
            watchId = nil
            setCapturing(false)
            setStatus("stopped - \(rows.count) rows")
            if restartAfterStop { restartAfterStop = false; startCapture() }
        case "watch.error":
            if data["watch_id"] as? String == watchId { setStatus("error: \(data["message"] ?? "")") }
        default:
            break
        }
    }

    private func append(_ newRow: FileRow) {
        var row = newRow
        nextRowId += 1
        row.id = nextRowId
        rows.append(row)
        if rows.count > FilesViewController.maxRows { rows.removeFirst(rows.count - FilesViewController.maxRows); rebuildVisible() }
        else if matches(row) { visible.append(row) }
        scheduleReload()
    }

    //= bursts are coalesced: at most about four table updates per second
    private func scheduleReload() {
        guard !reloadPending else { return }
        reloadPending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
            guard let self = self else { return }
            self.reloadPending = false
            self.reloadViews(scrollToEnd: true)
        }
    }

    private func reloadViews(scrollToEnd: Bool) {
        let follow = scrollToEnd && autoscroll()
        if textScroll.isHidden {
            //= reloadData() drops the selection; remember the selected rows by id and select them again
            let selectedIds = Set(table.selectedRowIndexes.compactMap { $0 < visible.count ? visible[$0].id : nil })
            table.reloadData()
            if !selectedIds.isEmpty {
                var indexes = IndexSet()
                for (index, row) in visible.enumerated() where selectedIds.contains(row.id) { indexes.insert(index) }
                if !indexes.isEmpty { table.selectRowIndexes(indexes, byExtendingSelection: false) }
            }
            if follow, !visible.isEmpty { table.scrollRowToVisible(visible.count - 1) }
        } else {
            rebuildText(scrollToEnd: follow)
        }
        if capturing { setStatus("capturing - \(visible.count) of \(rows.count) rows") }
    }

    //= ---- filtering and actions of the window's toolbar -----------------------------------------------------
    func setSearch(_ text: String) {
        search = text.lowercased()
        rebuildVisible()
        reloadViews(scrollToEnd: false)
    }

    func clear() {
        rows.removeAll()
        visible.removeAll()
        showInspectorText(nil)
        reloadViews(scrollToEnd: false)
        setStatus(capturing ? "capturing" : "stopped")
    }

    //= writes the visible rows as cresc.filechange/1 JSON lines
    func exportVisible() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "file-activity.jsonl"
        panel.message = "Save the \(visible.count) visible rows as JSON lines (cresc.filechange/1)."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var text = ""
        for row in visible {
            if let data = try? JSONSerialization.data(withJSONObject: row.raw, options: [.sortedKeys]),
                let line = String(data: data, encoding: .utf8) { text += line + "\n" }
        }
        do { try text.write(to: url, atomically: true, encoding: .utf8) } catch { NSLog("export failed: %@", error.localizedDescription) }
    }

    private func matches(_ row: FileRow) -> Bool {
        if search.isEmpty { return true }
        return [row.path, row.process, row.eventType, row.source, String(row.pid)].contains { $0.lowercased().contains(search) }
    }

    private func rebuildVisible() { visible = rows.filter { matches($0) } }

    @objc private func modeChanged() {
        let showText = modeControl.selectedSegment == 1
        listScroll.isHidden = showText
        textScroll.isHidden = !showText
        reloadViews(scrollToEnd: false)
    }

    @objc private func toggleInspector() {
        inspectorScroll.isHidden = inspectorButton.state != .on
        split.adjustSubviews()
    }

    //= ---- text view -----------------------------------------------------------------------------------------
    private func rebuildText(scrollToEnd: Bool) {
        let font = NSFont.userFixedPitchFont(ofSize: 11) ?? NSFont.systemFont(ofSize: 11)
        let out = NSMutableAttributedString()
        for row in visible.suffix(5000) {
            let tag = FilesViewController.tag(row.category)
            let inode = row.inode.map { String($0) } ?? "-"
            let pid = row.pid >= 0 ? String(row.pid) : "-"
            var path = row.path
            if row.category == "moved_to", !row.source.isEmpty { path += "  <-  " + row.source }
            let line = "\(FileFormat.time(row.ts, withDate: true))  \(tag)  \(pid.padding(toLength: 7, withPad: " ", startingAt: 0)) "
                + "\(String(row.process.prefix(18)).padding(toLength: 18, withPad: " ", startingAt: 0)) "
                + "\(inode.padding(toLength: 20, withPad: " ", startingAt: 0)) \(path)\n"
            let color: NSColor = row.category == "deleted" ? .systemRed : (row.category == "moved_to" || row.category == "moved_from" ? .systemBlue : .labelColor)
            out.append(NSAttributedString(string: line, attributes: [.font: font, .foregroundColor: color]))
        }
        textView.textStorage?.setAttributedString(out)
        if scrollToEnd { textView.scrollToEndOfDocument(nil) }
    }

    private static func tag(_ category: String) -> String {
        ["created": "CRE ", "deleted": "DEL ", "modified": "MOD ", "attributes": "ATR ", "moved_from": "MVF ", "moved_to": "MVT ",
         "meta": "META"][category] ?? "?   "
    }

    //= ---- inspector -----------------------------------------------------------------------------------------
    private func showInspectorText(_ row: FileRow?) {
        let bold = NSFont.boldSystemFont(ofSize: 12), normal = NSFont.systemFont(ofSize: 12)
        let out = NSMutableAttributedString()
        func heading(_ text: String) {
            out.append(NSAttributedString(string: (out.length == 0 ? "" : "\n") + text + "\n", attributes: [.font: bold]))
        }
        func line(_ key: String, _ value: String) {
            guard !value.isEmpty else { return }
            out.append(NSAttributedString(string: key + ": ", attributes: [.font: bold, .foregroundColor: NSColor.secondaryLabelColor]))
            out.append(NSAttributedString(string: value + "\n", attributes: [.font: normal]))
        }
        guard let r = row else {
            out.append(NSAttributedString(string: "Select a change to see its details.", attributes: [.font: normal, .foregroundColor: NSColor.secondaryLabelColor]))
            inspectorView.textStorage?.setAttributedString(out)
            return
        }
        if r.category != "meta" {
            //= large file icon with the type name, centred, like a monitor's inspector
            let type = fileType(r)
            let big = (NSWorkspace.shared.icon(for: type).copy() as? NSImage) ?? NSWorkspace.shared.icon(for: type)
            big.size = NSSize(width: 64, height: 64)
            let attachment = NSTextAttachment()
            attachment.image = big
            attachment.bounds = NSRect(x: 0, y: 0, width: 64, height: 64)
            let center = NSMutableParagraphStyle()
            center.alignment = .center
            let picture = NSMutableAttributedString(attachment: attachment)
            picture.append(NSAttributedString(string: "\n" + (type.localizedDescription ?? type.preferredFilenameExtension ?? "File") + "\n"))
            picture.addAttributes([.paragraphStyle: center, .font: normal, .foregroundColor: NSColor.secondaryLabelColor],
                                  range: NSRange(location: 0, length: picture.length))
            out.append(picture)
        }
        heading("Current Status")
        line("Path", r.path)
        line("Created", FileFormat.time(r.created, withDate: true))
        line("Modified", FileFormat.time(r.modified, withDate: true))
        heading("Event Information")
        line("Category", FilesViewController.kind(r.category)?.label ?? r.category)
        line("Event Type", r.eventType)
        line("Time", FileFormat.time(r.ts, withDate: true))
        if r.count > 1 { line("Events merged", String(r.count)) }
        line("Owner uid", r.uid.map { String($0) } ?? "")
        line("Owner gid", r.gid.map { String($0) } ?? "")
        line("Mode", r.mode.map { FileFormat.mode($0) } ?? "")
        line("Size", r.size.map { "\($0) bytes" } ?? "")
        line("Inode", r.inode.map { String($0) } ?? "")
        line("Device", r.device.map { String($0) } ?? "")
        line("Source", r.source)
        let details = r.raw["details"] as? [String: Any] ?? [:]
        for key in ["destination", "extattr", "flags", "mode_set", "atime", "mtime", "first_ts", "other"] {
            if let value = details[key] { line(key.capitalized, "\(value)") }
        }
        heading("Process Information")
        line("PID", r.pid >= 0 ? String(r.pid) : "")
        line("PPID", r.ppid >= 0 ? String(r.ppid) : "")
        line("Name", r.process)
        line("Path", r.processPath)
        line("Signing id", r.signingId)
        line("UID", r.actorUid >= 0 ? String(r.actorUid) : "")
        line("GID", r.actorGid >= 0 ? String(r.actorGid) : "")
        inspectorView.textStorage?.setAttributedString(out)
    }

    //= ---- table ---------------------------------------------------------------------------------------------
    func numberOfRows(in _: NSTableView) -> Int { visible.count }

    func tableViewSelectionDidChange(_: Notification) {
        let index = table.selectedRow
        showInspectorText(index >= 0 && index < visible.count ? visible[index] : nil)
    }

    func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
        guard let column = column, row < visible.count else { return nil }
        let r = visible[row]
        let id = column.identifier.rawValue
        let cell = (tableView.makeView(withIdentifier: column.identifier, owner: self) as? NSTableCellView) ?? makeCell(column.identifier)
        if id == "kind" {
            if let kind = FilesViewController.kind(r.category) {
                cell.imageView?.image = symbol(kind.symbol, kind.color, kind.label)
                cell.imageView?.toolTip = kind.label
            }
            return cell
        }
        var text = ""
        switch id {
        case "pid": text = r.pid >= 0 ? String(r.pid) : "-"
        case "process": text = r.process
        case "path":
            text = r.category == "moved_to" && !r.source.isEmpty ? r.path + "   <-  " + r.source : r.path
            cell.imageView?.image = fileIcon(r)
        case "inode": text = r.inode.map { String($0) } ?? "-"
        case "date": text = FileFormat.time(r.ts)
        default: break
        }
        cell.textField?.stringValue = text
        cell.textField?.textColor = r.category == "deleted" ? .systemRed : .labelColor
        cell.textField?.toolTip = id == "path" ? text : nil
        return cell
    }

    private func makeCell(_ identifier: NSUserInterfaceItemIdentifier) -> NSTableCellView {
        let cell = NSTableCellView()
        cell.identifier = identifier
        if identifier.rawValue == "kind" {
            let image = NSImageView()
            image.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(image)
            cell.imageView = image
            NSLayoutConstraint.activate([image.centerXAnchor.constraint(equalTo: cell.centerXAnchor), image.centerYAnchor.constraint(equalTo: cell.centerYAnchor)])
        } else if identifier.rawValue == "path" {
            let image = NSImageView()
            image.translatesAutoresizingMaskIntoConstraints = false
            let label = NSTextField(labelWithString: "")
            label.translatesAutoresizingMaskIntoConstraints = false
            label.lineBreakMode = .byTruncatingMiddle
            label.font = NSFont.systemFont(ofSize: 12)
            cell.addSubview(image)
            cell.addSubview(label)
            cell.imageView = image
            cell.textField = label
            NSLayoutConstraint.activate([
                image.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                image.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
                image.widthAnchor.constraint(equalToConstant: 16), image.heightAnchor.constraint(equalToConstant: 16),
                label.leadingAnchor.constraint(equalTo: image.trailingAnchor, constant: 5),
                label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -2),
                label.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            ])
        } else {
            let label = NSTextField(labelWithString: "")
            label.translatesAutoresizingMaskIntoConstraints = false
            label.lineBreakMode = .byTruncatingMiddle
            label.font = identifier.rawValue == "path" ? NSFont.systemFont(ofSize: 12) : NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .regular)
            cell.addSubview(label)
            cell.textField = label
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -2),
                label.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            ])
        }
        return cell
    }
}
