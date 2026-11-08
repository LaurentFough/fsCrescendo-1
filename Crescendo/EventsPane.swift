import Cocoa

//= EventsPane.swift  version 0.1.0 (2026-11-08)
//= The Events tab. The app never runs privileged: it creates a private FIFO, tells the engine to read it
//= (`watch.start`), and shows the one-line command that YOU run in a terminal to feed it:
//=     sudo eslogger <events> > <fifo>
//= (eslogger needs root, plus Full Disk Access for the terminal app). No Endpoint Security entitlement is used.
//= One button does it all: Start asks the engine to read the FIFO and opens a Terminal window that runs the command
//= (a generated 0700 .command file; you type your sudo password there). Stop closes the FIFO, and eslogger
//= exits by itself on its next write (SIGPIPE).
//= Scope = all / app / dir / file / pid; the engine filters (following child processes) and pushes `watch.event`.

final class EventsPane: NSObject, NSTableViewDataSource {
    let view = NSStackView()
    var call: ((String, [String: Any], EngineClient.Reply?) -> Void)?
    var log: ((String) -> Void)?

    private static let eventNames = "exec fork exit open close write create rename unlink truncate link"
    private static let maxRows = 5000

    private var watchId: String?
    private var all = [[String: String]]()
    private var visible = [[String: String]]()
    private var reloadPending = false

    private let scopePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let scopeValue = NSTextField(string: "")
    private let kindsField = NSTextField(string: "")
    private let searchField = NSSearchField()
    private let pauseCheck = NSButton(checkboxWithTitle: "Pause", target: nil, action: nil)
    private let scrollCheck = NSButton(checkboxWithTitle: "Autoscroll", target: nil, action: nil)
    private let statsLabel = NSTextField(labelWithString: "not watching")
    private let table = NSTableView()
    private let scroll = NSScrollView()
    private let columns: [(id: String, title: String, width: CGFloat)] = [
        ("time", "Time", 110), ("kind", "Kind", 100), ("process", "Process", 170), ("pid", "PID", 60), ("target", "Target", 520),
    ]

    override init() {
        super.init()
        build()
    }

    //= ---- FIFO ----------------------------------------------------------------------------------------------
    static func fifoPath() -> String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support")
        return base.appendingPathComponent("Crescendo/es/events.fifo").path
    }

    //= creates the private directory (0700) and the FIFO (0600); returns an error text or nil
    private func prepareFifo() -> String? {
        let path = EventsPane.fifoPath()
        let dir = (path as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { return "cannot create \(dir): \(error.localizedDescription)" }
        var st = stat()
        if lstat(path, &st) == 0 {
            //= 0o170000 = S_IFMT and 0o010000 = S_IFIFO, as literals (the macro types differ between SDKs)
            let isFifo = (st.st_mode & 0o170000) == 0o010000
            return isFifo ? nil : "\(path) exists and is not a FIFO"
        }
        return mkfifo(path, 0o600) == 0 ? nil : "mkfifo failed: \(String(cString: strerror(errno)))"
    }

    private func shellQuote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    private func esCommand() -> String {
        "sudo eslogger \(EventsPane.eventNames) > \(shellQuote(EventsPane.fifoPath()))"
    }

    //= writes the launcher next to the FIFO and opens it (Terminal handles .command files)
    private func launchTerminal() {
        let path = (EventsPane.fifoPath() as NSString).deletingLastPathComponent + "/run-eslogger.command"
        let script = "#!/bin/sh\n"
            + "echo 'Crescendo event source: eslogger (needs your sudo password). Close this window or press Ctrl-C to stop.'\n"
            + "exec \(esCommand())\n"
        do {
            try script.write(toFile: path, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path)
        } catch {
            log?("ERROR: cannot write \(path): \(error.localizedDescription)")
            return
        }
        if !NSWorkspace.shared.open(URL(fileURLWithPath: path)) {
            log?("could not open Terminal; run this yourself: \(esCommand())")
        }
    }

    //= ---- UI ------------------------------------------------------------------------------------------------
    private func build() {
        scopePopup.addItems(withTitles: ["all events", "app", "dir", "file", "pid"])
        scopeValue.placeholderString = "app name or path / absolute path / pid"
        kindsField.placeholderString = "kinds, e.g. file.* proc.exec (empty = all)"
        let start = NSButton(title: "Start", target: self, action: #selector(startWatch))
        let stop = NSButton(title: "Stop", target: self, action: #selector(stopWatch))
        let clear = NSButton(title: "Clear", target: self, action: #selector(clearRows))
        let controlRow = NSStackView(views: [NSTextField(labelWithString: "Scope:"), scopePopup, scopeValue, kindsField, start, stop, clear])
        scopeValue.setContentHuggingPriority(.defaultLow, for: .horizontal)
        kindsField.setContentHuggingPriority(.defaultLow, for: .horizontal)

        searchField.placeholderString = "filter shown rows"
        searchField.target = self
        searchField.action = #selector(filterChanged)
        scrollCheck.state = .on
        let filterRow = NSStackView(views: [searchField, pauseCheck, scrollCheck, statsLabel])
        searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 240).isActive = true

        for col in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(col.id))
            column.title = col.title
            column.width = col.width
            table.addTableColumn(column)
        }
        table.dataSource = self
        scroll.documentView = table
        scroll.hasVerticalScroller = true

        view.orientation = .vertical
        view.alignment = .leading
        view.spacing = 8
        view.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        for row in [controlRow, filterRow, scroll] {
            view.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: view.widthAnchor, constant: -24).isActive = true
        }
    }

    //= ---- watch control -------------------------------------------------------------------------------------
    @objc private func startWatch() {
        guard watchId == nil else { log?("already watching"); return }
        if let problem = prepareFifo() { log?("ERROR: \(problem)"); return }
        var params: [String: Any] = ["source": ["file": EventsPane.fifoPath(), "follow": false]]
        let kinds = kindsField.stringValue.split(separator: " ").map { String($0) }
        if !kinds.isEmpty { params["kinds"] = kinds }
        let title = scopePopup.titleOfSelectedItem ?? ""
        if ["app", "dir", "file", "pid"].contains(title) {
            let kind = title
            let value = scopeValue.stringValue.trimmingCharacters(in: .whitespaces)
            if value.isEmpty { log?("ERROR: the \(kind) scope needs a value"); return }
            params["scopes"] = [["kind": kind, "value": value]]
        }
        call?("watch.start", params) { [weak self] result in
            switch result {
            case let .success(info):
                self?.watchId = info["watch_id"] as? String
                self?.statsLabel.stringValue = "watching - enter your password in the Terminal window"
                self?.launchTerminal()
            case let .failure(err):
                self?.log?("watch.start failed: \(err.code): \(err.message)")
            }
        }
    }

    @objc private func stopWatch() {
        guard let id = watchId else { return }
        call?("watch.stop", ["watch_id": id], nil)
    }

    @objc private func clearRows() {
        all.removeAll(); visible.removeAll(); table.reloadData()
    }

    @objc private func filterChanged() {
        rebuildVisible(); table.reloadData()
    }

    //= ---- events from the engine ----------------------------------------------------------------------------
    func handle(_ name: String, _ data: [String: Any]) {
        switch name {
        case "watch.event":
            guard data["watch_id"] as? String == watchId, let ev = data["event"] as? [String: Any] else { return }
            add(ev)
        case "watch.ended":
            guard data["watch_id"] as? String == watchId else { return }
            watchId = nil
            let stats = data["stats"] as? [String: Any] ?? [:]
            statsLabel.stringValue = "ended: read \(stats["read"] ?? 0), shown \(stats["shown"] ?? 0), dropped \(stats["dropped"] ?? 0)"
        case "watch.error":
            log?("watch error: \(data["message"] ?? "")")
        default:
            break
        }
    }

    private func timeText(_ raw: Any?) -> String {
        //= eslogger "time" is nanoseconds since the epoch (as a number or digit string); anything else is shown as is
        let text = raw.map { "\($0)" } ?? ""
        guard let ns = Double(text), ns > 1e15 else { return String(text.suffix(12)) }
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: Date(timeIntervalSince1970: ns / 1e9))
    }

    private func add(_ ev: [String: Any]) {
        let actor = ev["actor"] as? [String: Any] ?? [:]
        let path = actor["path"] as? String ?? ""
        var target = ev["target"] as? String ?? ""
        if let t2 = ev["target2"] as? String, !t2.isEmpty { target += "  ->  " + t2 }
        let row = ["time": timeText(ev["ts"]), "kind": ev["kind"] as? String ?? "",
                   "process": (path as NSString).lastPathComponent, "pid": "\(actor["pid"] ?? "")", "target": target]
        all.append(row)
        if all.count > EventsPane.maxRows { all.removeFirst(all.count - EventsPane.maxRows); rebuildVisible() }
        else if matches(row) { visible.append(row) }
        scheduleReload()
    }

    private func matches(_ row: [String: String]) -> Bool {
        let needle = searchField.stringValue.lowercased()
        if needle.isEmpty { return true }
        return row.values.contains { $0.lowercased().contains(needle) }
    }

    private func rebuildVisible() { visible = all.filter { matches($0) } }

    //= coalesce bursts: at most ~4 table reloads per second
    private func scheduleReload() {
        guard !reloadPending else { return }
        reloadPending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
            guard let self = self else { return }
            self.reloadPending = false
            if self.pauseCheck.state == .on { return }
            self.table.reloadData()
            if self.scrollCheck.state == .on, !self.visible.isEmpty { self.table.scrollRowToVisible(self.visible.count - 1) }
            self.statsLabel.stringValue = "\(self.visible.count) shown / \(self.all.count) kept"
        }
    }

    //= ---- table ---------------------------------------------------------------------------------------------
    func numberOfRows(in _: NSTableView) -> Int { visible.count }

    func tableView(_: NSTableView, objectValueFor column: NSTableColumn?, row: Int) -> Any? {
        guard let id = column?.identifier.rawValue, row < visible.count else { return nil }
        return visible[row][id]
    }
}
