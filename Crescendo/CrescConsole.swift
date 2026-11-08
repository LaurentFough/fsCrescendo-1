import Cocoa

//= CrescConsole.swift  version 0.1.0 (2026-11-08)
//= The cresc console: Sessions and Denials tabs (and an Events placeholder) driven by the `cresc serve` engine.
//= Workflow: run a program under a sandbox profile, see its denials, grant rules, stop and restart it.
//= Everything is built in code (no storyboard changes). Opened from the menu bar item "Cresc Console...".

final class CrescConsole: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    private let engine = EngineClient()
    private let events = EventsPane()
    let window: NSWindow

    //= state
    private var currentRun: Int?
    private var runActive = false
    private var restartAfterStop = false
    private var rows = [[String: String]]()
    private var ruleIds = [String]() //= parallel to rows: rule id or ""

    //= widgets
    private let statusLabel = NSTextField(labelWithString: "engine: starting...")
    private let profileField = NSTextField(string: "default")
    private let targetField = NSTextField(string: "")
    private let writeDirField = NSTextField(string: NSHomeDirectory() + "/tmp/_sandbox")
    private let argsField = NSTextField(string: "")
    private let logView = NSTextView()
    private let table = NSTableView()
    private let columns: [(id: String, title: String, width: CGFloat)] = [
        ("class", "Class", 80), ("risk", "Risk", 60), ("op", "Operation", 170),
        ("target", "Target", 330), ("count", "Count", 50), ("rule", "Rule", 330),
    ]

    override init() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1060, height: 640),
                          styleMask: [.titled, .closable, .resizable, .miniaturizable],
                          backing: .buffered, defer: false)
        super.init()
        window.title = "Crescendo - cresc console"
        window.delegate = self
        window.isReleasedWhenClosed = false
        buildUI()
        window.center()
        startEngine()
    }

    //= ---- UI ------------------------------------------------------------------------------------------------
    private func button(_ title: String, _ action: Selector) -> NSButton {
        NSButton(title: title, target: self, action: action)
    }

    private func labelled(_ text: String, _ field: NSTextField) -> NSStackView {
        let label = NSTextField(labelWithString: text)
        label.widthAnchor.constraint(equalToConstant: 90).isActive = true
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: [label, field])
        row.orientation = .horizontal
        return row
    }

    private func buildUI() {
        let tabs = NSTabView()

        //= Sessions
        targetField.placeholderString = "/absolute/path/to/program"
        writeDirField.placeholderString = "directories the program may write to, separated by ':'"
        argsField.placeholderString = "program arguments (split on spaces)"
        logView.isEditable = false
        logView.font = NSFont.userFixedPitchFont(ofSize: 11)
        let logScroll = NSScrollView()
        logScroll.documentView = logView
        logScroll.hasVerticalScroller = true
        logScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
        let buttons = NSStackView(views: [button("Start", #selector(startRun)), button("Stop", #selector(stopRun)),
                                          button("Restart", #selector(restartRun))])
        buttons.orientation = .horizontal
        let sessions = NSStackView(views: [labelled("Profile", profileField), labelled("Program", targetField),
                                           labelled("Write dirs", writeDirField), labelled("Arguments", argsField),
                                           buttons, logScroll])
        sessions.orientation = .vertical
        sessions.alignment = .leading
        sessions.spacing = 8
        sessions.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        for view in sessions.arrangedSubviews { view.widthAnchor.constraint(equalTo: sessions.widthAnchor, constant: -24).isActive = true }
        addTab(tabs, "Sessions", sessions)

        //= Denials
        for col in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(col.id))
            column.title = col.title
            column.width = col.width
            table.addTableColumn(column)
        }
        table.dataSource = self
        table.delegate = self
        table.allowsMultipleSelection = true
        let tableScroll = NSScrollView()
        tableScroll.documentView = table
        tableScroll.hasVerticalScroller = true
        let grantButtons = NSStackView(views: [button("Grant selected", #selector(grantSelected)),
                                               button("Grant all low-risk", #selector(grantLow)),
                                               button("Grant selected & restart", #selector(grantAndRestart))])
        grantButtons.orientation = .horizontal
        let denials = NSStackView(views: [tableScroll, grantButtons])
        denials.orientation = .vertical
        denials.alignment = .leading
        denials.spacing = 8
        denials.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        tableScroll.widthAnchor.constraint(equalTo: denials.widthAnchor, constant: -24).isActive = true
        addTab(tabs, "Denials", denials)

        //= Events: privileged eslogger feeds a FIFO that the engine reads (see EventsPane.swift)
        events.call = { [weak self] method, params, reply in self?.engine.call(method, params, reply: reply) }
        events.log = { [weak self] text in self?.log(text) }
        addTab(tabs, "Events", events.view)

        let root = NSStackView(views: [statusLabel, tabs])
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 6
        root.edgeInsets = NSEdgeInsets(top: 8, left: 8, bottom: 8, right: 8)
        tabs.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -16).isActive = true
        window.contentView = root
    }

    private func addTab(_ tabs: NSTabView, _ title: String, _ view: NSView) {
        let item = NSTabViewItem(identifier: title)
        item.label = title
        item.view = view
        tabs.addTabViewItem(item)
    }

    func show() {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_: Notification) {
        //= keep the engine (and a running program) alive while the window is hidden
    }

    //= ---- engine --------------------------------------------------------------------------------------------
    private func log(_ text: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        logView.textStorage?.append(NSAttributedString(string: "\(stamp) \(text)\n",
                                                       attributes: [.font: logView.font as Any,
                                                                    .foregroundColor: NSColor.textColor]))
        logView.scrollToEndOfDocument(nil)
    }

    private func startEngine() {
        engine.onEvent = { [weak self] name, data in self?.handleEvent(name, data) }
        engine.onExit = { [weak self] status in
            self?.statusLabel.stringValue = "engine: stopped (exit \(status))"
            self?.runActive = false
        }
        if let problem = engine.start() {
            statusLabel.stringValue = "engine: not started"
            log("ERROR: \(problem)")
            return
        }
        engine.call("hello") { [weak self] result in
            switch result {
            case let .success(info):
                self?.statusLabel.stringValue = "engine: ready (protocol \(info["protocol"] ?? "?"), cresc \(info["cresc"] ?? "?"))"
                self?.events.refreshDaemon()
            case let .failure(err):
                self?.statusLabel.stringValue = "engine: \(err.message)"
            }
        }
    }

    func shutdown() { engine.stop() }

    private func handleEvent(_ name: String, _ data: [String: Any]) {
        switch name {
        case "run.started":
            currentRun = data["run"] as? Int
            runActive = true
            rows.removeAll(); ruleIds.removeAll(); table.reloadData()
            log("run \(currentRun ?? 0) started (profile version \(data["profile_version"] ?? "?"))")
        case "run.denial":
            if let d = data["denial"] as? [String: Any] { addLive(d) }
        case "run.finished":
            runActive = false
            let meta = data["meta"] as? [String: Any] ?? [:]
            log("run \(data["run"] ?? "?") finished: exit \(meta["exit"] ?? "?"), stopped=\(meta["stopped"] ?? false), timed_out=\(meta["timed_out"] ?? false)")
            if let triage = data["triage"] as? [String: Any], let items = triage["items"] as? [[String: Any]] { showTriage(items) }
            if restartAfterStop { restartAfterStop = false; beginRun() }
        case "run.error":
            runActive = false
            log("run error: \(data["message"] ?? "")")
        default:
            events.handle(name, data)
        }
    }

    //= live denials before triage exists: merge by op+target
    private func addLive(_ d: [String: Any]) {
        let op = d["op"] as? String ?? "", target = d["target"] as? String ?? ""
        let count = d["count"] as? Int ?? 1
        if let i = rows.firstIndex(where: { $0["op"] == op && $0["target"] == target }) {
            rows[i]["count"] = String((Int(rows[i]["count"] ?? "0") ?? 0) + count)
        } else {
            rows.append(["class": "live", "risk": "", "op": op, "target": target, "count": String(count), "rule": ""])
            ruleIds.append("")
        }
        table.reloadData()
    }

    private func showTriage(_ items: [[String: Any]]) {
        rows.removeAll(); ruleIds.removeAll()
        for item in items where (item["class"] as? String) == "candidate" {
            let rule = item["rule"] as? [String: Any]
            rows.append(["class": "candidate", "risk": item["risk"] as? String ?? "",
                         "op": item["op"] as? String ?? "", "target": item["target"] as? String ?? "",
                         "count": String(item["count"] as? Int ?? 1), "rule": rule?["text"] as? String ?? "(no rule)"])
            ruleIds.append(rule?["id"] as? String ?? "")
        }
        table.reloadData()
        log("\(rows.count) candidate denial(s)")
    }

    //= ---- session actions -----------------------------------------------------------------------------------
    private var profileName: String { profileField.stringValue.trimmingCharacters(in: .whitespaces) }

    @objc private func startRun() { beginRun() }

    @objc private func stopRun() {
        guard runActive else { log("no run is active"); return }
        engine.call("run.stop", ["name": profileName, "run": currentRun ?? "last"]) { [weak self] result in
            if case let .failure(err) = result { self?.log("stop failed: \(err.message)") }
        }
    }

    @objc private func restartRun() {
        if runActive { restartAfterStop = true; stopRun() } else { beginRun() }
    }

    //= creates the profile when it does not exist yet, then starts the run
    private func beginRun() {
        let name = profileName
        guard !name.isEmpty, !targetField.stringValue.isEmpty else { log("profile and program are required"); return }
        engine.call("profile.list") { [weak self] result in
            guard let self = self else { return }
            let known = (try? result.get())?["profiles"] as? [String] ?? []
            if known.contains(name) { self.sendRunStart(name) } else {
                self.engine.call("profile.new", ["name": name]) { created in
                    switch created {
                    case .success: self.log("profile '\(name)' created"); self.sendRunStart(name)
                    case let .failure(err): self.log("profile.new failed: \(err.message)")
                    }
                }
            }
        }
    }

    private func sendRunStart(_ name: String) {
        let dirs = writeDirField.stringValue.split(separator: ":").map { String($0) }
        let args = argsField.stringValue.split(separator: " ").map { String($0) }
        engine.call("run.start", ["name": name, "target": targetField.stringValue, "write_dirs": dirs, "args": args]) { [weak self] result in
            if case let .failure(err) = result { self?.log("run.start failed: \(err.code): \(err.message)") }
        }
    }

    //= ---- grants --------------------------------------------------------------------------------------------
    private func selectedRuleIds() -> [String] {
        table.selectedRowIndexes.compactMap { $0 < ruleIds.count && !ruleIds[$0].isEmpty ? ruleIds[$0] : nil }
    }

    @objc private func grantSelected() { grant(["ids": selectedRuleIds()], restart: false) }
    @objc private func grantAndRestart() { grant(["ids": selectedRuleIds()], restart: true) }
    @objc private func grantLow() { grant(["auto": "low"], restart: false) }

    private func grant(_ what: [String: Any], restart: Bool, confirm: Bool = false) {
        if let ids = what["ids"] as? [String], ids.isEmpty { log("select at least one row that has a rule"); return }
        var params = what
        params["name"] = profileName
        params["run"] = currentRun ?? "last"
        if confirm { params["confirm"] = true }
        engine.call("profile.grant", params) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case let .success(info):
                self.log("granted: profile version \(info["version"] ?? "?")")
                if restart { self.restartRun() }
            case let .failure(err) where err.code == "confirmation_required":
                let rules = ((err.data as? [String: Any])?["rules"] as? [[String: Any]] ?? [])
                    .compactMap { ($0["rule"] as? [String: Any])?["text"] as? String }
                let alert = NSAlert()
                alert.messageText = "These rules need your confirmation"
                alert.informativeText = rules.joined(separator: "\n")
                alert.addButton(withTitle: "Grant")
                alert.addButton(withTitle: "Cancel")
                if alert.runModal() == .alertFirstButtonReturn { self.grant(what, restart: restart, confirm: true) }
            case let .failure(err):
                self.log("grant failed: \(err.code): \(err.message)")
            }
        }
    }

    //= ---- table ---------------------------------------------------------------------------------------------
    func numberOfRows(in _: NSTableView) -> Int { rows.count }

    func tableView(_: NSTableView, objectValueFor column: NSTableColumn?, row: Int) -> Any? {
        guard let id = column?.identifier.rawValue, row < rows.count else { return nil }
        return rows[row][id]
    }
}
