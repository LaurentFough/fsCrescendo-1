import Cocoa

//= EventsPane.swift  version 0.1.0 (2026-11-08)
//= The Events tab. The app never runs privileged: it creates a private FIFO, tells the engine to read it
//= (`watch.start`), and shows the one-line command that YOU run in a terminal to feed it:
//=     sudo eslogger <events> > <fifo>
//= (eslogger needs root, plus Full Disk Access for the terminal app). No Endpoint Security entitlement is used.
//= Preferred source: the Crescendo event daemon (make esd-install), a root LaunchDaemon that runs eslogger on request:
//= Start/Stop/Pause just talk to it over a socket, no Terminal and no password. Fallback when it is not installed:
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
    private let kinds = ListField(pick: .none,
                                  hint: "Only show these kinds, one pattern per row (empty = all). * is a wildcard.",
                                  tip: "Examples: file.* (all file events), proc.exec, file.write, ipc.connect", visibleRows: 2)
    private let scopeChoose = NSButton(title: "Choose...", target: nil, action: nil)
    private let searchField = NSSearchField()
    private let pauseCheck = NSButton(checkboxWithTitle: "Pause", target: nil, action: nil)
    private let scrollCheck = NSButton(checkboxWithTitle: "Autoscroll", target: nil, action: nil)
    private let statsLabel = NSTextField(labelWithString: "not watching")
    private let daemonLabel = NSTextField(labelWithString: "daemon: checking...")
    private var usingDaemon = false
    private let bannerLabel = NSTextField(wrappingLabelWithString: "")
    private let bannerButton = NSButton(title: "", target: nil, action: nil)
    private let bannerBox = NSStackView()
    private var bannerAction: (() -> Void)?
    private var pausedByUser = false
    static let daemonSocket = "/var/run/com.loff.crescendo.esd.sock"
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
        scopePopup.toolTip = "What to watch: everything, or only one app (and the processes it starts), a folder, a file or a process id"
        scopeValue.placeholderString = "app name or path / absolute path / pid"
        scopeValue.toolTip = "app: a name like Safari or a path to an .app; dir/file: an absolute path; pid: a number"
        scopeChoose.target = self
        scopeChoose.action = #selector(chooseScope)
        scopeChoose.toolTip = "Pick the app, folder or file with a file dialog"
        scopePopup.target = self
        scopePopup.action = #selector(scopeKindChanged)
        let start = NSButton(title: "Start", target: self, action: #selector(startWatch))
        start.toolTip = "Begin capturing events with the chosen scope and kinds"
        let stop = NSButton(title: "Stop", target: self, action: #selector(stopWatch))
        stop.toolTip = "Stop capturing (with the event daemon, eslogger is stopped too)"
        let clear = NSButton(title: "Clear", target: self, action: #selector(clearRows))
        clear.toolTip = "Remove the captured rows from the table"
        let scopeBox = NSStackView(views: [NSTextField(labelWithString: "Scope:"), scopePopup, scopeValue, scopeChoose])
        scopeValue.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let actions = NSStackView(views: [start, stop, clear])
        let controlRow = NSStackView(views: [scopeBox, kinds.view, actions])
        controlRow.orientation = .horizontal
        controlRow.alignment = .top
        controlRow.distribution = .fill

        searchField.placeholderString = "filter shown rows"
        searchField.toolTip = "Show only captured rows that contain this text"
        pauseCheck.toolTip = "With the event daemon: stop eslogger and resume later. Otherwise: freeze the table."
        scrollCheck.toolTip = "Keep the newest row in view"
        daemonLabel.toolTip = "State of the event daemon that runs eslogger for this app"
        searchField.target = self
        searchField.action = #selector(filterChanged)
        scrollCheck.state = .on
        pauseCheck.target = self
        pauseCheck.action = #selector(pauseToggled)
        let filterRow = NSStackView(views: [searchField, pauseCheck, scrollCheck, daemonLabel, statsLabel])
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
        scroll.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical) //= the table takes the spare height
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true

        view.orientation = .vertical
        view.alignment = .leading
        view.spacing = 8
        view.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        scopeKindChanged() //= initial state: nothing to choose for "all events"
        bannerBox.orientation = .horizontal
        bannerBox.addArrangedSubview(bannerLabel)
        bannerBox.addArrangedSubview(bannerButton)
        bannerLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        bannerButton.target = self
        bannerButton.action = #selector(bannerClicked)
        bannerBox.isHidden = true
        //= re-check whenever the user comes back to the app (e.g. after granting Full Disk Access in System Settings)
        NotificationCenter.default.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil,
                                               queue: .main) { [weak self] _ in self?.refreshDaemon() }
        for row in [bannerBox, controlRow, filterRow, scroll] {
            view.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: view.widthAnchor, constant: -24).isActive = true
        }
    }

    //= ---- first-run checks ----------------------------------------------------------------------------------
    //= Three states: daemon missing -> offer to install it; daemon without Full Disk Access -> open System Settings
    //= at the right pane and reveal the binary to drag in; otherwise hide the banner.
    private func bundledInstaller() -> (script: String, binary: String)? {
        guard let dir = Bundle.main.resourceURL?.appendingPathComponent("esd").path else { return nil }
        let script = dir + "/esd-install.sh", binary = dir + "/crescendo-esd"
        let fm = FileManager.default
        return fm.fileExists(atPath: script) && fm.fileExists(atPath: binary) ? (script, binary) : nil
    }

    private func showBanner(_ text: String, button: String, action: @escaping () -> Void) {
        bannerLabel.stringValue = text
        bannerButton.title = button
        bannerButton.toolTip = text
        bannerAction = action
        bannerBox.isHidden = false
    }

    private func updateBanner(available: Bool, fda: Bool?) {
        if !available {
            if bundledInstaller() != nil {
                showBanner("The event daemon is not installed. It lets Crescendo start and stop system event capture "
                    + "without a Terminal. Installing asks for your administrator password once.",
                           button: "Install daemon...") { [weak self] in self?.installDaemon() }
            } else {
                showBanner("The event daemon is not installed. Run `make esd-install` in the repository (this build does not "
                    + "contain the installer).", button: "Copy command") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString("make esd-install", forType: .string)
                }
            }
        } else if fda == false {
            showBanner("The daemon needs Full Disk Access to run eslogger. Click the button, then add "
                + "/Library/PrivilegedHelperTools/com.loff.crescendo.esd to the list (drag it in from the Finder window "
                + "that opens) and switch it on.", button: "Open Full Disk Access...") { [weak self] in self?.openFullDiskAccess() }
        } else {
            bannerBox.isHidden = true
        }
    }

    @objc private func bannerClicked() { bannerAction?() }

    private func openFullDiskAccess() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
        let daemon = URL(fileURLWithPath: "/Library/PrivilegedHelperTools/com.loff.crescendo.esd")
        NSWorkspace.shared.activateFileViewerSelecting([daemon])
    }

    //= Runs the bundled installer with an administrator prompt. Paths travel as osascript arguments (never pasted into
    //= the script text), and the script quotes them for the shell.
    private func installDaemon() {
        guard let installer = bundledInstaller() else { return }
        let applescript = [
            "on run argv",
            "set cmd to \"/bin/sh \" & quoted form of (item 1 of argv) & \" install --uid \" & (item 2 of argv) & \" --binary \" & quoted form of (item 3 of argv)",
            "do shell script cmd with administrator privileges",
            "end run",
        ]
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = applescript.flatMap { ["-e", $0] } + [installer.script, String(getuid()), installer.binary]
        let errors = Pipe()
        proc.standardError = errors
        proc.standardOutput = Pipe()
        proc.terminationHandler = { [weak self] finished in
            let text = String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            DispatchQueue.main.async {
                if finished.terminationStatus == 0 {
                    self?.log?("event daemon installed")
                } else {
                    self?.log?("daemon install failed or was cancelled: \(text.trimmingCharacters(in: .whitespacesAndNewlines))")
                }
                self?.refreshDaemon()
            }
        }
        do { try proc.run() } catch { log?("cannot run osascript: \(error.localizedDescription)") }
    }

    //= ---- watch control -------------------------------------------------------------------------------------
    //= asks the engine whether the daemon answers; updates the label and (optionally) continues
    func refreshDaemon(then next: ((Bool) -> Void)? = nil) {
        call?("esd.status", ["socket": EventsPane.daemonSocket]) { [weak self] result in
            var available = false
            switch result {
            case let .success(info):
                available = info["available"] as? Bool ?? false
                let state = info["state"] as? String ?? "?"
                self?.daemonLabel.stringValue = available ? "daemon: \(state)" : "daemon: not installed"
                self?.updateBanner(available: available, fda: info["fda"] as? Bool)
            case .failure:
                self?.daemonLabel.stringValue = "daemon: engine not ready"
            }
            next?(available)
        }
    }

    @objc private func startWatch() {
        guard watchId == nil else { log?("already watching"); return }
        refreshDaemon { [weak self] available in self?.beginWatch(useDaemon: available) }
    }

    private func beginWatch(useDaemon: Bool) {
        var params: [String: Any]
        if useDaemon {
            params = ["source": ["socket": EventsPane.daemonSocket, "events": EventsPane.eventNames.split(separator: " ").map { String($0) }]]
        } else {
            if let problem = prepareFifo() { log?("ERROR: \(problem)"); return }
            params = ["source": ["file": EventsPane.fifoPath(), "follow": false]]
        }
        let kindValues = kinds.values
        if !kindValues.isEmpty { params["kinds"] = kindValues }
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
                self?.usingDaemon = useDaemon
                if useDaemon {
                    self?.statsLabel.stringValue = "watching via the event daemon"
                } else {
                    self?.statsLabel.stringValue = "watching - enter your password in the Terminal window"
                    self?.launchTerminal()
                }
                self?.refreshDaemon()
            case let .failure(err):
                self?.log?("watch.start failed: \(err.code): \(err.message)")
            }
        }
    }

    @objc private func stopWatch() {
        pausedByUser = false
        pauseCheck.state = .off
        endWatch()
    }

    private func endWatch() {
        guard let id = watchId else { return }
        call?("watch.stop", ["watch_id": id], nil)
    }

    //= With the daemon, Pause really stops eslogger (no CPU, nothing queued) and un-pausing starts it again with the
    //= same scope. Without it, Pause only freezes the table.
    @objc private func pauseToggled() {
        guard usingDaemon else { return }
        if pauseCheck.state == .on {
            pausedByUser = true
            endWatch()
        } else if pausedByUser {
            pausedByUser = false
            startWatch()
        }
    }

    @objc private func scopeKindChanged() {
        let title = scopePopup.titleOfSelectedItem ?? ""
        scopeChoose.isEnabled = ["app", "dir", "file"].contains(title)
    }

    @objc private func chooseScope() {
        let title = scopePopup.titleOfSelectedItem ?? ""
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = title == "dir" || title == "app" //= .app bundles are directories
        panel.canChooseFiles = title == "file" || title == "app"
        if title == "app" { panel.directoryURL = URL(fileURLWithPath: "/Applications") }
        panel.prompt = "Choose"
        if panel.runModal() == .OK, let url = panel.url { scopeValue.stringValue = url.path }
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
            refreshDaemon()
            let stats = data["stats"] as? [String: Any] ?? [:]
            statsLabel.stringValue = (pausedByUser ? "paused (eslogger stopped): " : "ended: ") + "read \(stats["read"] ?? 0), shown \(stats["shown"] ?? 0), dropped \(stats["dropped"] ?? 0)"
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
