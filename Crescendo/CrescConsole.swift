import Cocoa
import UniformTypeIdentifiers

//= CrescConsole.swift  version 0.4.0 (2026-11-09)
//= The cresc console: Sessions, Denials, Profile and Events tabs, driven by the `cresc serve` engine.
//= Workflow: run a program under a sandbox profile -> review its denials -> grant rules -> stop and restart -> compare.
//= Everything is built in code (no storyboard changes). Opened from the menu bar item "Cresc Console...".
//= Every control has a tooltip; multi-value inputs are ListField rows with pickers.

//= one displayed denial (a triage item flattened for the table)
struct DenialRow {
    var cls = "", risk = "", process = "", op = "", target = "", count = "", rule = "", change = ""
    var reason = "", note = "", ruleId = ""
    var needsConfirm = false, verified = false
}

final class CrescConsole: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate, NSTabViewDelegate, NSSplitViewDelegate {
    private let engine = EngineClient.shared
    private var mainTabs: NSTabView?
    private let events = EventsPane()
    let window: NSWindow

    //= run state
    private var currentRun: Int?
    private var runActive = false
    private var restartAfterStop = false

    //= denials state: raw triage items of the shown run, compare markers, and the filtered rows
    private var shownRun: Int?
    private var rawItems = [[String: Any]]()
    private var changes = [String: String]() //= "op|target" -> "new" | "persisting"
    private var resolvedCount = 0
    private var rows = [DenialRow]()
    private var runNumbers = [Int]()

    //= profile tab state
    private var history = [[String: Any]]()
    private var grantCount = 0

    //= Sessions widgets
    private let statusLabel = NSTextField(labelWithString: "engine: starting...")
    private let profileBox = NSComboBox()
    private let targetField = NSTextField(string: "")
    private let writeDirs = ListField(pick: .directories,
                                      hint: "Folders the program may WRITE to, one per row (everything else stays read-only or denied). "
                                          + "The first row is also its working directory.",
                                      tip: "Add... picks folders, + types a path, drag folders in from the Finder. At most 8.", visibleRows: 3)
    private let arguments = ListField(pick: .any,
                                      hint: "Program arguments, one per row, in order. Spaces inside a row stay part of that argument.",
                                      tip: "+ types an argument, Add... inserts file or folder paths, drag items in from the Finder.", visibleRows: 3)
    private let logView = NSTextView()

    //= Denials widgets
    private let runPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let showControl = NSSegmentedControl(labels: ["Candidates", "All"], trackingMode: .selectOne, target: nil, action: nil)
    private let denialSearch = NSSearchField()
    private let summaryLabel = NSTextField(labelWithString: "no run loaded")
    private let denialTable = NSTableView()
    private let detailView = NSTextView()
    private let denialColumns: [(id: String, title: String, width: CGFloat, tip: String)] = [
        ("change", "Change", 70, "Compared with the previous run: new, or persisting (resolved denials are counted in the summary)"),
        ("cls", "Class", 80, "candidate = may be worth allowing; benign = known harmless; path-search = PATH lookups; live = still running"),
        ("risk", "Risk", 60, "How risky the generated rule is: low, medium or high"),
        ("process", "Process", 110, "The process that was denied"),
        ("op", "Operation", 150, "The sandbox operation that was denied"),
        ("target", "Target", 290, "The file, device, service or host involved"),
        ("count", "Count", 50, "How many times it was denied in this run"),
        ("rule", "Rule", 300, "The sandbox rule that would allow it (empty = no safe rule can be generated)"),
    ]

    //= Profile widgets
    private let profileInfo = NSTextField(labelWithString: "")
    private let historyTable = NSTableView()
    private let sbplView = NSTextView()
    private let historyColumns: [(id: String, title: String, width: CGFloat)] = [
        ("version", "Version", 60), ("ts", "When", 180), ("action", "Action", 80), ("grant", "Grant id", 240), ("risk", "Risk", 70),
    ]

    override init() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 720),
                          styleMask: [.titled, .closable, .resizable, .miniaturizable],
                          backing: .buffered, defer: false)
        super.init()
        window.title = "Crescendo - cresc console - \(AppInfo.shortText)"
        window.delegate = self
        window.isReleasedWhenClosed = false
        buildUI()
        window.center()
        startEngine()
    }

    //= Default write folder, in order of preference: ~/.local/state/crescendo/sandbox, then
    //= ~/Library/Application Support/Crescendo/sandbox. The first one that exists or can be created (mode 0700) wins.
    static func defaultWriteFolder() -> String {
        let home = NSHomeDirectory()
        let candidates = [home + "/.local/state/crescendo/sandbox", home + "/Library/Application Support/Crescendo/sandbox"]
        for path in candidates {
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) {
                if isDirectory.boolValue { return path }
                continue //= something else is in the way
            }
            do {
                try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                return path
            } catch {
                NSLog("cannot create default write folder %@: %@", path, error.localizedDescription)
            }
        }
        return candidates[1]
    }

    //= ---- resizable panes -----------------------------------------------------------------------------------
    //= A table over a details area with a draggable divider. `bottomHeight` is the initial details height.
    private var pendingSplits = [(split: NSSplitView, bottom: CGFloat)]()

    private func makeSplit(top: NSView, bottom: NSView, bottomHeight: CGFloat) -> NSSplitView {
        let split = NSSplitView()
        split.isVertical = false //= panes stacked, divider is a horizontal line
        split.dividerStyle = .thin
        split.arrangesAllSubviews = true
        split.delegate = self
        split.addArrangedSubview(top)
        split.addArrangedSubview(bottom)
        split.setHoldingPriority(NSLayoutConstraint.Priority(250), forSubviewAt: 0) //= the table takes spare height...
        split.setHoldingPriority(NSLayoutConstraint.Priority(260), forSubviewAt: 1) //= ...the details keep their size
        split.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
        split.heightAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true
        pendingSplits.append((split, bottomHeight))
        return split
    }

    //= sets the initial divider position once the split has a real size (first time its tab is shown)
    private func applyPendingSplits() {
        pendingSplits.removeAll { entry in
            guard entry.split.bounds.height > entry.bottom + 120 else { return false }
            entry.split.setPosition(entry.split.bounds.height - entry.bottom - entry.split.dividerThickness, ofDividerAt: 0)
            return true
        }
    }

    func splitView(_ split: NSSplitView, constrainMinCoordinate proposed: CGFloat, ofSubviewAt _: Int) -> CGFloat {
        max(proposed, 100) //= keep at least 100 pt of table
    }

    func splitView(_ split: NSSplitView, constrainMaxCoordinate proposed: CGFloat, ofSubviewAt _: Int) -> CGFloat {
        min(proposed, split.bounds.height - 50 - split.dividerThickness) //= keep at least 50 pt of details
    }

    //= ---- small UI helpers ----------------------------------------------------------------------------------
    private func button(_ title: String, _ tip: String, _ action: Selector) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        b.toolTip = tip
        return b
    }

    private func rowLabel(_ text: String, _ tip: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.toolTip = tip
        label.alignment = .right
        label.widthAnchor.constraint(equalToConstant: 90).isActive = true
        return label
    }

    private func labelled(_ text: String, tip: String, _ content: NSView) -> NSStackView {
        let row = NSStackView(views: [rowLabel(text, tip), content])
        row.orientation = .horizontal
        row.alignment = .top
        return row
    }

    //= `grows`: this scroll view takes the spare height of its tab (one per tab); the others stay near minHeight
    private func scrolling(_ view: NSView, minHeight: CGFloat, grows: Bool = false) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.documentView = view
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: minHeight).isActive = true
        scroll.setContentHuggingPriority(NSLayoutConstraint.Priority(grows ? 1 : 750), for: .vertical)
        return scroll
    }

    //= read-only text that wraps to the width of its scroll view and grows downwards
    private func configureText(_ textView: NSTextView) {
        textView.isEditable = false
        textView.textColor = .textColor //= adaptive colours stated explicitly (light and dark mode)
        textView.drawsBackground = true
        textView.backgroundColor = .textBackgroundColor
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textView.textContainer?.containerSize = NSSize(width: 0, height: CGFloat.greatestFiniteMagnitude)
        textView.textContainerInset = NSSize(width: 4, height: 4)
    }

    private func pinWidths(_ stack: NSStackView, inset: CGFloat = 24) {
        for view in stack.arrangedSubviews {
            view.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -inset).isActive = true
        }
    }

    private func makeTable(_ table: NSTableView, columns: [(id: String, title: String, width: CGFloat)], tips: [String: String] = [:]) {
        for col in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(col.id))
            column.title = col.title
            column.width = col.width
            column.headerToolTip = tips[col.id]
            table.addTableColumn(column)
        }
        table.dataSource = self
        table.delegate = self
        table.usesAlternatingRowBackgroundColors = true
    }

    //= ---- UI ------------------------------------------------------------------------------------------------
    private func buildUI() {
        let tabs = NSTabView()
        tabs.delegate = self
        mainTabs = tabs
        addTab(tabs, "Sessions", buildSessions())
        addTab(tabs, "Denials", buildDenials())
        addTab(tabs, "Profile", buildProfile())
        events.call = { [weak self] method, params, reply in self?.engine.call(method, params, reply: reply) }
        events.log = { [weak self] text in self?.log(text) }
        addTab(tabs, "Events", events.view)

        statusLabel.toolTip = "State of the cresc engine (a Python helper the app starts and talks to over a pipe)"
        let root = NSStackView(views: [statusLabel, tabs])
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 6
        root.edgeInsets = NSEdgeInsets(top: 8, left: 8, bottom: 8, right: 8)
        tabs.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -16).isActive = true
        window.contentView = root
    }

    private func addTab(_ tabs: NSTabView, _ title: String, _ view: NSView) {
        //= The tab view gives its item view a frame but stack views size themselves to their contents, so the content
        //= is pinned to all four edges of a plain container; that is what makes it follow the window size.
        let container = NSView()
        view.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(view)
        NSLayoutConstraint.activate([
            view.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            view.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            view.topAnchor.constraint(equalTo: container.topAnchor),
            view.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
        let item = NSTabViewItem(identifier: title)
        item.label = title
        item.view = container
        tabs.addTabViewItem(item)
    }

    private func buildSessions() -> NSView {
        profileBox.isEditable = true
        profileBox.completes = true
        profileBox.stringValue = UserDefaults.standard.string(forKey: "cresc.profile") ?? "default"
        profileBox.toolTip = "Sandbox profile name. Pick an existing profile or type a new name (created on the first Start). "
            + "Letters, digits, '.', '_' and '-' only."
        targetField.placeholderString = "/absolute/path/to/the/program"
        targetField.stringValue = UserDefaults.standard.string(forKey: "cresc.target") ?? ""
        targetField.toolTip = "The program to run inside the sandbox. It is started with an empty environment, no stdin, "
            + "and the first write folder as its working directory."
        targetField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let choose = button("Choose...", "Pick the program with a file dialog", #selector(chooseTarget))
        let targetRow = NSStackView(views: [targetField, choose])
        var savedDirs = UserDefaults.standard.stringArray(forKey: "cresc.writeDirs") ?? []
        //= older builds defaulted to ~/tmp/_sandbox: if that was never changed, move to the new default
        if savedDirs.isEmpty || savedDirs == [NSHomeDirectory() + "/tmp/_sandbox"] { savedDirs = [CrescConsole.defaultWriteFolder()] }
        writeDirs.setValues(savedDirs)
        arguments.setValues(UserDefaults.standard.stringArray(forKey: "cresc.args") ?? [])

        configureText(logView)
        logView.font = NSFont.userFixedPitchFont(ofSize: 11)
        logView.toolTip = "Activity log of this window"
        let logScroll = scrolling(logView, minHeight: 150, grows: true)

        let buttons = NSStackView(views: [
            button("Start", "Run the program under the profile and watch its sandbox denials", #selector(startRun)),
            button("Stop", "Stop the running program (the whole process tree)", #selector(stopRun)),
            button("Restart", "Stop the program if it is running, then start it again with the current profile version", #selector(restartRun)),
        ])
        buttons.orientation = .horizontal

        let stack = NSStackView(views: [
            labelled("Profile", tip: "Sandbox profile", profileBox),
            labelled("Program", tip: "Program to run", targetRow),
            labelled("Write folders", tip: "Folders the program may write to", writeDirs.view),
            labelled("Arguments", tip: "Program arguments", arguments.view),
            buttons, logScroll,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        pinWidths(stack)
        return stack
    }

    private func buildDenials() -> NSView {
        runPopup.toolTip = "Which run to look at. A new run is shown automatically when it finishes."
        runPopup.target = self
        runPopup.action = #selector(runSelected)
        showControl.selectedSegment = 0
        showControl.target = self
        showControl.action = #selector(filterChanged)
        showControl.toolTip = "Candidates: denials that may be worth allowing. All: also known-harmless and PATH-search noise."
        denialSearch.placeholderString = "filter rows"
        denialSearch.toolTip = "Show only rows containing this text (process, operation, target, rule)"
        denialSearch.target = self
        denialSearch.action = #selector(filterChanged)
        denialSearch.widthAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
        summaryLabel.toolTip = "Counts for the shown run and how it compares with the previous run"
        let top = NSStackView(views: [NSTextField(labelWithString: "Run:"), runPopup,
                                      button("Reload", "Reload the list of runs and the shown run", #selector(reloadDenials)),
                                      showControl, denialSearch, summaryLabel])
        top.orientation = .horizontal

        makeTable(denialTable, columns: denialColumns.map { (id: $0.id, title: $0.title, width: $0.width) },
                  tips: Dictionary(uniqueKeysWithValues: denialColumns.map { ($0.id, $0.tip) }))
        denialTable.allowsMultipleSelection = true
        denialTable.toolTip = "Select rows, then use the buttons below. Rows without a rule cannot be granted."
        let tableScroll = scrolling(denialTable, minHeight: 100, grows: true)

        configureText(detailView)
        detailView.font = NSFont.userFixedPitchFont(ofSize: 11)
        detailView.toolTip = "Details of the selected denial"
        let detailScroll = scrolling(detailView, minHeight: 50)

        let grants = NSStackView(views: [
            button("Grant selected", "Add the rules of the selected rows to the profile (a new profile version)", #selector(grantSelected)),
            button("Grant selected & restart", "Grant, then stop and start the program again to see whether it is fixed", #selector(grantAndRestart)),
            button("Grant all low-risk", "Grant every low-risk candidate of the shown run", #selector(grantLow)),
            button("Grant up to medium...", "Grant every low and medium-risk candidate (asks you to confirm risky ones)", #selector(grantMedium)),
            button("Add rule by hand...", "Type an operation and a target yourself, for access the log did not show", #selector(addManual)),
        ])
        grants.orientation = .horizontal

        let evidence = NSStackView(views: [
            button("Export evidence...", "Zip everything about the shown run (record, output, denials, analysis, profile, SHA-256 manifest) for an investigation", #selector(exportEvidence)),
            button("Verify bundle...", "Check an evidence zip against its manifest to see whether any file was changed", #selector(verifyBundle)),
        ])
        evidence.orientation = .horizontal

        let split = makeSplit(top: tableScroll, bottom: detailScroll, bottomHeight: 120)
        let stack = NSStackView(views: [top, split, grants, evidence])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        pinWidths(stack)
        return stack
    }

    private func buildProfile() -> NSView {
        profileInfo.toolTip = "The profile named on the Sessions tab"
        makeTable(historyTable, columns: historyColumns)
        historyTable.toolTip = "Every change to the profile. Select a row to see that version's sandbox text."
        let tableScroll = scrolling(historyTable, minHeight: 100, grows: true)

        configureText(sbplView)
        sbplView.font = NSFont.userFixedPitchFont(ofSize: 11)
        sbplView.toolTip = "The sandbox profile text (SBPL) of the selected version"
        let sbplScroll = scrolling(sbplView, minHeight: 50)

        let buttons = NSStackView(views: [
            button("Refresh", "Reload the history from the engine", #selector(refreshProfile)),
            button("Diff with previous", "Show what the selected version changed compared with the one before it", #selector(diffSelected)),
            button("Revoke selected grant", "Remove the grant of the selected history row (creates a new profile version)", #selector(revokeSelected)),
        ])
        buttons.orientation = .horizontal
        let split = makeSplit(top: tableScroll, bottom: sbplScroll, bottomHeight: 300)
        let stack = NSStackView(views: [profileInfo, buttons, split])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        pinWidths(stack)
        return stack
    }

    func show() {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async { [weak self] in self?.applyPendingSplits() }
    }

    func windowWillClose(_: Notification) {
        //= keep the engine (and a running program) alive while the window is hidden
    }

    func tabView(_: NSTabView, didSelect item: NSTabViewItem?) {
        DispatchQueue.main.async { [weak self] in self?.applyPendingSplits() }
        switch item?.label {
        case "Denials": reloadDenials()
        case "Profile": refreshProfile()
        default: break
        }
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
        engine.addEventHandler { [weak self] name, data in self?.handleEvent(name, data) }
        engine.onExit = { [weak self] status in
            self?.statusLabel.stringValue = "engine: stopped (exit \(status))"
            self?.runActive = false
        }
        if let problem = engine.ensureStarted() {
            statusLabel.stringValue = "engine: not started"
            log("ERROR: \(problem)")
            return
        }
        engine.call("hello") { [weak self] result in
            switch result {
            case let .success(info):
                self?.statusLabel.stringValue = "engine: ready (protocol \(info["protocol"] ?? "?"), cresc \(info["cresc"] ?? "?"))"
                self?.events.refreshDaemon()
                self?.refreshProfileNames()
            case let .failure(err):
                self?.statusLabel.stringValue = "engine: \(err.message)"
            }
        }
    }

    //= the engine is shared with the main window and stopped by the app at exit
    func shutdown() {}

    func showEventsTab() {
        mainTabs?.selectTabViewItem(withIdentifier: "Events")
        show()
    }

    private func handleEvent(_ name: String, _ data: [String: Any]) {
        switch name {
        case "run.started":
            currentRun = data["run"] as? Int
            runActive = true
            shownRun = currentRun
            rawItems.removeAll(); changes.removeAll(); resolvedCount = 0
            rebuildRows()
            summaryLabel.stringValue = "run \(currentRun ?? 0) is running..."
            log("run \(currentRun ?? 0) started (profile version \(data["profile_version"] ?? "?"))")
        case "run.denial":
            if let d = data["denial"] as? [String: Any] { addLive(d) }
        case "run.finished":
            runActive = false
            let meta = data["meta"] as? [String: Any] ?? [:]
            log("run \(data["run"] ?? "?") finished: exit \(meta["exit"] ?? "?"), stopped=\(meta["stopped"] ?? false), timed_out=\(meta["timed_out"] ?? false)")
            reloadRuns(select: data["run"] as? Int)
            if restartAfterStop { restartAfterStop = false; beginRun() }
        case "run.error":
            runActive = false
            log("run error: \(data["message"] ?? "")")
        default:
            events.handle(name, data)
        }
    }

    //= ---- Sessions actions ----------------------------------------------------------------------------------
    private var profileName: String { profileBox.stringValue.trimmingCharacters(in: .whitespaces) }

    private func refreshProfileNames() {
        engine.call("profile.list") { [weak self] result in
            guard let self = self, case let .success(info) = result else { return }
            let names = info["profiles"] as? [String] ?? []
            let current = self.profileBox.stringValue
            self.profileBox.removeAllItems()
            self.profileBox.addItems(withObjectValues: names)
            self.profileBox.stringValue = current
        }
    }

    @objc private func chooseTarget() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Choose"
        if panel.runModal() == .OK, let url = panel.url { targetField.stringValue = url.path }
    }

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
        guard !writeDirs.values.isEmpty else { log("add at least one write folder"); return }
        let defaults = UserDefaults.standard
        defaults.set(name, forKey: "cresc.profile")
        defaults.set(targetField.stringValue, forKey: "cresc.target")
        defaults.set(writeDirs.values, forKey: "cresc.writeDirs")
        defaults.set(arguments.values, forKey: "cresc.args")
        engine.call("profile.list") { [weak self] result in
            guard let self = self else { return }
            let known = (try? result.get())?["profiles"] as? [String] ?? []
            if known.contains(name) { self.sendRunStart(name) } else {
                self.engine.call("profile.new", ["name": name]) { created in
                    switch created {
                    case .success: self.log("profile '\(name)' created"); self.refreshProfileNames(); self.sendRunStart(name)
                    case let .failure(err): self.log("profile.new failed: \(err.message)")
                    }
                }
            }
        }
    }

    private func sendRunStart(_ name: String) {
        let params: [String: Any] = ["name": name, "target": targetField.stringValue,
                                     "write_dirs": writeDirs.values, "args": arguments.values]
        engine.call("run.start", params) { [weak self] result in
            if case let .failure(err) = result { self?.log("run.start failed: \(err.code): \(err.message)") }
        }
    }

    //= ---- Denials: loading ----------------------------------------------------------------------------------
    @objc private func reloadDenials() { reloadRuns(select: shownRun) }

    //= refreshes the run popup, then loads `select` (or the newest run)
    private func reloadRuns(select: Int?) {
        let name = profileName
        guard !name.isEmpty else { return }
        engine.call("run.list", ["name": name]) { [weak self] result in
            guard let self = self else { return }
            guard case let .success(info) = result else { return }
            let runs = info["runs"] as? [[String: Any]] ?? []
            self.runNumbers = runs.compactMap { $0["run"] as? Int }
            self.runPopup.removeAllItems()
            for meta in runs {
                let n = meta["run"] as? Int ?? 0
                self.runPopup.addItem(withTitle: "Run \(n) - exit \(meta["exit"] ?? "?"), \(meta["groups"] ?? 0) groups, profile v\(meta["profile_version"] ?? "?")")
            }
            guard let wanted = select ?? self.runNumbers.last, let index = self.runNumbers.firstIndex(of: wanted) else {
                self.rawItems.removeAll(); self.rebuildRows()
                self.summaryLabel.stringValue = "no runs yet"
                return
            }
            self.runPopup.selectItem(at: index)
            self.loadRun(wanted)
        }
    }

    @objc private func runSelected() {
        let index = runPopup.indexOfSelectedItem
        if index >= 0 && index < runNumbers.count { loadRun(runNumbers[index]) }
    }

    //= loads every group of a run (hidden ones too, the filter is local) and compares it with the previous run
    private func loadRun(_ number: Int) {
        let name = profileName
        shownRun = number
        engine.call("triage.run", ["name": name, "run": number, "all": true]) { [weak self] result in
            guard let self = self, self.shownRun == number else { return }
            switch result {
            case let .success(info):
                self.rawItems = info["items"] as? [[String: Any]] ?? []
                self.changes.removeAll(); self.resolvedCount = 0
                self.updateSummary(info["summary"] as? [String: Any] ?? [:], compare: nil)
                self.rebuildRows()
                self.compareWithPrevious(number, summary: info["summary"] as? [String: Any] ?? [:])
            case let .failure(err):
                self.log("cannot load run \(number): \(err.message)")
            }
        }
    }

    private func compareWithPrevious(_ number: Int, summary: [String: Any]) {
        guard let index = runNumbers.firstIndex(of: number), index > 0 else { return }
        let previous = runNumbers[index - 1]
        engine.call("run.compare", ["name": profileName, "a": previous, "b": number]) { [weak self] result in
            guard let self = self, self.shownRun == number, case let .success(info) = result else { return }
            for entry in info["new"] as? [[String: Any]] ?? [] { self.changes[self.key(entry)] = "new" }
            for entry in info["persisting"] as? [[String: Any]] ?? [] { self.changes[self.key(entry)] = "persisting" }
            self.resolvedCount = (info["resolved"] as? [[String: Any]] ?? []).count
            self.updateSummary(summary, compare: previous)
            self.rebuildRows()
        }
    }

    private func key(_ entry: [String: Any]) -> String { "\(entry["op"] as? String ?? "")|\(entry["target"] as? String ?? "")" }

    private func updateSummary(_ s: [String: Any], compare: Int?) {
        var text = "\(s["groups"] ?? 0) groups: \(s["candidate"] ?? 0) candidate (\(s["low"] ?? 0) low, \(s["medium"] ?? 0) medium, \(s["high"] ?? 0) high), "
            + "\(s["benign"] ?? 0) benign, \(s["path-search"] ?? 0) path-search"
        if let previous = compare { text += " | vs run \(previous): \(resolvedCount) resolved" }
        summaryLabel.stringValue = text
    }

    //= live denials while the program runs: merge by op+target (no rule yet)
    private func addLive(_ d: [String: Any]) {
        let op = d["op"] as? String ?? "", target = d["target"] as? String ?? ""
        let count = d["count"] as? Int ?? 1
        if let i = rawItems.firstIndex(where: { ($0["op"] as? String) == op && ($0["target"] as? String) == target }) {
            rawItems[i]["count"] = (rawItems[i]["count"] as? Int ?? 0) + count
        } else {
            rawItems.append(["class": "live", "op": op, "target": target, "count": count,
                             "process": d["process"] as? String ?? "", "risk": ""])
        }
        rebuildRows()
    }

    private func rebuildRows() {
        let needle = denialSearch.stringValue.lowercased()
        let onlyCandidates = showControl.selectedSegment == 0
        rows = rawItems.compactMap { item -> DenialRow? in
            let cls = item["class"] as? String ?? ""
            if onlyCandidates && cls != "candidate" && cls != "live" { return nil }
            let rule = item["rule"] as? [String: Any]
            var row = DenialRow()
            row.cls = cls
            row.risk = item["risk"] as? String ?? ""
            row.process = item["process"] as? String ?? ""
            row.op = item["op"] as? String ?? ""
            row.target = item["target"] as? String ?? ""
            row.count = String(item["count"] as? Int ?? 1)
            row.rule = rule?["text"] as? String ?? ""
            row.ruleId = rule?["id"] as? String ?? ""
            row.reason = item["reason"] as? String ?? ""
            row.note = rule?["note"] as? String ?? ""
            row.needsConfirm = item["needs_confirm"] as? Bool ?? false
            row.verified = rule?["verified"] as? Bool ?? false
            row.change = changes["\(row.op)|\(row.target)"] ?? ""
            if !needle.isEmpty {
                let haystack = [row.process, row.op, row.target, row.rule, row.cls].joined(separator: " ").lowercased()
                if !haystack.contains(needle) { return nil }
            }
            return row
        }
        denialTable.reloadData()
        showDetail()
    }

    @objc private func filterChanged() { rebuildRows() }

    private func showDetail() {
        let selected = denialTable.selectedRowIndexes.filter { $0 < rows.count }
        guard let first = selected.first else {
            detailView.string = rows.isEmpty ? "No denials to show." : "Select a row to see details."
            return
        }
        let r = rows[first]
        var lines = ["\(r.process)  \(r.op)  \(r.target)", "class: \(r.cls)   risk: \(r.risk.isEmpty ? "-" : r.risk)   count: \(r.count)"]
        if !r.reason.isEmpty { lines.append("why: \(r.reason)") }
        lines.append(r.rule.isEmpty ? "rule: none (no safe rule can be generated automatically)" : "rule: \(r.rule)")
        if !r.note.isEmpty { lines.append("note: \(r.note)") }
        if r.needsConfirm { lines.append("needs confirmation: yes (high risk or an unverified rule form)") }
        if selected.count > 1 { lines.append("(\(selected.count) rows selected)") }
        detailView.string = lines.joined(separator: "\n")
    }

    func tableViewSelectionDidChange(_ note: Notification) {
        let table = note.object as? NSTableView
        if table === denialTable { showDetail() } else if table === historyTable { showSelectedVersion() }
    }

    //= ---- Denials: grants -----------------------------------------------------------------------------------
    private func selectedRuleIds() -> [String] {
        denialTable.selectedRowIndexes.compactMap { $0 < rows.count && !rows[$0].ruleId.isEmpty ? rows[$0].ruleId : nil }
    }

    @objc private func grantSelected() { grant(["ids": selectedRuleIds()], restart: false) }
    @objc private func grantAndRestart() { grant(["ids": selectedRuleIds()], restart: true) }
    @objc private func grantLow() { grant(["auto": "low"], restart: false) }
    @objc private func grantMedium() { grant(["auto": "medium"], restart: false) }

    private func grant(_ what: [String: Any], restart: Bool, confirm: Bool = false) {
        if let ids = what["ids"] as? [String], ids.isEmpty { log("select at least one row that has a rule"); return }
        var params = what
        params["name"] = profileName
        if what["manual"] == nil {
            if let run = shownRun ?? currentRun { params["run"] = run } else { params["run"] = "last" }
        }
        if confirm { params["confirm"] = true }
        engine.call("profile.grant", params) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case let .success(info):
                let granted = (info["grants"] as? [[String: Any]] ?? []).filter { $0["changed"] as? Bool ?? false }.count
                self.grantCount += granted
                self.log("granted \(granted) new rule(s): profile version \(info["version"] ?? "?")")
                self.refreshProfile()
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

    //= ---- evidence bundle -----------------------------------------------------------------------------------
    @objc private func exportEvidence() {
        guard let run = shownRun, !profileName.isEmpty else { log("load a run first (Denials tab)"); return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType.zip]
        panel.nameFieldStringValue = "\(profileName)-run\(run)-evidence.zip"
        panel.message = "Save an evidence bundle for run \(run): record, program output, denials, analysis, profile and a SHA-256 manifest."
        let redact = NSButton(checkboxWithTitle: "Replace my home folder path with ~", target: nil, action: nil)
        redact.state = .on
        redact.toolTip = "Removes your home folder path from the text files. Other personal data is NOT removed: review before sharing."
        panel.accessoryView = redact
        guard panel.runModal() == .OK, let url = panel.url else { return }
        //= NSSavePanel already asked about replacing an existing file, hence force
        engine.call("run.export", ["name": profileName, "run": run, "path": url.path, "force": true,
                                   "redact": redact.state == .on]) { [weak self] result in
            switch result {
            case let .success(info):
                let hash = info["sha256"] as? String ?? "?"
                self?.log("evidence bundle written: \(url.path)")
                self?.log("sha256 \(hash)  (keep this somewhere separate if the bundle is evidence)")
                NSWorkspace.shared.activateFileViewerSelecting([url])
            case let .failure(err):
                self?.log("export failed: \(err.code): \(err.message)")
            }
        }
    }

    @objc private func verifyBundle() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType.zip]
        panel.allowsMultipleSelection = false
        panel.message = "Choose an evidence bundle to verify against its manifest."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        engine.call("bundle.verify", ["path": url.path]) { [weak self] result in
            let alert = NSAlert()
            switch result {
            case let .success(info):
                let ok = info["ok"] as? Bool ?? false
                let problems = info["problems"] as? [String] ?? []
                alert.messageText = ok ? "Bundle is intact" : "Bundle does NOT match its manifest"
                alert.informativeText = ok ? "\(info["checked"] ?? 0) file(s) checked; every hash matches."
                    : problems.prefix(12).joined(separator: "\n")
                alert.alertStyle = ok ? .informational : .critical
            case let .failure(err):
                alert.messageText = "Could not verify"
                alert.informativeText = err.message
                self?.log("verify failed: \(err.message)")
            }
            alert.runModal()
        }
    }

    @objc private func addManual() {
        let op = NSTextField(string: "")
        op.placeholderString = "operation, e.g. file-read-data"
        op.toolTip = "A sandbox operation name such as file-read-data, sysctl-read or mach-lookup"
        let target = NSTextField(string: "")
        target.placeholderString = "target, e.g. /usr/share/zoneinfo (path, name or host)"
        target.toolTip = "What the operation applies to: an absolute path, a name, or a network target"
        let box = NSStackView(views: [op, target])
        box.orientation = .vertical
        box.spacing = 6
        box.frame = NSRect(x: 0, y: 0, width: 420, height: 56)
        op.widthAnchor.constraint(equalToConstant: 420).isActive = true
        target.widthAnchor.constraint(equalToConstant: 420).isActive = true
        let alert = NSAlert()
        alert.messageText = "Add a rule by hand"
        alert.informativeText = "Allow one operation on one target. Risky or unverified forms ask for confirmation next."
        alert.accessoryView = box
        alert.addButton(withTitle: "Grant")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let opText = op.stringValue.trimmingCharacters(in: .whitespaces)
        let targetText = target.stringValue.trimmingCharacters(in: .whitespaces)
        guard !opText.isEmpty, !targetText.isEmpty, !opText.contains(" ") else { log("manual rule needs an operation (no spaces) and a target"); return }
        grant(["manual": ["\(opText) \(targetText)"]], restart: false)
    }

    //= ---- Profile tab ---------------------------------------------------------------------------------------
    @objc private func refreshProfile() {
        let name = profileName
        guard !name.isEmpty else { return }
        engine.call("profile.history", ["name": name]) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case let .success(info):
                self.history = info["history"] as? [[String: Any]] ?? []
                self.profileInfo.stringValue = "Profile '\(name)': version \(info["version"] ?? "?"), \(self.history.count) change(s)"
                self.historyTable.reloadData()
                if !self.history.isEmpty {
                    self.historyTable.selectRowIndexes(IndexSet(integer: self.history.count - 1), byExtendingSelection: false)
                }
            case let .failure(err):
                self.history = []
                self.historyTable.reloadData()
                self.profileInfo.stringValue = "Profile '\(name)': \(err.message)"
                self.sbplView.string = ""
            }
        }
    }

    private func selectedHistoryRow() -> [String: Any]? {
        let index = historyTable.selectedRow
        return index >= 0 && index < history.count ? history[index] : nil
    }

    private func showSelectedVersion() {
        guard let row = selectedHistoryRow(), let version = row["version"] as? Int else { return }
        engine.call("profile.show", ["name": profileName, "version": version]) { [weak self] result in
            if case let .success(info) = result { self?.sbplView.string = info["text"] as? String ?? "" }
        }
    }

    @objc private func diffSelected() {
        guard let row = selectedHistoryRow(), let version = row["version"] as? Int, version > 1 else {
            log("select a version above 1 to compare with the previous one"); return
        }
        engine.call("profile.diff", ["name": profileName, "a": version - 1, "b": version]) { [weak self] result in
            switch result {
            case let .success(info): self?.sbplView.string = info["diff"] as? String ?? ""
            case let .failure(err): self?.log("diff failed: \(err.message)")
            }
        }
    }

    @objc private func revokeSelected() {
        guard let row = selectedHistoryRow(), row["action"] as? String == "grant", let id = row["grant"] as? String else {
            log("select a history row whose action is 'grant'"); return
        }
        let alert = NSAlert()
        alert.messageText = "Revoke this grant?"
        alert.informativeText = "\(id)\n\nThe rule is removed in a new profile version; older versions stay in the history."
        alert.addButton(withTitle: "Revoke")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        engine.call("profile.revoke", ["name": profileName, "id": id]) { [weak self] result in
            switch result {
            case let .success(info): self?.log("revoked: profile version \(info["version"] ?? "?")"); self?.refreshProfile()
            case let .failure(err): self?.log("revoke failed: \(err.code): \(err.message)")
            }
        }
    }

    //= ---- tables --------------------------------------------------------------------------------------------
    func numberOfRows(in table: NSTableView) -> Int {
        table === denialTable ? rows.count : history.count
    }

    func tableView(_ table: NSTableView, objectValueFor column: NSTableColumn?, row: Int) -> Any? {
        guard let id = column?.identifier.rawValue else { return nil }
        if table === denialTable {
            guard row < rows.count else { return nil }
            let r = rows[row]
            switch id {
            case "change": return r.change
            case "cls": return r.cls
            case "risk": return r.risk
            case "process": return r.process
            case "op": return r.op
            case "target": return r.target
            case "count": return r.count
            case "rule": return r.rule
            default: return nil
            }
        }
        guard row < history.count else { return nil }
        let value = history[row][id]
        return value.map { "\($0)" } ?? ""
    }
}

