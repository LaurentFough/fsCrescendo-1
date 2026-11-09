import Cocoa

//= RecordingPlayer.swift  version 0.1.0 (2026-11-09)
//= Opening and replaying recordings (.crescrec). A recording is a read-only document: the engine reads and replays it
//= (recording.open / recording.play, see tools/cresc/PROTOCOL.md), and the window shows the replay in the same Files view as
//= live capture (list, text, inspector, filters, hidden folders), plus a transport bar: play / pause, restart, speed, a time scrubber.
//= "Save As..." on a recording copies the file. Closing the window stops the replay.

final class RecordingDocument: NSDocument {
    private var player: PlayerViewController?

    override class var autosavesInPlace: Bool { false }
    override class func canConcurrentlyReadDocuments(ofType _: String) -> Bool { false }

    //= the engine reads the file; the document only checks the extension and remembers where the file is
    override func read(from url: URL, ofType _: String) throws {
        guard url.pathExtension == "crescrec" else {
            throw NSError(domain: NSCocoaErrorDomain, code: NSFileReadCorruptFileError,
                          userInfo: [NSLocalizedDescriptionKey: "This is not a Crescendo recording (.crescrec)."])
        }
    }

    //= Save As... copies the recording
    override func data(ofType _: String) throws -> Data {
        guard let url = fileURL else {
            throw NSError(domain: NSCocoaErrorDomain, code: NSFileNoSuchFileError, userInfo: nil)
        }
        return try Data(contentsOf: url)
    }

    override func makeWindowControllers() {
        guard let url = fileURL else { return }
        let controller = PlayerViewController(path: url.path)
        player = controller
        let window = NSWindow(contentViewController: controller)
        window.setContentSize(NSSize(width: 1100, height: 700))
        window.minSize = NSSize(width: 760, height: 460)
        addWindowController(NSWindowController(window: window))
    }

    override func close() {
        player?.shutdown()
        super.close()
    }
}

final class PlayerViewController: NSViewController {
    private let path: String
    private let files = FilesViewController(replay: true)
    private let engine = EngineClient.shared
    private var playId: String?
    private var duration = 0.0
    private var paused = false
    private var ended = false

    private let playButton = NSButton(title: "Pause", target: nil, action: nil)
    private let restartButton = NSButton(title: "Restart", target: nil, action: nil)
    private let speedPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let scrubber = NSSlider(value: 0, minValue: 0, maxValue: 1, target: nil, action: nil)
    private let timeLabel = NSTextField(labelWithString: "0:00 / 0:00")
    private let infoLabel = NSTextField(wrappingLabelWithString: "opening...")
    private let followCheck = NSButton(checkboxWithTitle: "Follow newest", target: nil, action: nil)
    private let speeds: [(title: String, value: Double)] = [
        ("0.5x", 0.5), ("1x", 1), ("2x", 2), ("5x", 5), ("10x", 10), ("50x", 50), ("500x", 500),
    ]

    init(path: String) {
        self.path = path
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder _: NSCoder) { fatalError("not used") }

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 1100, height: 700))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        playButton.target = self
        playButton.action = #selector(togglePlay)
        playButton.toolTip = "Pause or resume the replay (Replay starts again after the end)"
        restartButton.target = self
        restartButton.action = #selector(restart)
        restartButton.toolTip = "Clear the list and replay from the beginning"
        speedPopup.addItems(withTitles: speeds.map { $0.title })
        speedPopup.selectItem(at: 1)
        speedPopup.target = self
        speedPopup.action = #selector(speedChanged)
        speedPopup.toolTip = "Replay speed. Long quiet gaps (over 2 seconds) are always shortened."
        scrubber.isContinuous = false //= the action fires when the mouse is released
        scrubber.target = self
        scrubber.action = #selector(scrubbed)
        scrubber.toolTip = "Drag to jump to a moment: the list shows everything up to that time"
        scrubber.setContentHuggingPriority(.defaultLow, for: .horizontal)
        scrubber.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
        timeLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .regular)
        timeLabel.toolTip = "Position in the recording / its length"
        followCheck.state = .on
        followCheck.toolTip = "Keep the newest row in view while replaying"
        infoLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        infoLabel.textColor = .secondaryLabelColor
        infoLabel.toolTip = "What this recording is: kind, when and where it was made, how many records, whether its hash is intact"
        files.autoscroll = { [weak self] in self?.followCheck.state != .off }

        let transport = NSStackView(views: [playButton, restartButton, speedPopup, scrubber, timeLabel, followCheck])
        transport.orientation = .horizontal
        let top = NSStackView(views: [infoLabel, transport])
        top.orientation = .vertical
        top.alignment = .leading
        top.spacing = 6
        top.edgeInsets = NSEdgeInsets(top: 10, left: 20, bottom: 4, right: 20)
        top.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(top)

        addChild(files)
        let list = files.view
        list.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(list)
        NSLayoutConstraint.activate([
            top.leadingAnchor.constraint(equalTo: view.leadingAnchor), top.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            top.topAnchor.constraint(equalTo: view.topAnchor),
            transport.widthAnchor.constraint(equalTo: top.widthAnchor, constant: -40),
            infoLabel.widthAnchor.constraint(equalTo: top.widthAnchor, constant: -40),
            list.leadingAnchor.constraint(equalTo: view.leadingAnchor), list.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            list.topAnchor.constraint(equalTo: top.bottomAnchor), list.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        engine.addEventHandler { [weak self] name, data in self?.handle(name, data) }
        start()
    }

    func shutdown() {
        stopCurrent()
    }

    //= ---- engine --------------------------------------------------------------------------------------------
    private func start() {
        if let problem = engine.ensureStarted() {
            infoLabel.stringValue = "engine: \(problem)"
            return
        }
        engine.call("recording.open", ["path": path]) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case let .success(info):
                let header = info["header"] as? [String: Any] ?? [:]
                let host = (header["host"] as? [String: Any])?["hostname"] as? String ?? "unknown host"
                let seconds = info["duration_s"] as? Double ?? 0
                var text = "\(header["kind"] as? String ?? "recording") made \(header["created"] as? String ?? "?") on \(host): "
                text += "\(info["records"] as? Int ?? 0) records, \(String(format: "%.1f", seconds)) s. "
                if info["ok"] as? Bool == true {
                    text += info["complete"] as? Bool == true ? "Hash verified: not changed since it was written." : "Incomplete file (no footer)."
                } else {
                    text += "NOT VERIFIED: " + ((info["problems"] as? [String])?.first ?? "unknown problem")
                }
                self.infoLabel.stringValue = text
                self.play(from: 0)
            case let .failure(err):
                self.infoLabel.stringValue = "cannot open the recording: \(err.message)"
            }
        }
    }

    private func play(from start: Double) {
        let speed = speeds[max(0, speedPopup.indexOfSelectedItem)].value
        var params: [String: Any] = ["path": path, "speed": speed, "max_gap": 2.0]
        if start > 0 { params["start_t"] = start }
        engine.call("recording.play", params) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case let .success(info):
                self.playId = info["play_id"] as? String
                self.duration = info["duration_s"] as? Double ?? 0
                self.scrubber.maxValue = max(self.duration, 0.001)
                self.ended = false
                self.paused = false
                self.playButton.title = "Pause"
                self.updateTime(start)
            case let .failure(err):
                self.infoLabel.stringValue = "cannot play: \(err.message)"
            }
        }
    }

    private func stopCurrent() {
        if let id = playId { engine.call("recording.control", ["play_id": id, "action": "stop"]) }
        playId = nil
    }

    private func handle(_ name: String, _ data: [String: Any]) {
        guard name == "recording.records", let id = playId, data["play_id"] as? String == id else { return }
        if data["reset"] as? Bool == true { files.resetRows() }
        for record in data["records"] as? [[String: Any]] ?? [] {
            if record["type"] as? String == "change", let change = record["data"] as? [String: Any] { files.ingest(change) }
        }
        let position = data["position"] as? Double ?? 0
        scrubber.doubleValue = position
        updateTime(position)
        if data["ended"] as? Bool == true {
            ended = true
            playButton.title = "Replay"
        }
    }

    private func updateTime(_ position: Double) {
        func clock(_ s: Double) -> String { String(format: "%d:%02d", Int(s) / 60, Int(s) % 60) }
        timeLabel.stringValue = "\(clock(position)) / \(clock(duration))"
    }

    //= ---- transport -----------------------------------------------------------------------------------------
    @objc private func togglePlay() {
        if ended { restart(); return }
        guard let id = playId else { return }
        paused.toggle()
        playButton.title = paused ? "Play" : "Pause"
        engine.call("recording.control", ["play_id": id, "action": paused ? "pause" : "resume"])
    }

    @objc private func restart() {
        stopCurrent()
        files.resetRows()
        play(from: 0)
    }

    @objc private func speedChanged() {
        guard let id = playId, !ended else { return }
        engine.call("recording.control", ["play_id": id, "action": "speed", "value": speeds[max(0, speedPopup.indexOfSelectedItem)].value])
    }

    @objc private func scrubbed() {
        let target = scrubber.doubleValue
        if ended || playId == nil {
            stopCurrent()
            files.resetRows()
            play(from: target) //= a finished replay has no running player: start a new one at that moment
        } else if let id = playId {
            engine.call("recording.control", ["play_id": id, "action": "seek", "value": target])
        }
    }
}
