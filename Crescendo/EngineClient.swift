import Foundation

//= EngineClient.swift  version 0.2.0 (2026-11-09)
//= Talks to the `cresc serve` child process (protocol 1, see tools/cresc/PROTOCOL.md): JSON objects, one per line,
//= requests on its stdin, responses and push events on its stdout. No network socket is involved.
//= All callbacks arrive on the main queue. Nothing here runs privileged.

struct EngineError: Error {
    let code: String
    let message: String
    let data: Any?
}

final class EngineClient {
    typealias Reply = (Result<[String: Any], EngineError>) -> Void
    typealias EventHandler = (String, [String: Any]) -> Void

    //= one engine for the whole app: the console and the Files view share it
    static let shared = EngineClient()

    private var handlers = [EventHandler]()

    //= every listener sees every push event (filter by event name and watch_id yourself); call on the main queue
    func addEventHandler(_ handler: @escaping EventHandler) { handlers.append(handler) }

    //= push events: (event name, data), e.g. ("run.denial", [...])
    var onEvent: ((String, [String: Any]) -> Void)?
    //= called once when the child exits (status), whatever the reason
    var onExit: ((Int32) -> Void)?

    private let ioQueue = DispatchQueue(label: "com.loff.crescendo.engine")
    private var process: Process?
    private var input: FileHandle?
    private var nextId = 1
    private var pending = [Int: Reply]()
    private var buffer = Data()

    var isRunning: Bool { process?.isRunning ?? false }

    //= ---- locating the pieces -------------------------------------------------------------------------------
    //= Engine directory (the folder that contains the `cresc` package): CRESC_ENGINE_DIR, then the app bundle
    //= (Contents/Resources/cresc-engine, added by `make build-lite`), then a dev checkout next to the app.
    static func engineDirectory() -> URL? {
        let fm = FileManager.default
        var candidates = [URL]()
        if let env = ProcessInfo.processInfo.environment["CRESC_ENGINE_DIR"], !env.isEmpty {
            candidates.append(URL(fileURLWithPath: env))
        }
        if let res = Bundle.main.resourceURL {
            candidates.append(res.appendingPathComponent("cresc-engine"))
        }
        var dir = Bundle.main.bundleURL
        for _ in 0 ..< 5 { //= build/lite/Crescendo.app -> ... -> repo root
            dir = dir.deletingLastPathComponent()
            candidates.append(dir.appendingPathComponent("tools/cresc"))
        }
        return candidates.first { fm.fileExists(atPath: $0.appendingPathComponent("cresc/__init__.py").path) }
    }

    //= Python 3: CRESC_PYTHON, then the usual places. /usr/bin/python3 is the Command Line Tools shim.
    static func pythonPath() -> String? {
        var candidates = [String]()
        if let env = ProcessInfo.processInfo.environment["CRESC_PYTHON"], !env.isEmpty { candidates.append(env) }
        candidates += ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    //= ---- lifecycle -----------------------------------------------------------------------------------------
    //= Starts the child unless it already runs. Returns an error text, or nil.
    func ensureStarted() -> String? { isRunning ? nil : start() }

    //= Starts the child. Returns an error text, or nil on success.
    func start() -> String? {
        if isRunning { return nil }
        signal(SIGPIPE, SIG_IGN) //= a dead engine must give an error on write, not kill the app
        guard let python = EngineClient.pythonPath() else {
            return "python3 not found (install it, or set CRESC_PYTHON)"
        }
        guard let engine = EngineClient.engineDirectory() else {
            return "cresc engine not found (expected Contents/Resources/cresc-engine or tools/cresc)"
        }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: python)
        proc.arguments = ["-m", "cresc", "serve"]
        proc.currentDirectoryURL = engine
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = engine.path
        env["PYTHONDONTWRITEBYTECODE"] = "1" //= never write into the (signed) app bundle
        env["PYTHONIOENCODING"] = "utf-8"
        proc.environment = env

        let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
        proc.standardInput = inPipe
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        input = inPipe.fileHandleForWriting

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            if chunk.isEmpty { handle.readabilityHandler = nil; return }
            self?.ioQueue.async { self?.consume(chunk) }
        }
        errPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty { handle.readabilityHandler = nil; return }
            if let text = String(data: chunk, encoding: .utf8) { NSLog("cresc: %@", text) }
        }
        proc.terminationHandler = { [weak self] finished in
            self?.ioQueue.async {
                let waiting = self?.pending ?? [:]
                self?.pending.removeAll()
                DispatchQueue.main.async {
                    for (_, reply) in waiting {
                        reply(.failure(EngineError(code: "engine_exited", message: "the cresc engine stopped", data: nil)))
                    }
                    self?.onExit?(finished.terminationStatus)
                }
            }
        }
        do {
            try proc.run()
        } catch {
            return "cannot start the engine: \(error.localizedDescription)"
        }
        process = proc
        return nil
    }

    //= Closing stdin makes the server cancel runs and watches and exit 0; terminate() is the fallback.
    func stop() {
        try? input?.close()
        input = nil
        let proc = process
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
            if proc?.isRunning == true { proc?.terminate() }
        }
    }

    //= ---- requests ------------------------------------------------------------------------------------------
    func call(_ method: String, _ params: [String: Any] = [:], reply: Reply? = nil) {
        ioQueue.async { [self] in
            let id = nextId
            nextId += 1
            if let reply = reply { pending[id] = reply }
            let request: [String: Any] = ["id": id, "method": method, "params": params]
            guard JSONSerialization.isValidJSONObject(request),
                let body = try? JSONSerialization.data(withJSONObject: request), let handle = input else {
                pending[id] = nil
                DispatchQueue.main.async {
                    reply?(.failure(EngineError(code: "not_running", message: "the cresc engine is not running", data: nil)))
                }
                return
            }
            do {
                try handle.write(contentsOf: body + Data([0x0A]))
            } catch {
                pending[id] = nil
                DispatchQueue.main.async {
                    reply?(.failure(EngineError(code: "write_failed", message: error.localizedDescription, data: nil)))
                }
            }
        }
    }

    //= ---- reading (ioQueue) ---------------------------------------------------------------------------------
    private func consume(_ chunk: Data) {
        buffer.append(chunk)
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer.subdata(in: buffer.startIndex ..< newline)
            buffer.removeSubrange(buffer.startIndex ... newline)
            guard !line.isEmpty, let obj = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else {
                NSLog("cresc: unreadable line from engine (%d bytes)", line.count)
                continue
            }
            dispatch(obj)
        }
    }

    private func dispatch(_ obj: [String: Any]) {
        if let event = obj["event"] as? String {
            let data = obj["data"] as? [String: Any] ?? [:]
            DispatchQueue.main.async {
                self.onEvent?(event, data)
                for handler in self.handlers { handler(event, data) }
            }
            return
        }
        guard let id = obj["id"] as? Int, let reply = pending.removeValue(forKey: id) else { return }
        let result: Result<[String: Any], EngineError>
        if obj["ok"] as? Bool == true {
            result = .success(obj["result"] as? [String: Any] ?? [:])
        } else {
            let err = obj["error"] as? [String: Any] ?? [:]
            result = .failure(EngineError(code: err["code"] as? String ?? "internal",
                                          message: err["message"] as? String ?? "unknown error",
                                          data: err["data"]))
        }
        DispatchQueue.main.async { reply(result) }
    }
}
