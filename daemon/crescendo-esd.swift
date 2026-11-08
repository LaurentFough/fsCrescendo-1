import Foundation

//= crescendo-esd.swift  version 0.1.0 (2026-11-08)
//= Crescendo event daemon: a small root LaunchDaemon that runs Apple's /usr/bin/eslogger ON REQUEST and streams its
//= JSON lines to the one user it serves. It needs no Endpoint Security entitlement of its own (eslogger has Apple's).
//= Socket protocol (client -> daemon, one line each; replies are single JSON lines starting {"esd":1,...}):
//=     status                  -> ok, state idle|running, version, events
//=     start EVENT [EVENT ...] -> ok, then raw eslogger lines until `stop` or disconnect
//=     stop                    -> ok, state idle
//= Safety: socket file is owned by --uid with mode 0600 AND every connection's uid is checked with getpeereid();
//= event names are [a-z_]{1,40}, at most 40; one stream at a time; eslogger is killed when the client goes away.
//= The daemon holds the Full Disk Access grant that eslogger needs (System Settings > Privacy & Security).
//= Usage: crescendo-esd --uid N [--socket PATH] [--eslogger PATH]      (logs to stderr; launchd redirects it)

let esdVersion = "0.1.0"
let defaultSocket = "/var/run/com.loff.crescendo.esd.sock"

func logLine(_ text: String) {
    let stamp = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write(Data("\(stamp) crescendo-esd[\(esdVersion)] \(text)\n".utf8))
}

struct Config {
    var socket = defaultSocket
    var uid: uid_t = 0
    var eslogger = "/usr/bin/eslogger"
}

func parseArguments() -> Config? {
    var cfg = Config()
    var args = Array(CommandLine.arguments.dropFirst())
    var haveUid = false
    while !args.isEmpty {
        let flag = args.removeFirst()
        guard !args.isEmpty else { logLine("missing value for \(flag)"); return nil }
        let value = args.removeFirst()
        switch flag {
        case "--socket": cfg.socket = value
        case "--eslogger": cfg.eslogger = value
        case "--uid":
            guard let n = UInt32(value), n > 0 else { logLine("--uid must be a positive number"); return nil }
            cfg.uid = uid_t(n); haveUid = true
        default: logLine("unknown argument \(flag)"); return nil
        }
    }
    guard haveUid else { logLine("--uid is required (the user this daemon serves)"); return nil }
    guard cfg.socket.hasPrefix("/"), cfg.socket.utf8.count < 100 else { logLine("--socket must be an absolute path under 100 bytes"); return nil }
    guard cfg.eslogger.hasPrefix("/") else { logLine("--eslogger must be an absolute path"); return nil }
    return cfg
}

func validEventName(_ name: String) -> Bool {
    guard (1 ... 40).contains(name.utf8.count) else { return false }
    return name.utf8.allSatisfy { ($0 >= 97 && $0 <= 122) || $0 == 95 } //= a-z or _
}

//= one connection; writes are serialised so control replies never land inside an event line
final class Conn {
    let fd: Int32
    private let lock = NSLock()
    init(fd: Int32) { self.fd = fd }

    @discardableResult
    func write(_ bytes: [UInt8]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        var offset = 0
        while offset < bytes.count {
            let n = bytes[offset...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            if n < 0 {
                if errno == EINTR { continue }
                return false
            }
            offset += n
        }
        return true
    }

    //= {"esd":1,...} built by hand so that "esd" is always the first key
    @discardableResult
    func reply(_ fields: [String: Any]) -> Bool {
        var body = fields
        if body["ok"] == nil { body["ok"] = true }
        guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]),
            let text = String(data: data, encoding: .utf8), text.hasPrefix("{") else { return false }
        let rest = String(text.dropFirst())
        return write(Array(("{\"esd\":1," + rest + "\n").utf8))
    }
}

//= the eslogger child and the pump that forwards whole lines
final class Streamer {
    let events: [String]
    let conn: Conn
    private let process = Process()
    private let pipe = Pipe()
    private var intentional = false
    private let stateLock = NSLock()

    init(events: [String], conn: Conn) { self.events = events; self.conn = conn }

    func start(eslogger: String, onEnd: @escaping () -> Void) throws {
        process.executableURL = URL(fileURLWithPath: eslogger)
        process.arguments = events
        process.standardOutput = pipe
        process.standardError = FileHandle.standardError
        process.terminationHandler = { [self] finished in
            stateLock.lock(); let wanted = intentional; stateLock.unlock()
            logLine("eslogger ended (status \(finished.terminationStatus))")
            if !wanted {
                conn.reply(["ok": false, "error": "eslogger exited with status \(finished.terminationStatus). "
                    + "Does crescendo-esd have Full Disk Access? See /var/log/crescendo-esd.log"])
                shutdown(conn.fd, SHUT_RDWR) //= wakes the connection's read loop so it can clean up
            }
            onEnd()
        }
        try process.run()
        logLine("eslogger started: \(events.joined(separator: " "))")
        let reader = pipe.fileHandleForReading
        Thread.detachNewThread { [self] in
            var pending = [UInt8]()
            while true {
                let chunk = reader.availableData
                if chunk.isEmpty { break }
                pending.append(contentsOf: chunk)
                while let nl = pending.firstIndex(of: 0x0A) {
                    let line = Array(pending[pending.startIndex ... nl])
                    pending.removeSubrange(pending.startIndex ... nl)
                    if !conn.write(line) { stop(); return } //= client went away
                }
                if pending.count > (1 << 22) { pending.removeAll() } //= absurdly long line: drop it
            }
        }
    }

    func stop() {
        stateLock.lock(); intentional = true; stateLock.unlock()
        if process.isRunning { process.terminate() }
    }
}

//= ---- shared state ------------------------------------------------------------------------------------------
let stateLock = NSLock()
var current: Streamer?
var config = Config()

func handle(fd: Int32) {
    let conn = Conn(fd: fd)
    var owned: Streamer?
    defer {
        owned?.stop()
        stateLock.lock(); if current === owned { current = nil }; stateLock.unlock()
        close(fd)
    }
    var peerUid: uid_t = 0, peerGid: gid_t = 0
    guard getpeereid(fd, &peerUid, &peerGid) == 0, peerUid == config.uid || peerUid == 0 else {
        logLine("refused a connection from uid \(peerUid)")
        return
    }
    var buffer = [UInt8]()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = read(fd, &chunk, chunk.count)
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { break }
        buffer.append(contentsOf: chunk[0 ..< n])
        if buffer.count > 8192 { conn.reply(["ok": false, "error": "line too long"]); return }
        while let nl = buffer.firstIndex(of: 0x0A) {
            let line = String(decoding: buffer[buffer.startIndex ..< nl], as: UTF8.self)
            buffer.removeSubrange(buffer.startIndex ... nl)
            let words = line.split(separator: " ").map { String($0) }
            guard let command = words.first else { continue }
            switch command {
            case "status":
                stateLock.lock(); let running = current != nil; let events = current?.events ?? []; stateLock.unlock()
                conn.reply(["state": running ? "running" : "idle", "version": esdVersion, "events": events])
            case "start":
                let names = Array(words.dropFirst())
                guard owned == nil else { conn.reply(["ok": false, "error": "already started on this connection"]); continue }
                guard (1 ... 40).contains(names.count), names.allSatisfy(validEventName) else {
                    conn.reply(["ok": false, "error": "events must be 1-40 names of [a-z_]"]); continue
                }
                let streamer = Streamer(events: names, conn: conn)
                stateLock.lock()
                if current != nil { stateLock.unlock(); conn.reply(["ok": false, "error": "busy: another client is streaming"]); continue }
                current = streamer
                stateLock.unlock()
                do {
                    try streamer.start(eslogger: config.eslogger) {
                        stateLock.lock(); if current === streamer { current = nil }; stateLock.unlock()
                    }
                    owned = streamer
                    conn.reply(["state": "running", "events": names])
                } catch {
                    stateLock.lock(); if current === streamer { current = nil }; stateLock.unlock()
                    conn.reply(["ok": false, "error": "cannot start eslogger: \(error.localizedDescription)"])
                }
            case "stop":
                owned?.stop(); owned = nil
                conn.reply(["state": "idle"])
            default:
                conn.reply(["ok": false, "error": "unknown command"])
            }
        }
    }
}

//= ---- main ------------------------------------------------------------------------------------------------
signal(SIGPIPE, SIG_IGN)
guard let parsed = parseArguments() else { exit(64) }
config = parsed

let server = socket(AF_UNIX, SOCK_STREAM, 0)
guard server >= 0 else { logLine("socket() failed: \(String(cString: strerror(errno)))"); exit(71) }
unlink(config.socket)
var address = sockaddr_un()
address.sun_family = sa_family_t(AF_UNIX)
address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
let pathBytes = Array(config.socket.utf8CString)
withUnsafeMutablePointer(to: &address.sun_path) {
    $0.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { destination in
        for (i, byte) in pathBytes.enumerated() { destination[i] = byte }
    }
}
let previousMask = umask(0o177)
let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(server, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
}
umask(previousMask)
guard bound == 0 else { logLine("bind \(config.socket) failed: \(String(cString: strerror(errno)))"); exit(71) }
guard chown(config.socket, config.uid, gid_t.max) == 0, chmod(config.socket, 0o600) == 0 else {
    logLine("cannot set owner/mode on \(config.socket): \(String(cString: strerror(errno)))"); exit(71)
}
guard listen(server, 8) == 0 else { logLine("listen failed: \(String(cString: strerror(errno)))"); exit(71) }
logLine("listening on \(config.socket) for uid \(config.uid)")

signal(SIGTERM, SIG_IGN)
let terminator = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
terminator.setEventHandler {
    logLine("SIGTERM: shutting down")
    stateLock.lock(); let streamer = current; stateLock.unlock()
    streamer?.stop()
    unlink(config.socket)
    exit(0)
}
terminator.resume()

while true {
    let client = accept(server, nil, nil)
    if client < 0 {
        if errno == EINTR { continue }
        logLine("accept failed: \(String(cString: strerror(errno)))"); exit(71)
    }
    Thread.detachNewThread { handle(fd: client) }
}
