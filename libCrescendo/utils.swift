import Darwin
import EndpointSecurityPrivate
import Foundation

// https://stackoverflow.com/questions/24376829/converting-a-c-string-inside-a-struct-to-a-swift-string/40433950
extension String {
    //= Converts a fixed-size C char array (imported as a tuple) to a String.
    //= Stops at the first NUL byte (the rest of the array is padding/garbage) and
    //= repairs invalid UTF-8 instead of force-unwrapping, so odd bytes can't crash the extension.
    init<T>(tupleOfCChars: T, length: Int = Int.max) {
        self = withUnsafePointer(to: tupleOfCChars) {
            let lengthOfTuple = MemoryLayout<T>.size / MemoryLayout<CChar>.size
            return $0.withMemoryRebound(to: UInt8.self, capacity: lengthOfTuple) {
                let bytes = UnsafeBufferPointer(start: $0, count: Swift.min(length, lengthOfTuple))
                let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
                return String(decoding: bytes[..<end], as: UTF8.self)
            }
        }
    }
}

// swiftlint:disable:next identifier_name
public func getUsername(id: uid_t) -> String {
    guard let passwd = getpwuid(id)?.pointee.pw_name else { return "" }
    return String(cString: passwd)
}

// Given a es_process_t this func will populate a prop dict for a process.
//= `exec` must be passed ONLY for ES_EVENT_TYPE_AUTH_EXEC/NOTIFY_EXEC messages. The event
//= payload is a union: for fork/exit messages the exec member holds unrelated memory, and
//= es_exec_arg_count/es_exec_arg would read garbage (COR-01). Pass nil for every other event.
func getProcessProps(proc: es_process_t, exec: es_event_exec_t? = nil) -> [String: String] {
    var props: Dictionary = [String: String]()

    props["teamid"] = getString(tok: proc.team_id)
    props["signingid"] = getString(tok: proc.signing_id)
    props["isplatformbin"] = String(proc.is_platform_binary)
    props["size"] = String(proc.executable.pointee.stat.st_size)
    props["ppid"] = String(proc.ppid)

    if var ref = exec {
        let argc = es_exec_arg_count(&ref)
        props["argc"] = String(argc)

        var argv = ""

        // swiftlint:disable:next identifier_name
        for i in 0 ..< argc {
            argv += getString(tok: es_exec_arg(&ref, i)) + " "
        }

        props["argv"] = argv
    }

    return props
}

//= Joins a directory path and a file name without doubling or dropping the separator.
//= (No filesystem access: ES gives us both parts as strings.)
func joinPath(dir: String, name: String) -> String {
    if name.isEmpty { return dir }
    if dir.isEmpty { return name }
    return dir.hasSuffix("/") ? dir + name : dir + "/" + name
}

// Converts a es_string_token_t to swift string
func getString(tok: es_string_token_t) -> String {
    if tok.length > 0 {
        return String(cString: tok.data)
    }

    return ""
}
