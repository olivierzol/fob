import CryptoKit
import Foundation
import LocalAuthentication

/// ssh-agent protocol (draft-miller-ssh-agent) — the two messages that matter.
private enum AgentMessage: UInt8 {
    case failure = 5            // SSH_AGENT_FAILURE
    case success = 6            // SSH_AGENT_SUCCESS
    case requestIdentities = 11 // SSH_AGENTC_REQUEST_IDENTITIES
    case identitiesAnswer = 12  // SSH_AGENT_IDENTITIES_ANSWER
    case signRequest = 13       // SSH_AGENTC_SIGN_REQUEST
    case signResponse = 14      // SSH_AGENT_SIGN_RESPONSE
    case extensionRequest = 27  // SSH_AGENTC_EXTENSION
}

final class Agent {
    private let store: KeyStore
    private let audit: AuditLog
    private static let maxMessageSize: UInt32 = 1 << 20

    /// Touch-reuse window: after a successful touch, the authorized LAContext is
    /// kept (per key) and reused until its deadline. This is the only way to skip
    /// re-prompting — touchIDAuthenticationAllowableReuseDuration measures from
    /// device unlock, not from the previous approval, so it does not help here.
    private var authorizations: [String: (context: LAContext, deadline: Date)] = [:]
    private let authorizationsLock = NSLock()

    init(store: KeyStore) {
        self.store = store
        self.audit = AuditLog(directory: store.directory)
    }

    private func cachedAuthorization(for keyName: String) -> LAContext? {
        authorizationsLock.lock()
        defer { authorizationsLock.unlock() }
        guard let entry = authorizations[keyName] else { return nil }
        guard entry.deadline > Date() else {
            entry.context.invalidate()
            authorizations[keyName] = nil
            return nil
        }
        return entry.context
    }

    private func storeAuthorization(_ context: LAContext, for keyName: String, seconds: Double) {
        authorizationsLock.lock()
        defer { authorizationsLock.unlock() }
        authorizations[keyName] = (context, Date().addingTimeInterval(seconds))
    }

    private func dropAuthorization(for keyName: String) {
        authorizationsLock.lock()
        defer { authorizationsLock.unlock() }
        authorizations[keyName]?.context.invalidate()
        authorizations[keyName] = nil
    }

    func run() throws -> Never {
        signal(SIGPIPE, SIG_IGN)
        let socketPath = store.socketPath
        unlink(socketPath)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AgentError.socket(errno) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxPath = MemoryLayout.size(ofValue: addr.sun_path) - 1
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count <= maxPath else { throw AgentError.socketPathTooLong(socketPath) }
        withUnsafeMutableBytes(of: &addr.sun_path) { dst in
            dst.copyBytes(from: pathBytes)
        }

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else { throw AgentError.bind(errno) }
        chmod(socketPath, 0o600)
        guard listen(fd, 16) == 0 else { throw AgentError.listen(errno) }

        log("listening on \(socketPath)")
        while true {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { continue }
            Thread.detachNewThread { [weak self] in
                self?.serve(client: client)
                close(client)
            }
        }
    }

    private func serve(client: Int32) {
        let peer = Peer.describe(fd: client)
        var bindings: [SessionBinding] = [] // session-bind state, per connection
        while true {
            guard let header = readExactly(fd: client, count: 4) else { return }
            let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length > 0, length <= Self.maxMessageSize,
                  let payload = readExactly(fd: client, count: Int(length)) else { return }

            let response = handle(payload: Data(payload), peer: peer, bindings: &bindings)
            var framed = SSHWriter()
            framed.writeString(response)
            guard writeAll(fd: client, data: framed.data) else { return }
        }
    }

    private func handle(payload: Data, peer: String, bindings: inout [SessionBinding]) -> Data {
        var reader = SSHReader(payload)
        do {
            let type = try reader.readByte()
            switch AgentMessage(rawValue: type) {
            case .requestIdentities:
                return try listIdentities()
            case .signRequest:
                return try sign(reader: &reader, peer: peer, bindings: bindings)
            case .extensionRequest:
                return try handleExtension(reader: &reader, peer: peer, bindings: &bindings)
            default:
                log("unsupported message type \(type)")
                return Data([AgentMessage.failure.rawValue])
            }
        } catch {
            log("request failed: \(error.localizedDescription)")
            return Data([AgentMessage.failure.rawValue])
        }
    }

    private func handleExtension(reader: inout SSHReader, peer: String, bindings: inout [SessionBinding]) throws -> Data {
        let name = String(decoding: try reader.readString(), as: UTF8.self)
        guard name == "session-bind@openssh.com" else {
            log("unsupported extension '\(name)' from \(peer)")
            return Data([AgentMessage.failure.rawValue])
        }
        guard let binding = SessionBinding.parse(&reader),
              SessionBinding.add(binding, to: &bindings) else {
            log("rejected session-bind from \(peer) (bad signature or already bound)")
            audit.record("bind-rejected", peer: peer)
            return Data([AgentMessage.failure.rawValue])
        }
        log("connection from \(peer) bound to \(binding.destination)")
        audit.record("bind", destination: binding.destination, peer: peer)
        return Data([AgentMessage.success.rawValue])
    }

    private func listIdentities() throws -> Data {
        let keys = try store.all()
        var writer = SSHWriter()
        writer.writeByte(AgentMessage.identitiesAnswer.rawValue)
        writer.writeUInt32(UInt32(keys.count))
        for key in keys {
            writer.writeString(SSHFormat.publicKeyBlob(try key.publicKey()))
            writer.writeString("fob:\(key.name)")
        }
        return writer.data
    }

    private func sign(reader: inout SSHReader, peer: String, bindings: [SessionBinding]) throws -> Data {
        let requestedBlob = try reader.readString()
        let dataToSign = try reader.readString()
        _ = try? reader.readUInt32() // flags — only meaningful for RSA

        let destination = SessionBinding.describe(bindings)
        guard let key = try store.all().first(where: { candidate in
            guard let publicKey = try? candidate.publicKey() else { return false }
            return SSHFormat.publicKeyBlob(publicKey) == requestedBlob
        }) else {
            log("sign request from \(peer) for \(destination) with unknown key")
            Notifier.post("⚠️ \(peer) requested a signature for \(destination) with a key this agent does not have")
            audit.record("unknown-key", destination: destination, peer: peer)
            return Data([AgentMessage.failure.rawValue])
        }

        // Pinning: a pinned key signs only for its verified, bound host — refused
        // before any Touch ID prompt, so a blocked request never costs a touch.
        let policy = store.policy(name: key.name)
        if !policy.pinnedHostKeys.isEmpty {
            guard let bound = bindings.last, bound.verified,
                  policy.pinnedHostKeys.contains(bound.hostKeyBlob) else {
                log("REFUSED key '\(key.name)' for \(destination) (\(peer)) — key is pinned to its host")
                Notifier.post("⛔️ Blocked: \(peer) tried to use pinned key '\(key.name)' for \(destination)")
                audit.record("refused-pin", key: key.name, destination: destination, peer: peer)
                return Data([AgentMessage.failure.rawValue])
            }
        }

        let reuseWindow = min(policy.reuseSeconds ?? 0, 300)

        // Within the reuse window: sign with the previously authorized context, no prompt.
        if reuseWindow > 0, let cached = cachedAuthorization(for: key.name) {
            if let signature = try? key.privateKey(context: cached).signature(for: dataToSign) {
                log("signed with key '\(key.name)' for \(destination) (\(peer)) — reuse window")
                Notifier.post("🔑 \(peer) signed in to \(destination) with key '\(key.name)' (reuse window)")
                audit.record("signed-reused", key: key.name, destination: destination, peer: peer)
                return signResponse(signature)
            }
            dropAuthorization(for: key.name) // grant no longer valid — fall through to a fresh prompt
        }

        let context = LAContext()
        context.localizedReason = "connect to \(destination) — requested by \(peer) with key \"\(key.name)\""
        log("sign request from \(peer) for \(destination) with key '\(key.name)' — waiting for user approval")
        do {
            let signature = try key.privateKey(context: context).signature(for: dataToSign)
            log("signed with key '\(key.name)' for \(destination) (\(peer))")
            Notifier.post("🔑 \(peer) signed in to \(destination) with key '\(key.name)'")
            audit.record("signed", key: key.name, destination: destination, peer: peer)
            if reuseWindow > 0 {
                storeAuthorization(context, for: key.name, seconds: reuseWindow)
            }
            return signResponse(signature)
        } catch {
            log("signature for \(destination) with key '\(key.name)' (\(peer)) failed: \(error.localizedDescription)")
            Notifier.post("🚫 Signature request from \(peer) for \(destination) with key '\(key.name)' was denied")
            audit.record("denied", key: key.name, destination: destination, peer: peer)
            return Data([AgentMessage.failure.rawValue])
        }
    }

    private func signResponse(_ signature: P256.Signing.ECDSASignature) -> Data {
        var writer = SSHWriter()
        writer.writeByte(AgentMessage.signResponse.rawValue)
        writer.writeString(SSHFormat.signatureBlob(signature))
        return writer.data
    }

    private func readExactly(fd: Int32, count: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let n = buffer.withUnsafeMutableBytes { ptr in
                read(fd, ptr.baseAddress!.advanced(by: offset), count - offset)
            }
            guard n > 0 else { return nil }
            offset += n
        }
        return buffer
    }

    private func writeAll(fd: Int32, data: Data) -> Bool {
        let remaining = [UInt8](data)
        var offset = 0
        while offset < remaining.count {
            let n = remaining.withUnsafeBytes { ptr in
                write(fd, ptr.baseAddress!.advanced(by: offset), remaining.count - offset)
            }
            guard n > 0 else { return false }
            offset += n
        }
        return true
    }

    private func log(_ message: String) {
        FileHandle.standardError.write(Data("[fob] \(message)\n".utf8))
    }
}

enum AgentError: LocalizedError {
    case socket(Int32)
    case bind(Int32)
    case listen(Int32)
    case socketPathTooLong(String)

    var errorDescription: String? {
        switch self {
        case .socket(let code): return "socket() failed: \(String(cString: strerror(code)))"
        case .bind(let code): return "bind() failed: \(String(cString: strerror(code)))"
        case .listen(let code): return "listen() failed: \(String(cString: strerror(code)))"
        case .socketPathTooLong(let path): return "socket path too long: \(path)"
        }
    }
}
