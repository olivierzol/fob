import Foundation

/// Exclusive single-instance lock for the agent.
///
/// Only one process may own the agent socket at a time. Every path that starts
/// the agent acquires this advisory `flock(2)` on `~/.fob/agent.lock` first, so a
/// second agent — a stray binary, a double-launched app — fails fast instead of
/// racing to `bind()` the socket. The lock fd stays open for the life of the
/// process and the kernel releases it automatically on exit (even on crash).
public final class AgentLock {
    private let path: String
    private var fd: Int32 = -1

    public init(directory: URL) {
        self.path = directory.appendingPathComponent("agent.lock").path
    }

    /// Take the lock, or throw `AgentError.alreadyRunning` if another agent holds it.
    public func acquire() throws {
        let handle = open(path, O_CREAT | O_RDWR, 0o600)
        guard handle >= 0 else { throw AgentError.lock(errno) }
        if flock(handle, LOCK_EX | LOCK_NB) != 0 {
            let code = errno
            close(handle)
            throw code == EWOULDBLOCK ? AgentError.alreadyRunning : AgentError.lock(code)
        }
        fd = handle
    }
}
