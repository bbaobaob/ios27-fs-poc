//
//  AncestorProbe.swift
//  FSProbeCore — directory-tree ascent experiment.
//
//  Starting from a directory the process legitimately owns (its own container),
//  walk upwards one level at a time and probe each ancestor with read-only
//  operations. The result is a map of where the sandbox boundary actually sits
//  relative to a known-good starting point.
//
//  This experiment exists to answer a specific question from the research plan:
//  "Why can an ordinary app read or write some files but fail to enumerate their
//  parent directories?" Answering it requires probing the parents themselves,
//  which the fixed target list does not do because the ancestors are only known
//  at runtime.
//
//  SAFETY: this probe is read-only by construction. It performs lstat, opendir,
//  and readdir only. It never creates, writes, or deletes anything in an
//  ancestor directory, because ancestors of the app container are not
//  authorized locations for this process. The write primitive is exercised only
//  against the synthetic file inside the app's own container.
//

import Foundation

/// One step of the ascent: an ancestor directory and what could be done to it.
public struct AncestorStep: Sendable, Identifiable, Codable {
    /// The ancestor path probed.
    public let path: String
    /// 0 is the starting directory, 1 its parent, and so on.
    public let depth: Int
    /// Outcome of `lstat()` on this ancestor.
    public let lstat: ProbeOutcome
    /// Outcome of `opendir()` on this ancestor.
    public let openDirectory: ProbeOutcome
    /// Outcome of `readdir()` on this ancestor.
    public let enumerate: ProbeOutcome
    /// Symbolic errno for the first denied operation, if any.
    public let errnoName: String?
    /// Number of entries, when enumeration succeeded.
    public let entryCount: Int?
    /// Set when the ascent stopped here and why.
    public let stopReason: String?

    public init(
        path: String,
        depth: Int,
        lstat: ProbeOutcome,
        openDirectory: ProbeOutcome,
        enumerate: ProbeOutcome,
        errnoName: String?,
        entryCount: Int?,
        stopReason: String? = nil
    ) {
        self.path = path
        self.depth = depth
        self.lstat = lstat
        self.openDirectory = openDirectory
        self.enumerate = enumerate
        self.errnoName = errnoName
        self.entryCount = entryCount
        self.stopReason = stopReason
    }

    public var id: String { "\(depth):\(path)" }

    /// True when every read-only operation on this ancestor succeeded.
    public var fullyVisible: Bool {
        lstat == .succeeded && openDirectory == .succeeded && enumerate == .succeeded
    }

    /// True when the ancestor exists but was refused.
    public var existsButDenied: Bool {
        lstat == .succeeded && (openDirectory != .succeeded || enumerate != .succeeded)
    }
}

public enum AncestorProbe {

    /// Walk up from `start`, probing each ancestor with read-only operations.
    ///
    /// - Parameters:
    ///   - start: the directory to begin from; typically the app container.
    ///   - maxDepth: maximum number of levels to climb, including `start`.
    ///   - stopAfterConsecutiveFailures: stop once this many consecutive
    ///     ancestors were not fully visible. The boundary is established by then
    ///     and further levels only add noise.
    /// - Returns: One step per probed ancestor, nearest first.
    public static func ascend(
        from start: String,
        maxDepth: Int = 8,
        stopAfterConsecutiveFailures: Int = 3
    ) -> [AncestorStep] {
        var steps: [AncestorStep] = []
        var current = normalize(start)
        var consecutiveFailures = 0

        for depth in 0..<max(1, maxDepth) {
            let step = probe(path: current, depth: depth)

            // Explain why the ascent stopped here, when it does.
            var stopReason: String? = nil
            if !step.fullyVisible {
                consecutiveFailures += 1
                if consecutiveFailures >= stopAfterConsecutiveFailures {
                    stopReason = """
                    Boundary established: \(consecutiveFailures) consecutive ancestors \
                    were not fully visible. Deeper levels are not probed.
                    """
                }
            } else {
                consecutiveFailures = 0
            }

            let annotated = AncestorStep(
                path: step.path,
                depth: step.depth,
                lstat: step.lstat,
                openDirectory: step.openDirectory,
                enumerate: step.enumerate,
                errnoName: step.errnoName,
                entryCount: step.entryCount,
                stopReason: stopReason
            )
            steps.append(annotated)

            if stopReason != nil { break }

            let parent = parentPath(of: current)
            if parent == current {
                // Reached the filesystem root.
                break
            }
            current = parent
        }

        return steps
    }

    /// The nearest ancestor that could not be fully seen, if any.
    public static func boundary(in steps: [AncestorStep]) -> AncestorStep? {
        steps.first { !$0.fullyVisible }
    }

    // MARK: - Internals

    /// Probe one directory with read-only operations only.
    private static func probe(path: String, depth: Int) -> AncestorStep {
        let lstatResult = POSIXProbeEngine.run(.stat, on: path)
        let openResult = POSIXProbeEngine.run(.openDirectory, on: path)
        let enumerateResult = POSIXProbeEngine.run(.enumerate, on: path)

        // Report the errno of the first operation that was refused, because that
        // is the evidence: EPERM is the sandbox, EACCES is permission bits.
        var errnoName: String?
        for result in [lstatResult, openResult, enumerateResult] {
            if !result.succeeded {
                errnoName = result.errnoName
                break
            }
        }

        return AncestorStep(
            path: path,
            depth: depth,
            lstat: lstatResult.outcome,
            openDirectory: openResult.outcome,
            enumerate: enumerateResult.outcome,
            errnoName: errnoName,
            entryCount: enumerateResult.evidence.entryCount
        )
    }

    /// Collapse duplicate slashes and drop a trailing one, so successive parents
    /// are distinct and the walk terminates.
    private static func normalize(_ path: String) -> String {
        var result = path
        while result.hasSuffix("/") && result.count > 1 {
            result.removeLast()
        }
        return result
    }

    /// Parent of a path, computed by hand.
    ///
    /// `URL.deletingLastPathComponent()` is not usable here: for the filesystem
    /// root it yields "/.." on some platforms, which makes the walk climb into
    /// "/../.." forever instead of terminating. Splitting the path explicitly
    /// terminates at the root on every platform.
    private static func parentPath(of path: String) -> String {
        let normalized = normalize(path)
        if normalized == "/" { return "/" }
        let components = normalized.split(separator: "/", omittingEmptySubsequences: true)
        guard components.count > 1 else { return "/" }
        return "/" + components.dropLast().joined(separator: "/")
    }
}
