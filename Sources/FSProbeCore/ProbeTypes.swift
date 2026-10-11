//
//  ProbeTypes.swift
//  FSProbeCore — result model, outcome classification, and evidence records.
//
//  Every probe produces a ProbeResult that records the exact errno observed.
//  Nothing in this file fabricates success: an outcome is derived only from
//  the return value of the syscall that was actually executed.
//

import Foundation

/// Coarse outcome of a probe, derived strictly from observed return values.
public enum ProbeOutcome: String, Codable, Sendable {
    /// The operation completed successfully.
    case succeeded
    /// The operation failed because the path does not exist (ENOENT).
    case notFound
    /// The operation failed because a path component is not a directory (ENOTDIR).
    case notDirectory
    /// The operation failed with EPERM — on iOS this is the sandbox (seatbelt) denial signature.
    case deniedEPERM
    /// The operation failed with EACCES — POSIX permission bits (or ACLs), not the sandbox.
    case deniedEACCES
    /// The operation failed with another errno.
    case failedOther
}

/// The classification of *why* access behaved the way it did.
///
/// This is the attribution layer required by the research protocol: a result
/// must be attributed to a cause, never left ambiguous.
public enum AccessCause: String, Codable, Sendable {
    /// Normal documented capability of an ordinary app (e.g. its own container).
    case documentedCapability
    /// Access granted through an explicit user action (document picker, bookmark, etc.).
    case userGranted
    /// Denial produced by the platform sandbox (seatbelt) profile.
    case sandboxEnforcement
    /// Denial produced by POSIX permission bits or ACLs.
    case posixPermissions
    /// The path simply does not exist on this system.
    case pathAbsent
    /// A configuration or implementation issue (e.g. malformed path, unsupported operation).
    case configurationIssue
    /// Behavior that is not yet explained and requires further investigation.
    case unexplained
}

/// Evidence captured alongside a result. Only non-sensitive, synthetic-safe
/// metadata is recorded (counts, sizes, hashes) — never file *contents* of
/// files the researcher did not create.
public struct ProbeEvidence: Codable, Sendable, Equatable {
    /// Number of directory entries observed (enumeration probes).
    public var entryCount: Int?
    /// First few entry names, used only for directories the researcher created.
    public var sampleEntryNames: [String]?
    /// Number of bytes successfully read.
    public var bytesRead: Int?
    /// Number of bytes successfully written.
    public var bytesWritten: Int?
    /// Whether read-back of written content matched what was written.
    public var readBackMatched: Bool?
    /// The resolved symlink target, when readLink succeeded.
    public var linkTarget: String?
    /// File size reported by stat.
    public var statSize: Int64?
    /// File mode reported by stat (octal string, e.g. "100644").
    public var statModeOctal: String?

    public init(
        entryCount: Int? = nil,
        sampleEntryNames: [String]? = nil,
        bytesRead: Int? = nil,
        bytesWritten: Int? = nil,
        readBackMatched: Bool? = nil,
        linkTarget: String? = nil,
        statSize: Int64? = nil,
        statModeOctal: String? = nil
    ) {
        self.entryCount = entryCount
        self.sampleEntryNames = sampleEntryNames
        self.bytesRead = bytesRead
        self.bytesWritten = bytesWritten
        self.readBackMatched = readBackMatched
        self.linkTarget = linkTarget
        self.statSize = statSize
        self.statModeOctal = statModeOctal
    }
}

/// The result of one operation against one path.
public struct ProbeResult: Codable, Sendable, Identifiable {
    /// The exact path the syscall was invoked on. For write probes this is the
    /// synthetic file inside the target directory, not the directory itself.
    public let path: String
    /// The investigation target this result belongs to. For most probes this
    /// equals `path`; for write probes it is the containing directory.
    public let targetPath: String
    /// The operation performed.
    public let operation: FSOperation
    /// Coarse outcome.
    public let outcome: ProbeOutcome
    /// The errno value observed (0 when the operation succeeded).
    public let errnoNumber: Int
    /// Symbolic errno name (e.g. "EPERM", "ENOENT"), or nil on success.
    public let errnoName: String?
    /// Exact strerror() text for the observed errno — never a generic message.
    public let errnoDescription: String?
    /// Structured evidence (counts, sizes) — never unrelated private data.
    public let evidence: ProbeEvidence
    /// Attribution assigned by the analysis layer.
    public var cause: AccessCause
    /// Free-form note for unexpected observations.
    public var note: String?

    public init(
        path: String,
        operation: FSOperation,
        outcome: ProbeOutcome,
        errnoNumber: Int,
        errnoName: String?,
        errnoDescription: String?,
        evidence: ProbeEvidence = ProbeEvidence(),
        cause: AccessCause = .unexplained,
        note: String? = nil,
        targetPath: String? = nil
    ) {
        self.path = path
        self.targetPath = targetPath ?? path
        self.operation = operation
        self.outcome = outcome
        self.errnoNumber = errnoNumber
        self.errnoName = errnoName
        self.errnoDescription = errnoDescription
        self.evidence = evidence
        self.cause = cause
        self.note = note
    }

    public var id: String { "\(targetPath)|\(operation.rawValue)" }

    /// True when the operation succeeded.
    public var succeeded: Bool { outcome == .succeeded }
}
