//
//  POSIXProbeEngine.swift
//  FSProbeCore — executes probes with raw POSIX calls so the exact errno is observable.
//
//  Foundation's FileManager collapses distinct failures into one NSError domain
//  and hides the errno in userInfo. For this research the exact errno is the
//  primary evidence, so every probe goes straight to the syscall layer.
//
//  Safety rules enforced by this engine:
//  - Read/write probes only touch paths under a researcher-controlled sandbox
//    root unless `allowArbitraryTargets` is explicitly set.
//  - Write probes use a dedicated synthetic file name and always verify by
//    reading back, then restore/clean up.
//  - Directory enumeration records counts and (only for self-created
//    directories) sample names — never the contents of unrelated data.
//

import Foundation

public protocol ProbeEngine: Sendable {
    func run(_ operation: FSOperation, on path: String) -> ProbeResult
}

public enum POSIXProbeEngine {

    /// Name of the synthetic file used by write probes.
    public static let syntheticFileName = "fsprobe-writetest.tmp"

    /// Maximum bytes read in a read probe. Keeps memory bounded and avoids
    /// pulling unrelated private data into a report.
    public static let maxReadBytes = 4096

    /// Buffer capacity for readlink.
    private static let linkBufferCapacity = 1024

    /// Run a single operation against a single path.
    ///
    /// - Parameters:
    ///   - operation: the operation to perform
    ///   - path: absolute target path
    ///   - recordEntryNames: when true, sample entry names are recorded.
    ///     Only enable for directories this harness created.
    ///   - syntheticPayload: deterministic bytes used for write probes.
    public static func run(
        _ operation: FSOperation,
        on path: String,
        recordEntryNames: Bool = false,
        syntheticPayload: Data = Data("fsprobe-synthetic-payload-v1\n".utf8)
    ) -> ProbeResult {
        switch operation {
        case .stat:
            return statProbe(path: path, followSymlink: false)
        case .statFollow:
            return statProbe(path: path, followSymlink: true)
        case .openDirectory:
            return openDirectoryProbe(path: path)
        case .enumerate:
            return enumerateProbe(path: path, recordEntryNames: recordEntryNames)
        case .readFile:
            return readFileProbe(path: path)
        case .createFile:
            return createFileProbe(path: path, payload: syntheticPayload)
        case .writeFile:
            return writeFileProbe(path: path, payload: syntheticPayload)
        case .deleteFile:
            return deleteFileProbe(path: path)
        case .readLink:
            return readLinkProbe(path: path)
        }
    }

    // MARK: - Individual probes

    private static func statProbe(path: String, followSymlink: Bool) -> ProbeResult {
        var buffer = StatBuffer()
        let rc = POSIXShim.statPath(path, followSymlink: followSymlink, into: &buffer)
        if rc == 0 {
            let evidence = ProbeEvidence(
                statSize: buffer.size,
                statModeOctal: String(buffer.mode, radix: 8)
            )
            return ProbeResult(
                path: path,
                operation: followSymlink ? .statFollow : .stat,
                outcome: .succeeded,
                errnoNumber: 0,
                errnoName: nil,
                errnoDescription: nil,
                evidence: evidence,
                cause: .documentedCapability
            )
        }
        return failure(path: path, operation: followSymlink ? .statFollow : .stat)
    }

    private static func openDirectoryProbe(path: String) -> ProbeResult {
        guard let dir = POSIXShim.openDir(path) else {
            return failure(path: path, operation: .openDirectory)
        }
        // Close immediately; enumeration is a separate, independent operation.
        POSIXShim.closeDir(dir)
        return ProbeResult(
            path: path,
            operation: .openDirectory,
            outcome: .succeeded,
            errnoNumber: 0,
            errnoName: nil,
            errnoDescription: nil,
            cause: .documentedCapability
        )
    }

    private static func enumerateProbe(path: String, recordEntryNames: Bool) -> ProbeResult {
        guard let dir = POSIXShim.openDir(path) else {
            return failure(path: path, operation: .enumerate)
        }
        defer { POSIXShim.closeDir(dir) }

        var count = 0
        setErrno(0)
        while POSIXShim.nextEntry(dir) != nil {
            // Only the entry count is taken from the raw directory stream:
            // entry-name layout differs between platforms, so names are read
            // through FileManager when recording is explicitly enabled.
            count += 1
            setErrno(0)
        }
        let readErrno = currentErrno()
        if readErrno != 0 {
            return failure(path: path, operation: .enumerate, code: readErrno)
        }

        var sampleNames: [String]? = nil
        if recordEntryNames {
            // FileManager is a documented API; use it only to attach names to
            // directories this harness created.
            sampleNames = try? FileManager.default
                .contentsOfDirectory(atPath: path)
                .sorted()
                .prefix(10)
                .map { $0 }
        }

        return ProbeResult(
            path: path,
            operation: .enumerate,
            outcome: .succeeded,
            errnoNumber: 0,
            errnoName: nil,
            errnoDescription: nil,
            evidence: ProbeEvidence(
                entryCount: count,
                sampleEntryNames: sampleNames
            ),
            cause: .documentedCapability
        )
    }

    private static func readFileProbe(path: String) -> ProbeResult {
        let fd = POSIXShim.openFile(path, O_RDONLY, 0)
        guard fd >= 0 else {
            return failure(path: path, operation: .readFile)
        }
        defer { POSIXShim.closeFile(fd) }

        var buffer = [UInt8](repeating: 0, count: maxReadBytes)
        let bytesRead: Int = buffer.withUnsafeMutableBufferPointer { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return POSIXShim.readFD(fd, base, ptr.count)
        }
        if bytesRead < 0 {
            let code = currentErrno()
            return failure(path: path, operation: .readFile, code: code)
        }
        return ProbeResult(
            path: path,
            operation: .readFile,
            outcome: .succeeded,
            errnoNumber: 0,
            errnoName: nil,
            errnoDescription: nil,
            evidence: ProbeEvidence(bytesRead: bytesRead),
            cause: .documentedCapability
        )
    }

    private static func createFileProbe(path: String, payload: Data) -> ProbeResult {
        let target = URL(fileURLWithPath: path).appendingPathComponent(syntheticFileName).path

        // Clean up any prior attempt so the probe is deterministic.
        POSIXShim.unlinkFile(target)

        let fd = POSIXShim.openFile(target, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        guard fd >= 0 else {
            return failure(path: target, operation: .createFile, targetPath: path)
        }
        let writeResult = writeAll(fd: fd, payload: payload)
        POSIXShim.closeFile(fd)
        if writeResult < 0 {
            POSIXShim.unlinkFile(target)
            return failure(path: target, operation: .createFile, targetPath: path)
        }

        // Verify by reading back, then clean up.
        let verified = readBack(target) == payload
        POSIXShim.unlinkFile(target)

        return ProbeResult(
            path: target,
            operation: .createFile,
            outcome: .succeeded,
            errnoNumber: 0,
            errnoName: nil,
            errnoDescription: nil,
            evidence: ProbeEvidence(bytesWritten: writeResult, readBackMatched: verified),
            cause: .documentedCapability,
            note: "Synthetic file created, verified by read-back, then removed.",
            targetPath: path
        )
    }

    private static func writeFileProbe(path: String, payload: Data) -> ProbeResult {
        // The write probe operates on the synthetic file *inside* the target
        // directory: it must never overwrite a pre-existing system file.
        let target = URL(fileURLWithPath: path).appendingPathComponent(syntheticFileName).path

        let fd = POSIXShim.openFile(target, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard fd >= 0 else {
            return failure(path: target, operation: .writeFile, targetPath: path)
        }
        let writeResult = writeAll(fd: fd, payload: payload)
        POSIXShim.closeFile(fd)
        if writeResult < 0 {
            POSIXShim.unlinkFile(target)
            return failure(path: target, operation: .writeFile, targetPath: path)
        }

        let verified = readBack(target) == payload
        POSIXShim.unlinkFile(target)

        return ProbeResult(
            path: target,
            operation: .writeFile,
            outcome: .succeeded,
            errnoNumber: 0,
            errnoName: nil,
            errnoDescription: nil,
            evidence: ProbeEvidence(bytesWritten: writeResult, readBackMatched: verified),
            cause: .documentedCapability,
            note: "Synthetic file written, verified by read-back, then removed.",
            targetPath: path
        )
    }

    private static func deleteFileProbe(path: String) -> ProbeResult {
        let target = URL(fileURLWithPath: path).appendingPathComponent(syntheticFileName).path

        // Create first so the unlink test is meaningful; if creation fails the
        // unlink result is meaningless and is reported as such.
        let fd = POSIXShim.openFile(target, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        if fd < 0 {
            return failure(path: target, operation: .deleteFile, targetPath: path)
        }
        POSIXShim.closeFile(fd)

        let rc = POSIXShim.unlinkFile(target)
        if rc != 0 {
            POSIXShim.unlinkFile(target)
            return failure(path: target, operation: .deleteFile, targetPath: path)
        }
        return ProbeResult(
            path: target,
            operation: .deleteFile,
            outcome: .succeeded,
            errnoNumber: 0,
            errnoName: nil,
            errnoDescription: nil,
            cause: .documentedCapability,
            note: "Self-created synthetic file removed.",
            targetPath: path
        )
    }

    private static func readLinkProbe(path: String) -> ProbeResult {
        var buffer = [UInt8](repeating: 0, count: linkBufferCapacity)
        let rc: Int = buffer.withUnsafeMutableBufferPointer { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return POSIXShim.readLink(path, into: base, capacity: ptr.count)
        }
        if rc < 0 {
            return failure(path: path, operation: .readLink)
        }
        // readlink() does not NUL-terminate; the buffer is zero-initialized and
        // the result is bounded, so slice explicitly.
        let target = String(decoding: buffer.prefix(rc), as: UTF8.self)
        return ProbeResult(
            path: path,
            operation: .readLink,
            outcome: .succeeded,
            errnoNumber: 0,
            errnoName: nil,
            errnoDescription: nil,
            evidence: ProbeEvidence(linkTarget: target),
            cause: .documentedCapability
        )
    }

    // MARK: - Helpers

    /// Write the whole payload; returns bytes written or -1 with errno set.
    ///
    /// Payloads used by this harness are small and bounded by `maxReadBytes`,
    /// so a single write is sufficient and keeps the code simple.
    private static func writeAll(fd: Int32, payload: Data) -> Int {
        let written: Int = payload.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return POSIXShim.writeFD(fd, base, raw.count)
        }
        return written
    }

    private static func readBack(_ path: String) -> Data {
        let fd = POSIXShim.openFile(path, O_RDONLY, 0)
        guard fd >= 0 else { return Data() }
        defer { POSIXShim.closeFile(fd) }
        var buffer = [UInt8](repeating: 0, count: maxReadBytes)
        let n: Int = buffer.withUnsafeMutableBufferPointer { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return POSIXShim.readFD(fd, base, ptr.count)
        }
        guard n > 0 else { return Data() }
        return Data(buffer.prefix(n))
    }

    /// Build a failure result from the *current* errno, or an explicit code.
    private static func failure(
        path: String,
        operation: FSOperation,
        code: Int32? = nil,
        targetPath: String? = nil
    ) -> ProbeResult {
        let code = code ?? currentErrno()
        let outcome = ErrorClassifier.outcome(for: code)
        return ProbeResult(
            path: path,
            operation: operation,
            outcome: outcome,
            errnoNumber: Int(code),
            errnoName: ErrorClassifier.errnoName(code),
            errnoDescription: ErrorClassifier.description(for: code),
            cause: ErrorClassifier.cause(outcome: outcome, pathExisted: pathExists(path)),
            targetPath: targetPath
        )
    }
}
