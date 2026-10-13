//
//  ContainerWriteProbe.swift
//  FSProbeCore — map the write boundary *inside* the app's own container.
//
//  HYPOTHESIS
//  ----------
//  The published iOS container profile allows writes only under
//  `tmp`, `Library`, and `Documents`, with the container root itself denied. The
//  device run confirmed the root is refused with EPERM and that Documents,
//  Library, and tmp are writable.
//
//  What has never been measured is the *rest* of the container. The device run
//  enumerated seven entries in the container root, one of which -- `SystemData`
//  -- has never been probed at all. It is system-managed by name, and it sits
//  inside the app's own writable tree.
//
//  If any system-managed path inside the container accepts writes from the app,
//  that is a boundary worth investigating: data a privileged daemon reads or
//  writes would be reachable from inside the sandbox. If every path is confined
//  as documented, the hypothesis is closed with evidence.
//
//  EXPECTED RESULT
//  ---------------
//  Documents, Library, tmp writable; SystemData and the container root refused.
//  A denial is the correct, informative outcome.
//
//  SAFETY
//  ------
//  Every write uses the dedicated synthetic filename inside the target
//  directory, verifies by read-back, and removes the file. Nothing pre-existing
//  is created, modified, or deleted.
//

import Foundation

public enum ContainerWriteProbe {

    public struct Entry: Sendable, Identifiable, Codable {
        /// Path probed.
        public let path: String
        /// Depth below the container root.
        public let depth: Int
        /// Whether the path exists.
        public let exists: Bool
        /// st_mode in octal, when stat succeeded.
        public let modeOctal: String?
        /// Whether it is a directory.
        public let isDirectory: Bool
        /// Whether it could be opened for enumeration.
        public let enumerable: Bool
        /// Number of entries, when enumerable.
        public let entryCount: Int?
        /// Whether a synthetic file could be created inside it.
        ///
        /// True only when the write was verified by a matching read-back: an
        /// unverified write is not a writable directory, and claiming otherwise
        /// would report a capability the harness never observed.
        public let writable: Bool
        /// errno from the create attempt, when refused.
        public let createErrnoName: String?
        /// errno from the write() call, when the create succeeded and the write
        /// did not. Kept apart from `createErrnoName` because it came from a
        /// different syscall.
        public let writeErrnoName: String?
        /// errno from the read-back open, when the create succeeded.
        public let readBackErrnoName: String?
        /// Whether written content read back identically.
        public let readBackMatched: Bool?
        /// Whether the synthetic file could be removed again.
        public let removable: Bool
        /// Names of the entries found one level down, for directories only.
        public let childNames: [String]

        public init(
            path: String,
            depth: Int,
            exists: Bool,
            modeOctal: String?,
            isDirectory: Bool,
            enumerable: Bool,
            entryCount: Int?,
            writable: Bool,
            createErrnoName: String?,
            writeErrnoName: String?,
            readBackErrnoName: String?,
            readBackMatched: Bool?,
            removable: Bool,
            childNames: [String]
        ) {
            self.path = path
            self.depth = depth
            self.exists = exists
            self.modeOctal = modeOctal
            self.isDirectory = isDirectory
            self.enumerable = enumerable
            self.entryCount = entryCount
            self.writable = writable
            self.createErrnoName = createErrnoName
            self.writeErrnoName = writeErrnoName
            self.readBackErrnoName = readBackErrnoName
            self.readBackMatched = readBackMatched
            self.removable = removable
            self.childNames = childNames
        }

        public var id: String { "\(depth):\(path)" }

        /// True when the directory is enumerable but refused the create, which is
        /// the shape the container root has.
        ///
        /// A directory that accepted a write the harness could not verify is
        /// *not* counted here: that is neither "read-only" nor a confirmed write.
        public var readableButNotWritable: Bool {
            enumerable && !writable && createErrnoName != nil
        }
    }

    public struct Result: Sendable, Codable {
        public let containerPath: String
        public let entries: [Entry]
        /// Directories that accepted a write.
        public let writablePaths: [String]
        /// Directories that are enumerable but refused a write.
        public let readableButNotWritablePaths: [String]
        /// Paths that could not be created in but also could not be enumerated,
        /// which is inconclusive rather than a denial.
        public let inconclusivePaths: [String]

        public init(
            containerPath: String,
            entries: [Entry],
            writablePaths: [String],
            readableButNotWritablePaths: [String],
            inconclusivePaths: [String]
        ) {
            self.containerPath = containerPath
            self.entries = entries
            self.writablePaths = writablePaths
            self.readableButNotWritablePaths = readableButNotWritablePaths
            self.inconclusivePaths = inconclusivePaths
        }
    }

    /// Probe the write boundary across the container.
    ///
    /// Enumerates the container root (which the device confirmed is possible),
    /// then probes every directory found there plus the second level under
    /// `Library`, because that is where the documented write allowance lives and
    /// where a system-managed path would hide.
    public static func probe(
        containerPath: String,
        maxDepth: Int = 2,
        payload: Data = Data("fsprobe-container-writeprobe\n".utf8)
    ) -> Result {
        var entries: [Entry] = []

        // Depth 0: the container root itself.
        entries.append(probeDirectory(containerPath, depth: 0, payload: payload))

        // Depth 1: every entry the root reveals.
        let children = childDirectories(of: containerPath)
        for child in children {
            entries.append(probeDirectory(child, depth: 1, payload: payload))
        }

        // Depth 2: one level below Library, where Preferences, Caches, and
        // Application Support live.
        if maxDepth >= 2 {
            let library = containerPath + "/Library"
            if children.contains(library) || childDirectories(of: library).isEmpty == false {
                for child in childDirectories(of: library) {
                    entries.append(probeDirectory(child, depth: 2, payload: payload))
                }
            }
        }

        var writable: [String] = []
        var readableNotWritable: [String] = []
        var inconclusive: [String] = []
        for entry in entries {
            if entry.writable {
                writable.append(entry.path)
            } else if entry.readableButNotWritable {
                readableNotWritable.append(entry.path)
            } else if !entry.enumerable {
                inconclusive.append(entry.path)
            }
        }

        return Result(
            containerPath: containerPath,
            entries: entries,
            writablePaths: writable,
            readableButNotWritablePaths: readableNotWritable,
            inconclusivePaths: inconclusive
        )
    }

    // MARK: - Internals

    /// Directory names one level below `path`, or an empty list when it cannot be
    /// enumerated. Non-directories are excluded.
    private static func childDirectories(of path: String) -> [String] {
        guard let dir = POSIXShim.openDir(path) else { return [] }
        defer { POSIXShim.closeDir(dir) }

        var names: [String] = []
        setErrno(0)
        while POSIXShim.nextEntry(dir) != nil {
            // Only the count is taken from the raw stream; names come from
            // FileManager so the code stays portable.
            setErrno(0)
        }

        let listed = (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []
        for name in listed where name != "." && name != ".." {
            let child = path + "/" + name
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: child, isDirectory: &isDirectory),
               isDirectory.boolValue {
                names.append(child)
            }
        }
        return names.sorted()
    }

    private static func probeDirectory(
        _ path: String,
        depth: Int,
        payload: Data
    ) -> Entry {
        var buffer = StatBuffer()
        let statRC = POSIXShim.statPath(path, followSymlink: false, into: &buffer)
        guard statRC == 0 else {
            return Entry(
                path: path, depth: depth, exists: false, modeOctal: nil,
                isDirectory: false, enumerable: false, entryCount: nil,
                writable: false, createErrnoName: nil, writeErrnoName: nil,
                readBackErrnoName: nil, readBackMatched: nil, removable: false,
                childNames: []
            )
        }

        let modeOctal = String(buffer.mode, radix: 8)
        let isDirectory = (buffer.mode & StatBuffer.modeTypeMask) == StatBuffer.modeDirectory

        // Enumerability.
        var enumerable = false
        var entryCount: Int?
        if isDirectory {
            if let dir = POSIXShim.openDir(path) {
                var count = 0
                setErrno(0)
                while POSIXShim.nextEntry(dir) != nil { count += 1; setErrno(0) }
                POSIXShim.closeDir(dir)
                enumerable = true
                entryCount = count
            }
        }

        // Writability: create the synthetic file, read it back, remove it.
        var writable = false
        var createErrnoName: String?
        var writeErrnoName: String?
        var readBackErrnoName: String?
        var readBackMatched: Bool?
        var removable = false

        let target = path + "/" + POSIXProbeEngine.syntheticFileName
        POSIXShim.unlinkFile(target)
        let fd = POSIXShim.openFile(target, O_CREAT | O_EXCL | O_WRONLY, 0o644)
        if fd >= 0 {
            let written: Int = payload.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return -1 }
                return POSIXShim.writeFD(fd, base, raw.count)
            }
            // errno is read before close() runs, because close() may replace it
            // with its own status and the wrong errno would then be reported.
            let writeErrno: Int32? = written < 0 ? currentErrno() : nil
            POSIXShim.closeFile(fd)
            if written == payload.count {

                // Read back through the same path to confirm content.
                let readFD = POSIXShim.openFile(target, O_RDONLY, 0)
                if readFD >= 0 {
                    var readBuffer = [UInt8](repeating: 0, count: 4096)
                    let n: Int = readBuffer.withUnsafeMutableBufferPointer { ptr in
                        guard let base = ptr.baseAddress else { return -1 }
                        return POSIXShim.readFD(readFD, base, ptr.count)
                    }
                    // Captured before close(); n == 0 is a clean end-of-file and
                    // carries no errno, so it must not be dressed up as one.
                    let readErrno: Int32? = n < 0 ? currentErrno() : nil
                    POSIXShim.closeFile(readFD)
                    if n > 0 {
                        readBackMatched = Data(readBuffer.prefix(n)) == payload
                    } else if let readErrno {
                        readBackErrnoName = ErrorClassifier.errnoName(readErrno)
                    }
                } else {
                    let openErrno = currentErrno()
                    readBackErrnoName = ErrorClassifier.errnoName(openErrno)
                }

                // Writability is what was *verified*, not what was attempted:
                // a write the harness could not read back is not a capability.
                writable = (readBackMatched == true)
                removable = POSIXShim.unlinkFile(target) == 0
            } else {
                // The file was created, so it must be removed again here as
                // well; leaving it behind would litter the container this probe
                // is only meant to observe.
                _ = POSIXShim.unlinkFile(target)
                writeErrnoName = writeErrno.map { ErrorClassifier.errnoName($0) }
            }
        } else {
            let createErrno = currentErrno()
            createErrnoName = ErrorClassifier.errnoName(createErrno)
        }

        let childNames = isDirectory
            ? (((try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []).sorted())
            : []

        return Entry(
            path: path,
            depth: depth,
            exists: true,
            modeOctal: modeOctal,
            isDirectory: isDirectory,
            enumerable: enumerable,
            entryCount: entryCount,
            writable: writable,
            createErrnoName: createErrnoName,
            writeErrnoName: writeErrnoName,
            readBackErrnoName: readBackErrnoName,
            readBackMatched: readBackMatched,
            removable: removable,
            childNames: childNames
        )
    }
}
