//
//  SandboxProfileProbe.swift
//  FSProbeCore — read the app's own sandbox profile out of its container metadata.
//
//  HYPOTHESIS
//  ----------
//  Every iOS app container contains `.com.apple.mobile_container_manager.metadata.plist`,
//  written by containermanagerd. Published analysis of that file reports it carries
//  `MCMMetadataInfo.SandboxProfileData` — the base64-encoded sandbox profile the
//  kernel compiled for this app — plus `SandboxProfileDataValidationInfo`, the
//  inputs libsandbox used to compile it.
//
//  The container is read-allowed in its entirety while writes are confined to
//  `tmp`, `Library`, and `Documents`. So the profile may be *readable* by the very
//  app it governs. If it is, this project stops guessing at the policy and starts
//  working from the real one — every later experiment can be designed against the
//  actual rules instead of inferred ones.
//
//  EXPECTED RESULT
//  ---------------
//  Reading succeeds (documented container read permission). That is not a
//  vulnerability: it is the app reading its own metadata.
//
//  The security-relevant question is the *write* half, which is probed separately
//  and non-destructively: if the app could modify the profile or its validation
//  info, a privileged daemon's trust in that file would be reachable from inside
//  the sandbox. That would be a genuine boundary violation.
//
//  SAFETY
//  ------
//  This probe never writes to the metadata file. The write test opens it O_WRONLY
//  and closes immediately without writing a single byte, so the file's contents
//  are unchanged whether the open succeeds or fails.
//

import Foundation

public enum SandboxProfileProbe {

    /// Name of the container metadata file written by containermanagerd.
    public static let metadataFileName = ".com.apple.mobile_container_manager.metadata.plist"

    /// Files written into Documents so the profile can be exported and analysed
    /// off-device. The raw decoded profile is binary; the parsed form is JSON.
    public static let exportedProfileName = "sandbox-profile.bin"
    public static let exportedProfileJSONName = "sandbox-profile.json"

    public struct Result: Sendable, Codable {
        /// Whether the metadata file could be read at all.
        public var readable: Bool
        /// Size of the metadata plist on disk.
        public var metadataSizeBytes: Int?
        /// `MCMMetadataIdentifier` if present.
        public var metadataIdentifier: String?
        /// Top-level keys found in the metadata plist.
        public var metadataKeys: [String]
        /// Keys found under `MCMMetadataInfo`.
        public var infoKeys: [String]
        /// Whether `MCMMetadataInfo.SandboxProfileData` was present.
        public var hasSandboxProfileData: Bool
        /// Byte length of the decoded `SandboxProfileData`.
        public var sandboxProfileBytes: Int?
        /// SHA-256 of the decoded profile, so another researcher can confirm they
        /// are looking at the same bytes without transferring the file.
        public var sandboxProfileSHA256: String?
        /// Whether `SandboxProfileDataValidationInfo` was present.
        public var hasValidationInfo: Bool
        /// Whether the decoded profile parses as a property list.
        public var profileParsesAsPlist: Bool
        /// Top-level keys of the decoded profile, when it parses.
        public var profileTopLevelKeys: [String]
        /// A short preview when the profile is text-like (Scheme source).
        public var profilePreview: String?
        /// errno from the read attempt, when it failed.
        public var readErrnoName: String?
        /// Whether the metadata file could be opened for writing.
        ///
        /// Non-destructive: opened and closed, nothing written.
        public var writable: Bool
        /// errno from the write test, when it failed.
        public var writeErrnoName: String?
        /// Whether the metadata file could be unlinked. Never attempted for real
        /// — see `note`.
        public var unlinkErrnoName: String?
        public var note: String

        enum CodingKeys: String, CodingKey {
            case readable, metadataSizeBytes, metadataIdentifier, metadataKeys,
                 infoKeys, hasSandboxProfileData, sandboxProfileBytes,
                 sandboxProfileSHA256, hasValidationInfo, profileParsesAsPlist,
                 profileTopLevelKeys, profilePreview, readErrnoName, writable,
                 writeErrnoName, unlinkErrnoName, note
        }
    }

    /// Read the metadata plist from `containerPath` and extract the profile.
    ///
    /// - Parameter documentsDirectory: when set, the decoded profile and a parsed
    ///   JSON form are written here so they can be exported off the device.
    public static func probe(
        containerPath: String,
        documentsDirectory: URL? = nil
    ) -> Result {
        let metadataURL = URL(fileURLWithPath: containerPath)
            .appendingPathComponent(metadataFileName)

        var result = Result(
            readable: false,
            metadataSizeBytes: nil,
            metadataIdentifier: nil,
            metadataKeys: [],
            infoKeys: [],
            hasSandboxProfileData: false,
            sandboxProfileBytes: nil,
            sandboxProfileSHA256: nil,
            hasValidationInfo: false,
            profileParsesAsPlist: false,
            profileTopLevelKeys: [],
            profilePreview: nil,
            readErrnoName: nil,
            writable: false,
            writeErrnoName: nil,
            unlinkErrnoName: nil,
            note: ""
        )

        // ---- read the metadata plist -------------------------------------
        guard let data = FileManager.default.contents(atPath: metadataURL.path) else {
            result.readErrnoName = currentErrnoName()
            result.note = "Metadata plist could not be read (\(result.readErrnoName ?? "unknown errno"))."
            finishWriteTest(&result, metadataURL: metadataURL)
            return result
        }
        result.readable = true
        result.metadataSizeBytes = data.count

        if let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: nil
        ) as? [String: Any] {
            result.metadataKeys = plist.keys.sorted()
            result.metadataIdentifier = plist["MCMMetadataIdentifier"] as? String

            if let info = plist["MCMMetadataInfo"] as? [String: Any] {
                result.infoKeys = info.keys.sorted()
                result.hasValidationInfo = info["SandboxProfileDataValidationInfo"] != nil

                if let encoded = info["SandboxProfileData"] as? Data,
                   let decoded = Data(base64Encoded: encoded) {
                    result.hasSandboxProfileData = true
                    result.sandboxProfileBytes = decoded.count
                    result.sandboxProfileSHA256 = SHA256.hexDigest(decoded)
                    describe(decoded, into: &result)

                    // Export the raw profile and a parsed form for off-device analysis.
                    if let documentsDirectory {
                        export(decoded, to: documentsDirectory)
                    }
                } else if let encoded = info["SandboxProfileData"] as? String,
                          let decoded = Data(base64Encoded: encoded) {
                    result.hasSandboxProfileData = true
                    result.sandboxProfileBytes = decoded.count
                    result.sandboxProfileSHA256 = SHA256.hexDigest(decoded)
                    describe(decoded, into: &result)
                    if let documentsDirectory {
                        export(decoded, to: documentsDirectory)
                    }
                }
            }
        }

        if !result.hasSandboxProfileData {
            result.note = """
            Metadata plist read (\(data.count) bytes) but it carries no \
            SandboxProfileData. Keys present: \(result.metadataKeys.joined(separator: ", ")).
            """
        } else {
            result.note = """
            Read the app's own sandbox profile from its container metadata: \
            \(result.sandboxProfileBytes ?? 0) bytes, \
            sha256 \(result.sandboxProfileSHA256 ?? "unknown").
            """
        }

        finishWriteTest(&result, metadataURL: metadataURL)
        return result
    }

    /// Non-destructive writability test: open O_WRONLY, close, write nothing.
    private static func finishWriteTest(_ result: inout Result, metadataURL: URL) {
        let fd = POSIXShim.openFile(metadataURL.path, O_WRONLY, 0)
        if fd >= 0 {
            POSIXShim.closeFile(fd)
            result.writable = true
            result.note += """
                The metadata file accepted an O_WRONLY open (nothing was written).
                """
        } else {
            result.writeErrnoName = currentErrnoName()
        }
    }

    /// Describe the decoded profile: is it a plist, is it text, what does it hold.
    private static func describe(_ profile: Data, into result: inout Result) {
        if let plist = try? PropertyListSerialization.propertyList(
            from: profile, options: [], format: nil
        ) {
            result.profileParsesAsPlist = true
            if let dict = plist as? [String: Any] {
                result.profileTopLevelKeys = dict.keys.sorted()
            } else if let array = plist as? [Any] {
                result.profileTopLevelKeys = ["<array of \(array.count) elements>"]
            }
            return
        }

        // A compiled profile is binary, but if it is Scheme-like text a preview
        // is far more useful than a key list.
        if let text = String(data: profile, encoding: .utf8),
           text.contains("(") || text.contains("allow") {
            result.profilePreview = String(text.prefix(2000))
        }
    }

    private static func export(_ profile: Data, to directory: URL) {
        let rawURL = directory.appendingPathComponent(exportedProfileName)
        try? profile.write(to: rawURL, options: .atomic)

        // A JSON form of whatever could be parsed, so it is readable off-device.
        var payload: [String: Any] = [
            "schema": "fsprobe.sandbox-profile.v1",
            "byteLength": profile.count,
            "sha256": SHA256.hexDigest(profile)
        ]
        if let plist = try? PropertyListSerialization.propertyList(
            from: profile, options: [], format: nil
        ) {
            payload["plist"] = plist
        }
        if let text = String(data: profile, encoding: .utf8), !text.isEmpty {
            payload["utf8Preview"] = String(text.prefix(4000))
        }
        if let json = try? JSONSerialization.data(
            withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]
        ) {
            try? json.write(
                to: directory.appendingPathComponent(exportedProfileJSONName),
                options: .atomic
            )
        }
    }

    private static func currentErrnoName() -> String? {
        ErrorClassifier.errnoName(currentErrno())
    }

}
