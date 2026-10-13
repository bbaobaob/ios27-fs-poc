//
//  FSOperation.swift
//  FSProbeCore — original research harness for iOS 27 filesystem capability probing.
//
//  Defines the discrete filesystem operations that are probed independently.
//  Operations are deliberately NOT interchangeable: each one maps to a distinct
//  kernel authorization path, so each one is recorded separately.
//

import Foundation

/// A single filesystem operation performed against a target path.
///
/// The raw value is used verbatim in the exported capability matrix so that a
/// reader can tell exactly which syscall family produced each result.
public enum FSOperation: String, Codable, Sendable, CaseIterable {
    /// `lstat()` — metadata without following the final symlink.
    case stat = "lstat"
    /// `stat()` — metadata, following the final symlink.
    case statFollow = "stat"
    /// `opendir()` — obtain a directory handle (search permission on the directory).
    case openDirectory = "opendir"
    /// `readdir()` — enumerate directory entries (read permission on the directory).
    case enumerate = "readdir"
    /// `open(O_RDONLY)` + `read()` — read file contents.
    case readFile = "open+read"
    /// `open(O_CREAT|O_EXCL)` — create a new file.
    case createFile = "open+create"
    /// `open(O_WRONLY|O_CREAT|O_TRUNC)` + `write()` — create or overwrite the
    /// synthetic file in the target directory.
    case writeFile = "open+write"
    /// `unlink()` — remove a file.
    case deleteFile = "unlink"
    /// `readlink()` — resolve a symbolic link.
    case readLink = "readlink"

    /// Human-readable explanation of what this operation exercises.
    public var explanation: String {
        switch self {
        case .stat:
            return "Metadata lookup that does not follow a final symlink."
        case .statFollow:
            return "Metadata lookup that follows a final symlink."
        case .openDirectory:
            return "Acquiring a directory handle (requires search/execute permission)."
        case .enumerate:
            return "Listing directory entries (requires read permission on the directory)."
        case .readFile:
            return "Opening a file for reading and reading its bytes."
        case .createFile:
            return "Creating a new file inside the target directory."
        case .writeFile:
            // The flags are O_CREAT|O_TRUNC and the target is the harness's own
            // synthetic file, which the probe has just removed — so this creates
            // the file and then writes into it. Describing it as "modifying an
            // existing file" would misstate what was actually executed.
            return "Creating or overwriting the synthetic file in the target directory and writing its bytes."
        case .deleteFile:
            return "Removing a file with unlink()."
        case .readLink:
            return "Resolving a symbolic link to its target path."
        }
    }
}
