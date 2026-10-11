//
//  POSIXShim+Compat.swift
//  FSProbeCore — non-Darwin implementation of the POSIX seam.
//
//  Verification-host support only. Some Swift toolchains on non-Darwin hosts do
//  not surface the POSIX surface through the platform module, which would
//  otherwise block compiling and unit-testing the identical probe logic off
//  the target device. The bindings below call the very same C symbols the
//  Darwin implementation uses. This file is inert on iOS and macOS.
//
//  Field layout mirrors asm-generic/stat.h on 64-bit Android, the only host
//  this shim is exercised on.
//

#if !canImport(Darwin)
import Foundation

/// Verification-only mirror of `struct stat` (64-bit Android layout).
///
/// The field list must match the C layout exactly — the kernel writes the whole
/// structure, so an undersized mirror corrupts the stack.
private struct CompatStat {
    var st_dev: UInt64 = 0        // 0
    var st_ino: UInt64 = 0        // 8
    var st_mode: UInt32 = 0       // 16
    var st_nlink: UInt32 = 0      // 20
    var st_uid: UInt32 = 0        // 24
    var st_gid: UInt32 = 0        // 28
    var st_rdev: UInt64 = 0       // 32
    var pad1: UInt64 = 0          // 40
    var st_size: Int64 = 0        // 48
    var st_blksize: Int32 = 0     // 56
    var pad2: Int32 = 0           // 60
    var st_blocks: Int64 = 0      // 64
    var st_atime: Int64 = 0       // 72
    var st_atime_nsec: UInt64 = 0 // 80
    var st_mtime: Int64 = 0       // 88
    var st_mtime_nsec: UInt64 = 0 // 96
    var st_ctime: Int64 = 0       // 104
    var st_ctime_nsec: UInt64 = 0 // 112
    var unused4: UInt32 = 0       // 120
    var unused5: UInt32 = 0       // 124
}

extension POSIXShim {

    @_silgen_name("open")
    private static func cOpen(_ path: UnsafePointer<CChar>, _ flags: Int32, _ mode: UInt32) -> Int32

    @_silgen_name("close")
    private static func cClose(_ fd: Int32) -> Int32

    @_silgen_name("read")
    private static func cRead(_ fd: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int

    @_silgen_name("write")
    private static func cWrite(_ fd: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int

    @_silgen_name("opendir")
    private static func cOpendir(_ path: UnsafePointer<CChar>) -> OpaquePointer?

    @_silgen_name("readdir")
    private static func cReaddir(_ dir: OpaquePointer) -> OpaquePointer?

    @_silgen_name("closedir")
    private static func cClosedir(_ dir: OpaquePointer) -> Int32

    @_silgen_name("lstat")
    private static func cLstat(_ path: UnsafePointer<CChar>, _ buffer: UnsafeMutableRawPointer) -> Int32

    @_silgen_name("stat")
    private static func cStat(_ path: UnsafePointer<CChar>, _ buffer: UnsafeMutableRawPointer) -> Int32

    @_silgen_name("readlink")
    private static func cReadlink(_ path: UnsafePointer<CChar>, _ buffer: UnsafeMutableRawPointer, _ size: Int) -> Int

    public static func openFile(_ path: String, _ flags: Int32, _ mode: UInt32) -> Int32 {
        return path.withCString { cOpen($0, flags, mode) }
    }

    @discardableResult
    public static func closeFile(_ fd: Int32) -> Int32 {
        return cClose(fd)
    }

    public static func readFD(_ fd: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        return cRead(fd, buffer, count)
    }

    public static func writeFD(_ fd: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        return cWrite(fd, buffer, count)
    }

    public static func openDir(_ path: String) -> OpaquePointer? {
        return path.withCString { cOpendir($0) }
    }

    public static func nextEntry(_ dir: OpaquePointer) -> OpaquePointer? {
        return cReaddir(dir)
    }

    @discardableResult
    public static func closeDir(_ dir: OpaquePointer) -> Int32 {
        return cClosedir(dir)
    }

    public static func statPath(
        _ path: String,
        followSymlink: Bool,
        into buffer: inout StatBuffer
    ) -> Int32 {
        var st = CompatStat()
        let rc: Int32 = withUnsafeMutablePointer(to: &st) { ptr -> Int32 in
            path.withCString { cPtr in
                followSymlink
                    ? cStat(cPtr, UnsafeMutableRawPointer(ptr))
                    : cLstat(cPtr, UnsafeMutableRawPointer(ptr))
            }
        }
        if rc == 0 {
            buffer.size = st.st_size
            buffer.mode = st.st_mode
        }
        return rc
    }

    public static func readLink(_ path: String, into buffer: UnsafeMutableRawPointer, capacity: Int) -> Int {
        return path.withCString { ptr in
            cReadlink(ptr, buffer, capacity)
        }
    }

    @discardableResult
    public static func unlinkFile(_ path: String) -> Int32 {
        return path.withCString { ptr in
            unlink(ptr)
        }
    }
}
#endif
