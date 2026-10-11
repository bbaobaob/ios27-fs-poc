//
//  POSIXShim+Darwin.swift
//  FSProbeCore — Darwin implementation of the POSIX seam.
//
//  This is the implementation that runs on iOS 27 and macOS. Each wrapper is a
//  direct pass-through; no behavior is altered.
//
//  Note on `open`: the Darwin importer marks `open` as an unavailable variadic
//  shim, so it is bound by symbol name. The symbol is the documented libc
//  function from <fcntl.h>; only the Swift import path is avoided.
//

#if canImport(Darwin)
import Darwin

extension POSIXShim {

    @_silgen_name("open")
    private static func cOpen(_ path: UnsafePointer<CChar>, _ flags: Int32, _ mode: UInt32) -> Int32

    public static func openFile(_ path: String, _ flags: Int32, _ mode: UInt32) -> Int32 {
        return path.withCString { cOpen($0, flags, mode) }
    }

    @discardableResult
    public static func closeFile(_ fd: Int32) -> Int32 {
        return close(fd)
    }

    public static func readFD(_ fd: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        return read(fd, buffer, count)
    }

    public static func writeFD(_ fd: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        return write(fd, buffer, count)
    }

    public static func openDir(_ path: String) -> OpaquePointer? {
        return path.withCString { ptr in
            guard let dir = opendir(ptr) else { return nil }
            return OpaquePointer(dir)
        }
    }

    public static func nextEntry(_ dir: OpaquePointer) -> OpaquePointer? {
        guard let entry = readdir(UnsafeMutablePointer<DIR>(dir)) else { return nil }
        return OpaquePointer(entry)
    }

    @discardableResult
    public static func closeDir(_ dir: OpaquePointer) -> Int32 {
        return closedir(UnsafeMutablePointer<DIR>(dir))
    }

    public static func statPath(
        _ path: String,
        followSymlink: Bool,
        into buffer: inout StatBuffer
    ) -> Int32 {
        var st = stat()
        let rc: Int32 = path.withCString { ptr in
            followSymlink ? stat(ptr, &st) : lstat(ptr, &st)
        }
        if rc == 0 {
            buffer.size = Int64(st.st_size)
            buffer.mode = UInt32(st.st_mode)
        }
        return rc
    }

    public static func readLink(_ path: String, into buffer: UnsafeMutableRawPointer, capacity: Int) -> Int {
        // withMemoryRebound is the sanctioned way to retype a raw buffer;
        // assumingMemoryBound on memory already bound to another type is UB.
        return buffer.withMemoryRebound(to: CChar.self, capacity: capacity) { ptr in
            path.withCString { cPtr in
                readlink(cPtr, ptr, capacity)
            }
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
