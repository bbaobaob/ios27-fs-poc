//
//  XPCShim.swift
//  FSProbeCore — the single place the XPC C API is bound.
//
//  WHY THIS FILE EXISTS
//  --------------------
//  The same mistake has now happened twice, which makes it structural rather
//  than accidental.
//
//  `@_silgen_name` binds a symbol to a Swift declaration, and the compiler
//  treats the result as a method of the enclosing type. Two enums that both
//  declare `@_silgen_name("xpc_dictionary_get_string")` therefore share ONE
//  implementation while declaring different signatures, and the build fails with
//  "function type mismatch, declared as ... but used as ...".
//
//  It happened first with the Mach symbols, which is why MachShim exists. It has
//  now happened again with the XPC symbols, which is why this file exists.
//
//  The rule, stated once: any symbol bound by name has exactly one owner. There
//  is no second place.
//
//  A second lesson is recorded here too. The imported XPC functions have real
//  signatures that the obvious call site does not suggest:
//  `xpc_dictionary_get_string` takes position and options arguments, and
//  `xpc_connection_send_message_with_reply` takes a reply queue. Binding by name
//  with the full signature is what forces those to be supplied, and it is why
//  these are bound here rather than called through the import.
//

import Foundation

#if canImport(Darwin)
import Darwin
/// The XPC object and connection types, spelled portably so this file compiles
/// everywhere. On Darwin they come from the XPC module; elsewhere they are
/// stand-ins that are never used, because every function below is gated.
public typealias XPCObject = xpc_object_t
public typealias XPCConnection = xpc_connection_t
#else
public typealias XPCObject = AnyObject
public typealias XPCConnection = AnyObject
#endif

/// The single binding point for the XPC C API.
public enum XPCShim {

    /// The connection factory, resolved at runtime.
    ///
    /// The SDK marks `xpc_connection_create_mach_service` unavailable, which
    /// prevents linking it by name. Resolving it through dlsym answers the
    /// question the SDK availability cannot: does the code exist in the runtime,
    /// and if so, what does the operating system do when it is called?
    #if canImport(Darwin)
    private typealias CreateMachServiceFn = @convention(c) (
        UnsafePointer<CChar>, DispatchQueue?, UInt64
    ) -> XPCConnection?

    public static var connectionFactory: CreateMachServiceFn? {
        guard let sym = POSIXShim.lookupSymbol("xpc_connection_create_mach_service") else {
            return nil
        }
        return unsafeBitCast(sym, to: CreateMachServiceFn.self)
    }
    #else
    public static var connectionFactory: Any? { nil }
    #endif

    /// True when the connection factory resolves in this process.
    public static var connectionFactoryAvailable: Bool {
        connectionFactory != nil
    }

    /// `xpc_connection_set_event_handler(connection, handler)`.
    public static func setEventHandler(
        _ connection: XPCConnection,
        _ handler: @escaping @convention(block) (XPCObject) -> Void
    ) {
        #if canImport(Darwin)
        xpc_connection_set_event_handler(connection, handler)
        #endif
    }

    /// `xpc_connection_resume(connection)`.
    public static func resume(_ connection: XPCConnection) {
        #if canImport(Darwin)
        xpc_connection_resume(connection)
        #endif
    }

    /// `xpc_connection_cancel(connection)`.
    public static func cancel(_ connection: XPCConnection) {
        #if canImport(Darwin)
        xpc_connection_cancel(connection)
        #endif
    }

    /// `xpc_connection_send_message_with_reply(connection, message, queue, handler)`.
    ///
    /// Bound by name with the full signature. The imported function takes a reply
    /// QUEUE as its third argument, which a two-argument call site does not
    /// supply — and the compiler cannot catch that if the call is written against
    /// the import.
    #if canImport(Darwin)
    @_silgen_name("xpc_connection_send_message_with_reply")
    private static func cSendMessageWithReply(
        _ connection: XPCConnection,
        _ message: XPCObject,
        _ replyQueue: DispatchQueue?,
        _ handler: @escaping @convention(block) (XPCObject) -> Void
    )
    #endif

    public static func sendMessageWithReply(
        _ connection: XPCConnection,
        _ message: XPCObject,
        _ handler: @escaping @convention(block) (XPCObject) -> Void
    ) {
        #if canImport(Darwin)
        cSendMessageWithReply(connection, message, nil, handler)
        #endif
    }

    /// `xpc_dictionary_get_string(dictionary, key, position, options)`.
    ///
    /// Bound by name with the full signature. The imported function takes
    /// position and options arguments that a two-argument call site does not
    /// supply.
    #if canImport(Darwin)
    @_silgen_name("xpc_dictionary_get_string")
    private static func cDictionaryGetString(
        _ dictionary: XPCObject, _ key: UnsafePointer<CChar>,
        _ position: Int, _ options: UInt32
    ) -> UnsafePointer<CChar>?
    #endif

    /// The key under which XPC stores an error's human-readable description.
    public static let errorDescriptionKey = "XPCErrorDescription"

    /// The platform's own one-line reason for an XPC error object.
    public static func errorDescription(_ object: XPCObject) -> String? {
        #if canImport(Darwin)
        let structured = errorDescriptionKey.withCString { key in
            cDictionaryGetString(object, key, 0, 0).map { String(cString: $0) }
        }
        if let structured, !structured.isEmpty { return structured }
        let ptr = xpc_copy_description(object)
        defer { free(ptr) }
        return String(cString: ptr)
        #else
        return nil
        #endif
    }

    /// True when `object` is an XPC error.
    public static func isError(_ object: XPCObject) -> Bool {
        #if canImport(Darwin)
        return xpc_get_type(object) == XPC_TYPE_ERROR
        #else
        return false
        #endif
    }
}
