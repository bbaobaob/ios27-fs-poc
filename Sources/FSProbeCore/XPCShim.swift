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
    /// Create a connection to a named mach service, or nil when the factory is
    /// not present in this runtime.
    ///
    /// This is the whole public surface for reaching a service by name. The SDK
    /// marks the underlying function unavailable, which prevents linking it, so
    /// it is resolved at runtime instead -- and whether it resolves is itself a
    /// fact the caller needs, which is what `connectionFactoryAvailable` reports.
    ///
    /// The return is an optional on every platform, uniformly, because the
    /// factory's own return nullability is not knowable from here -- the header is
    /// unavailable. Declaring it optional everywhere means a caller writes the
    /// same guard-let on the device and on the host, and cannot accidentally rely
    /// on a non-null guarantee that only one branch actually provides.
    public static func createConnection(_ name: String) -> XPCConnection? {
        #if canImport(Darwin)
        guard let sym = POSIXShim.lookupSymbol("xpc_connection_create_mach_service") else {
            return nil
        }
        let factory = unsafeBitCast(sym, to: CreateMachServiceFn.self)
        return name.withCString { factory($0, nil, 0) }
        #else
        return nil
        #endif
    }

    #if canImport(Darwin)
    /// The factory's C signature. Private, because the public surface is the
    /// `createConnection` function rather than the function value itself: a public
    /// property cannot expose a private (or internal) function type, and leaking
    /// the raw C signature to callers buys nothing.
    private typealias CreateMachServiceFn = @convention(c) (
        UnsafePointer<CChar>, DispatchQueue?, UInt64
    ) -> XPCConnection?

    /// True when the connection factory resolves in this process. On iOS this is
    /// the interesting question: the SDK forbids linking it, but the code may
    /// still be present in libxpc.
    public static var connectionFactoryAvailable: Bool {
        POSIXShim.lookupSymbol("xpc_connection_create_mach_service") != nil
    }
    #else
    public static var connectionFactoryAvailable: Bool { false }
    #endif

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

    /// The number of keys in a dictionary.
    public static func dictionaryCount(_ dictionary: XPCObject) -> Int {
        #if canImport(Darwin)
        return Int(xpc_dictionary_get_count(dictionary))
        #else
        return 0
        #endif
    }

    /// Walk a dictionary, calling `body` with each key and value.
    ///
    /// Exposed so a caller can capture key NAMES without reading values, which is
    /// the discipline the reply-contents probe depends on.
    public static func dictionaryApply(
        _ dictionary: XPCObject,
        _ body: @escaping @convention(block) (UnsafePointer<CChar>, XPCObject) -> Bool
    ) {
        #if canImport(Darwin)
        xpc_dictionary_apply(dictionary, body)
        #endif
    }

    // xpc_get_type and XPC_TYPE_DICTIONARY are bound by name rather than used
    // through the import, because their imported signatures differ between the
    // macOS and iOS SDKs -- xpc_type_t is not an xpc_object_t, and comparing the
    // two directly fails to compile on the iOS SDK. Binding by name with an
    // explicit OpaquePointer return makes the comparison well defined everywhere.
    #if canImport(Darwin)
    @_silgen_name("xpc_get_type")
    private static func cXpcGetType(_ object: XPCObject) -> OpaquePointer

    @_silgen_name("_xpc_type_dictionary")
    private static var dictionaryTypeSymbol: OpaquePointer
    #endif

    /// The XPC type of an object, exposed so a caller can tell a dictionary from
    /// an error without treating either as data.
    public static func type(of object: XPCObject) -> OpaquePointer? {
        #if canImport(Darwin)
        return cXpcGetType(object)
        #else
        return nil
        #endif
    }

    /// The XPC_TYPE_DICTIONARY singleton, resolved at runtime.
    public static var dictionaryType: OpaquePointer? {
        #if canImport(Darwin)
        return dictionaryTypeSymbol
        #else
        return nil
        #endif
    }

    // XPC_TYPE_ERROR, bound by name for the same reason as the dictionary type:
    #if canImport(Darwin)
    @_silgen_name("_xpc_type_error")
    private static var errorTypeSymbol: OpaquePointer
    #endif

    /// True when `object` is an XPC error.
    public static func isError(_ object: XPCObject) -> Bool {
        #if canImport(Darwin)
        return cXpcGetType(object) == errorTypeSymbol
        #else
        return false
        #endif
    }
}
