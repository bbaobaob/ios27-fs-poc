//
//  main.swift
//  fsprobe-cli — runs the capability matrix from the command line.
//
//  Used by CI on the macOS runner to exercise the harness end-to-end and to
//  produce a host-platform matrix. Results produced on a macOS host are NOT
//  iOS device results: the platform label is embedded in every report and must
//  not be presented as device evidence.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif
import FSProbeCore

struct Options {
    var label: String = "cli"
    var jsonPath: String?
    var textPath: String?
    var targetFilter: String = "all" // all | baseline | comma-separated paths
    var recordEntryNames: Bool = false
}

func parseArguments(_ args: [String]) -> Options {
    var options = Options()
    var index = 0
    while index < args.count {
        let arg = args[index]
        switch arg {
        case "--label":
            index += 1
            if index < args.count { options.label = args[index] }
        case "--json":
            index += 1
            if index < args.count { options.jsonPath = args[index] }
        case "--text":
            index += 1
            if index < args.count { options.textPath = args[index] }
        case "--targets":
            index += 1
            if index < args.count { options.targetFilter = args[index] }
        case "--record-entry-names":
            options.recordEntryNames = true
        default:
            FileHandle.standardError.write("unknown argument: \(arg)\n".data(using: .utf8)!)
        }
        index += 1
    }
    return options
}

let options = parseArguments(Array(CommandLine.arguments.dropFirst()))

let targets: [FSTarget]
switch options.targetFilter {
case "baseline":
    targets = FSTargets.baselines
case "all":
    targets = FSTargets.all
default:
    let paths = options.targetFilter.split(separator: ",").map(String.init)
    targets = paths.map {
        FSTarget(path: $0, label: "cli", rationale: "CLI-specified target", isBaseline: false)
    }
}

let deviceModel = HostInfo.modelIdentifier()
let platformName: String
#if canImport(Darwin)
platformName = "macOS"
#else
platformName = HostInfo.platformName()
#endif
let environment = CapabilityMatrix.EnvironmentRecord(
    osName: platformName,
    osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
    osBuild: HostInfo.buildVersion(),
    deviceModel: "\(options.label) / \(deviceModel)"
)

let matrix = MatrixRunner().run(
    targets: targets,
    recordEntryNames: options.recordEntryNames,
    environment: environment
)

print(ReportExporter.text(matrix, targets: targets))

if let jsonPath = options.jsonPath {
    do {
        let data = try ReportExporter.json(matrix)
        try data.write(to: URL(fileURLWithPath: jsonPath))
        print("wrote \(jsonPath)")
    } catch {
        FileHandle.standardError.write("failed to write JSON: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

if let textPath = options.textPath {
    do {
        try ReportExporter.text(matrix, targets: targets)
            .write(toFile: textPath, atomically: true, encoding: .utf8)
        print("wrote \(textPath)")
    } catch {
        FileHandle.standardError.write("failed to write text: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

/// Host identification helpers, implemented per platform.
enum HostInfo {
    static func modelIdentifier() -> String {
        #if canImport(Darwin)
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        return String(cString: model)
        #else
        return "non-darwin-verification-host"
        #endif
    }

    static func buildVersion() -> String {
        #if canImport(Darwin)
        var size = 0
        sysctlbyname("kern.osversion", nil, &size, nil, 0)
        var build = [CChar](repeating: 0, count: size)
        sysctlbyname("kern.osversion", &build, &size, nil, 0)
        return String(cString: build)
        #else
        return "unknown"
        #endif
    }

    /// Platform name for the report header. Kept separate from the version
    /// string so the header never repeats itself.
    static func platformName() -> String {
        #if canImport(Darwin)
        return "macOS"
        #else
        return "verification-host"
        #endif
    }
}
