//
//  FSTargets.swift
//  FSProbeCore — the target path list under investigation.
//
//  These are investigation targets, not assumed-accessible locations.
//  Baseline targets (app container) establish the control behaviour; the
//  /var/ family is the actual research surface.
//

import Foundation

public struct FSTarget: Sendable, Identifiable, Codable {
    /// Absolute path to probe.
    public let path: String
    /// Short label used in the matrix.
    public let label: String
    /// Why this target is probed.
    public let rationale: String
    /// Whether this is a control/baseline target or an investigation target.
    public let isBaseline: Bool

    public init(path: String, label: String, rationale: String, isBaseline: Bool) {
        self.path = path
        self.label = label
        self.rationale = rationale
        self.isBaseline = isBaseline
    }

    public var id: String { path }
}

public enum FSTargets {

    /// Control targets: the app's own container. Any capability observed here
    /// is a documented capability, not a finding.
    public static let baselines: [FSTarget] = [
        FSTarget(
            path: NSHomeDirectory(),
            label: "app container root",
            rationale: "Control: documents the sandbox grant an ordinary app receives.",
            isBaseline: true
        ),
        FSTarget(
            path: NSHomeDirectory() + "/Documents",
            label: "app Documents",
            rationale: "Control: user-visible container directory, expected fully accessible.",
            isBaseline: true
        ),
        FSTarget(
            path: NSHomeDirectory() + "/Library",
            label: "app Library",
            rationale: "Control: container Library directory, expected fully accessible.",
            isBaseline: true
        ),
        FSTarget(
            path: NSHomeDirectory() + "/tmp",
            label: "app tmp",
            rationale: "Control: container scratch directory, expected fully accessible.",
            isBaseline: true
        )
    ]

    /// Investigation targets under /var/ and related locations.
    public static let investigations: [FSTarget] = [
        FSTarget(
            path: "/var",
            label: "/var",
            rationale: "Root of the research surface; /var is a symlink to /private/var on iOS.",
            isBaseline: false
        ),
        FSTarget(
            path: "/private/var",
            label: "/private/var",
            rationale: "Real path behind /var; tests whether the symlink changes authorization.",
            isBaseline: false
        ),
        FSTarget(
            path: "/var/mobile",
            label: "/var/mobile",
            rationale: "User home area on iOS; traditionally 0755 mobile:mobile.",
            isBaseline: false
        ),
        FSTarget(
            path: "/var/mobile/Library",
            label: "/var/mobile/Library",
            rationale: "Shared user Library; contains Preferences and other shared state.",
            isBaseline: false
        ),
        FSTarget(
            path: "/var/mobile/Library/Preferences",
            label: "/var/mobile/Library/Preferences",
            rationale: "Preference store area; tests whether cfprefsd-mediated access differs from direct access.",
            isBaseline: false
        ),
        FSTarget(
            path: "/var/mobile/Containers",
            label: "/var/mobile/Containers",
            rationale: "Container registry parent; tests enumeration of sibling app containers.",
            isBaseline: false
        ),
        FSTarget(
            path: "/var/mobile/Containers/Data/Application",
            label: "/var/mobile/Containers/Data/Application",
            rationale: "Per-app data container parent; tests cross-app container isolation.",
            isBaseline: false
        ),
        FSTarget(
            path: "/var/mobile/Containers/Shared/AppGroup",
            label: "/var/mobile/Containers/Shared/AppGroup",
            rationale: "App Group container parent; tests whether group membership is enforced by the sandbox profile or by directory permissions.",
            isBaseline: false
        ),
        FSTarget(
            path: "/var/tmp",
            label: "/var/tmp",
            rationale: "World-writable-style scratch area; tests whether shared temp space is reachable.",
            isBaseline: false
        )
    ]

    /// All targets, baselines first so the control results are read first.
    public static var all: [FSTarget] { baselines + investigations }
}
