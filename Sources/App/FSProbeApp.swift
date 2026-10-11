//
//  FSProbeApp.swift
//  FSProbe (App) — application entry point.
//
//  FSProbe is a research instrument, not a product: it probes filesystem
//  capabilities against /var/ locations on launch and records the result.
//

import SwiftUI

@main
struct FSProbeApp: App {

    @State private var model = MatrixViewModel()

    var body: some Scene {
        WindowGroup {
            MatrixView(model: model)
        }
    }
}