//
//  CSP_CIS_AuditApp.swift
//  CSP-CIS_Audit
//
//  Created by sean dolbec on 5/23/25.
//

import SwiftUI

@main
struct CSP_CIS_AuditApp: App {
    // Use CISApp from Main.swift as the application delegate
    // This will trigger its applicationDidFinishLaunching, which initializes MenuBarManager
    @NSApplicationDelegateAdaptor(CISApp.self) var appDelegate

    var body: some Scene {
        // Use Settings scene if you don't need a main window.
        // This makes it a menu-bar-only application.
        // If you want a main window (e.g., for settings), you could use WindowGroup here.
        Settings {
            // You can put a settings view here if needed.
            // For now, an EmptyView is fine for a menu-bar-only app.
            EmptyView()
        }

        // We do NOT add a MenuBarExtra here because MenuBarManager (initialized via CISApp)
        // is responsible for creating and managing the NSStatusItem and its menu.
    }
}
