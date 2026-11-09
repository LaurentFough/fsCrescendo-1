import Cocoa

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
    let menuIcon = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

    @objc func hideDockIcon(_: Any?) {
        NSApp.setActivationPolicy(.accessory)
    }

    @objc func showDockIcon(_: Any?) {
        NSApp.setActivationPolicy(.regular)
    }

    //= cresc console (Sessions / Denials / Events), created on first use
    var console: CrescConsole?

    @objc func showConsole(_: Any?) {
        if console == nil { console = CrescConsole() }
        console?.show()
    }

    func applicationWillTerminate(_: Notification) {
        EngineClient.shared.stop()
    }

    //= opens the console on its Events tab, where the event daemon is installed and Full Disk Access explained
    @objc func showEventSetup(_: Any?) {
        if console == nil { console = CrescConsole() }
        console?.showEventsTab()
    }

    @objc func showWindow(_: Any?) {
        NSApp.activate(ignoringOtherApps: true)
    }

    func buildMenuBarMenu() {
        let menu = NSMenu()

        menu.addItem(NSMenuItem(title: "Show App Window", action: #selector(showWindow), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Cresc Console...", action: #selector(showConsole), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())

        menu.addItem(NSMenuItem(title: "Run in Background", action: #selector(hideDockIcon), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Run in Dock", action: #selector(showDockIcon), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())

        menu.addItem(NSMenuItem(title: "Quit Crescendo",
                                action: #selector(NSApplication.terminate(_:)),
                                keyEquivalent: "q"))

        menuIcon.menu = menu
    }

    func applicationDidFinishLaunching(_: Notification) {
        buildMenuBarMenu()

        if let button = menuIcon.button {
            button.image = NSImage(named: NSImage.Name("menuicon"))
        }
    }
}

class AppWindowController: NSWindowController, NSWindowDelegate {
    func windowShouldClose(_: NSWindow) -> Bool {
        NSApp.hide(nil)
        return false
    }
}
