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

    //= recordings (.crescrec) open as documents in a player window
    @objc func openRecording(_: Any?) {
        NSDocumentController.shared.openDocument(nil)
    }

    //= this is not an app that starts with an untitled document
    func applicationShouldOpenUntitledFile(_: NSApplication) -> Bool { false }

    @objc func showWindow(_: Any?) {
        NSApp.activate(ignoringOtherApps: true)
    }

    func buildMenuBarMenu() {
        let menu = NSMenu()

        let about = NSMenuItem(title: AppInfo.longText, action: nil, keyEquivalent: "")
        about.isEnabled = false //= shows which build is running
        menu.addItem(about)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Show App Window", action: #selector(showWindow), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Cresc Console...", action: #selector(showConsole), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Open Recording...", action: #selector(openRecording), keyEquivalent: ""))
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
        //= File > Open Recording... (Command-O), added at run time to the storyboard's File menu
        if let fileMenu = NSApp.mainMenu?.items.first(where: { $0.title == "File" })?.submenu {
            let item = NSMenuItem(title: "Open Recording...", action: #selector(openRecording(_:)), keyEquivalent: "o")
            item.target = self
            fileMenu.insertItem(item, at: 0)
        }

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

//= The identity of this build, as baked into Info.plist by `make build-lite` (see Makefile BUILD_NUMBER / BUILD_COMMIT / BUILD_DATE).
enum AppInfo {
    private static var info: [String: Any] { Bundle.main.infoDictionary ?? [:] }

    //= "1.0.4 (build 312)"
    static var shortText: String {
        "\(info["CFBundleShortVersionString"] as? String ?? "?") (build \(info["CFBundleVersion"] as? String ?? "?"))"
    }

    //= "Crescendo 1.0.4 (build 312), commit 4a1b2c3-dirty, built 2026-11-09T12:00:00Z"
    static var longText: String {
        var text = "Crescendo " + shortText
        if let commit = info["CrescendoBuildCommit"] as? String, !commit.isEmpty { text += ", commit " + commit }
        if let date = info["CrescendoBuildDate"] as? String, !date.isEmpty { text += ", built " + date }
        return text
    }
}
