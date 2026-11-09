import Cocoa

//= ViewController+Files.swift  version 0.1.0 (2026-11-09)
//= Hosts FilesViewController inside the main window. While the "File" segment (index 1) is selected, the Files view covers the
//= old event table and details area, and the window's own Start / Stop / Clear / search / save controls act on it.
//= All other segments (All Events, Process, Network, Unsigned, Exclude Apple) are untouched.

extension ViewController {
    func installFilesView() {
        let controller = FilesViewController()
        addChild(controller)
        let host = controller.view
        host.translatesAutoresizingMaskIntoConstraints = false
        host.isHidden = true
        view.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            host.topAnchor.constraint(equalTo: eventFilter.bottomAnchor, constant: 14),
        ])
        controller.onCapturingChanged = { [weak self] capturing in self?.status = capturing ? .running : .stopped }
        controller.onNeedSetup = { (NSApp.delegate as? AppDelegate)?.showEventSetup(nil) }
        filesController = controller

        //= what the Files view covers: the event table, the details caption, label and box, the separator, the resize handle
        var covered: [NSView] = [eventLabel, eventProps]
        if let scroll = logTableView.enclosingScrollView { covered.append(scroll) }
        for sub in view.subviews {
            if let text = sub as? NSTextField, text.stringValue == "Event Details:" { covered.append(text) }
            if let box = sub as? NSBox, box.boxType == .separator, box.frame.width > 400 { covered.append(box) }
            if sub is SplitHandle { covered.append(sub) }
        }
        coveredByFiles = covered
    }

    //= called whenever the filter segments change
    func refreshFilesMode() {
        guard let controller = filesController else { return }
        let wantFiles = eventFilter.selectedSegment == 1 //= "File"
        if wantFiles == !controller.view.isHidden { return }
        controller.view.isHidden = !wantFiles
        for sub in coveredByFiles { sub.isHidden = wantFiles }
        if wantFiles {
            status = controller.isCapturing ? .running : .stopped
        } else {
            status = .stopped
        }
    }
}
