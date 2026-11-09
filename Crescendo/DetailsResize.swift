import Cocoa

//= DetailsResize.swift  version 0.1.0 (2026-11-09)
//= The main window's "Event Details" box has a fixed height in the storyboard. SplitHandle is a thin strip above it
//= (over the separator line) that the user drags up or down to change that height. It works by changing the constant of the
//= box's existing height constraint, so all six filters (All Events, File, Process, Network, Unsigned, Exclude Apple),
//= which share this one box, are covered. The height is remembered between launches.

final class SplitHandle: NSView {
    var heightConstraint: NSLayoutConstraint?
    var minHeight: CGFloat = 60
    var reservedHeight: CGFloat = 260 //= space always kept for the toolbar and the event table
    var defaultsKey = "details.height"
    private var startY: CGFloat = 0
    private var startHeight: CGFloat = 0

    override var isOpaque: Bool { false }

    override func resetCursorRects() {
        addCursorRect(bounds, cursor: .resizeUpDown)
    }

    override func mouseDown(with event: NSEvent) {
        startY = event.locationInWindow.y
        startHeight = heightConstraint?.constant ?? 0
    }

    override func mouseDragged(with event: NSEvent) {
        guard let constraint = heightConstraint, let host = superview else { return }
        //= window coordinates grow upwards: dragging up moves the divider up and makes the details box taller
        let proposed = startHeight + (event.locationInWindow.y - startY)
        let maxHeight = max(minHeight, host.bounds.height - reservedHeight)
        constraint.constant = min(max(proposed, minHeight), maxHeight)
    }

    override func mouseUp(with _: NSEvent) {
        if let value = heightConstraint?.constant { UserDefaults.standard.set(Double(value), forKey: defaultsKey) }
    }

    //= a short grip line so the handle is discoverable
    override func draw(_: NSRect) {
        NSColor.tertiaryLabelColor.setFill()
        let grip = NSRect(x: bounds.midX - 18, y: bounds.midY - 1, width: 36, height: 2)
        NSBezierPath(roundedRect: grip, xRadius: 1, yRadius: 1).fill()
    }
}

extension NSViewController {
    //= Makes `details` (a view with its own fixed height constraint) resizable by dragging a handle placed just above
    //= `anchor` (the label over the details box).
    func installDetailsHandle(details: NSView, above anchor: NSView, toolTip: String) {
        guard let heightConstraint = details.constraints.first(where: { $0.firstAttribute == .height && $0.secondItem == nil }) else {
            NSLog("details box has no fixed height constraint; leaving it as it is")
            return
        }
        let saved = UserDefaults.standard.double(forKey: "details.height")
        if saved >= 60 { heightConstraint.constant = CGFloat(saved) }
        let handle = SplitHandle()
        handle.heightConstraint = heightConstraint
        handle.toolTip = toolTip
        handle.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(handle)
        NSLayoutConstraint.activate([
            handle.leadingAnchor.constraint(equalTo: anchor.leadingAnchor),
            handle.trailingAnchor.constraint(equalTo: anchor.trailingAnchor),
            handle.bottomAnchor.constraint(equalTo: anchor.topAnchor),
            handle.heightAnchor.constraint(equalToConstant: 10),
        ])
    }
}
