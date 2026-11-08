import Cocoa

//= ListField.swift  version 0.1.0 (2026-11-08)
//= A multi-value input shown as ROWS: one value per row, editable in place, with
//=   "Add..."  a file/folder picker (NSOpenPanel, multiple selection) when `pick` allows it,
//=   "+"       a new empty row to type into,        "-"  remove the selected rows,
//=   drag and drop of files/folders from the Finder onto the list.
//= A small hint line above the rows says how the field works. Read `values` (empty rows are dropped).

final class ListField: NSObject, NSTableViewDataSource, NSTableViewDelegate {
    enum Pick { case none, directories, files, any }

    let view = NSStackView()
    var onChange: (() -> Void)?

    private let table = NSTableView()
    private let pick: Pick
    private var items = [String]()

    var values: [String] {
        items.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    func setValues(_ newValues: [String]) {
        items = newValues
        table.reloadData()
    }

    init(pick: Pick, hint: String, tip: String, visibleRows: Int = 4) {
        self.pick = pick
        super.init()

        let hintLabel = NSTextField(wrappingLabelWithString: hint)
        hintLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        hintLabel.textColor = .secondaryLabelColor
        hintLabel.toolTip = tip

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("value"))
        column.isEditable = true
        column.resizingMask = .autoresizingMask
        table.addTableColumn(column)
        table.headerView = nil
        table.allowsMultipleSelection = true
        table.usesAlternatingRowBackgroundColors = true
        table.dataSource = self
        table.delegate = self
        table.toolTip = tip
        table.registerForDraggedTypes([.fileURL])

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.heightAnchor.constraint(equalToConstant: CGFloat(visibleRows) * 20 + 6).isActive = true
        scroll.setContentHuggingPriority(.defaultLow, for: .horizontal)

        var buttons = [NSView]()
        if pick != .none {
            let add = NSButton(title: "Add...", target: self, action: #selector(addFromPicker))
            add.toolTip = pick == .directories ? "Choose one or more folders" : "Choose one or more files or folders"
            buttons.append(add)
        }
        let plus = NSButton(title: "+", target: self, action: #selector(addRow))
        plus.toolTip = "Add an empty row and type a value"
        let minus = NSButton(title: "-", target: self, action: #selector(removeSelected))
        minus.toolTip = "Remove the selected rows"
        buttons += [plus, minus]
        let buttonColumn = NSStackView(views: buttons)
        buttonColumn.orientation = .vertical
        buttonColumn.alignment = .leading
        buttonColumn.spacing = 4

        let body = NSStackView(views: [scroll, buttonColumn])
        body.orientation = .horizontal
        body.alignment = .top
        view.orientation = .vertical
        view.alignment = .leading
        view.spacing = 4
        view.addArrangedSubview(hintLabel)
        view.addArrangedSubview(body)
        body.widthAnchor.constraint(equalTo: view.widthAnchor).isActive = true
        hintLabel.widthAnchor.constraint(equalTo: view.widthAnchor).isActive = true
    }

    //= ---- actions -------------------------------------------------------------------------------------------
    @objc private func addRow() {
        items.append("")
        table.reloadData()
        table.editColumn(0, row: items.count - 1, with: nil, select: true)
    }

    @objc private func removeSelected() {
        for index in table.selectedRowIndexes.reversed() where index < items.count { items.remove(at: index) }
        table.reloadData()
        onChange?()
    }

    @objc private func addFromPicker() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = pick == .directories || pick == .any
        panel.canChooseFiles = pick == .files || pick == .any
        panel.canCreateDirectories = pick == .directories
        panel.prompt = "Add"
        guard panel.runModal() == .OK else { return }
        append(panel.urls.map { $0.path })
    }

    private func append(_ paths: [String]) {
        for path in paths where !items.contains(path) { items.append(path) }
        table.reloadData()
        onChange?()
    }

    //= ---- table ---------------------------------------------------------------------------------------------
    func numberOfRows(in _: NSTableView) -> Int { items.count }

    func tableView(_: NSTableView, objectValueFor _: NSTableColumn?, row: Int) -> Any? {
        row < items.count ? items[row] : nil
    }

    func tableView(_: NSTableView, setObjectValue object: Any?, for _: NSTableColumn?, row: Int) {
        guard row < items.count else { return }
        items[row] = (object as? String) ?? ""
        onChange?()
    }

    func tableView(_ tableView: NSTableView, validateDrop _: NSDraggingInfo, proposedRow _: Int,
                   proposedDropOperation _: NSTableView.DropOperation) -> NSDragOperation {
        guard pick != .none else { return [] }
        tableView.setDropRow(-1, dropOperation: .on)
        return .copy
    }

    func tableView(_: NSTableView, acceptDrop info: NSDraggingInfo, row _: Int,
                   dropOperation _: NSTableView.DropOperation) -> Bool {
        let urls = info.draggingPasteboard.readObjects(forClasses: [NSURL.self],
                                                       options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        var paths = [String]()
        for url in urls {
            var isDirectory: ObjCBool = false
            FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
            if pick == .directories && !isDirectory.boolValue { continue }
            if pick == .files && isDirectory.boolValue { continue }
            paths.append(url.path)
        }
        append(paths)
        return !paths.isEmpty
    }
}
