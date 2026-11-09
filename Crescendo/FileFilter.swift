import Cocoa

//= FileFilter.swift  version 0.1.0 (2026-11-09)
//= Filtering for the Files view, in the style of a file-system monitor: "All / Any of the following are true" and rows of
//=   [field] [operator] [value]  with - and + buttons, plus saved filter templates and a list of hidden folders.
//= The model (FilterRule, FileFilter) is plain Swift and independent of the UI; FilterPanel is the editor.

enum FilterField: String, Codable, CaseIterable {
    case path, processName, processPath, pid, category, eventType, signingId, fileOwner, processUser

    enum Kind { case text, number, category }

    var kind: Kind {
        switch self {
        case .pid, .fileOwner, .processUser: return .number
        case .category: return .category
        default: return .text
        }
    }

    var title: String {
        switch self {
        case .path: return "Path"
        case .processName: return "Process Name"
        case .processPath: return "Process Path"
        case .pid: return "PID"
        case .category: return "Category"
        case .eventType: return "Event Type"
        case .signingId: return "Signing ID"
        case .fileOwner: return "File Owner (uid)"
        case .processUser: return "Process User (uid)"
        }
    }
}

enum FilterOp: String, Codable {
    case contains, notContains, isEqual, notEqual, beginsWith, endsWith, greater, less

    var title: String {
        switch self {
        case .contains: return "contains"
        case .notContains: return "does not contain"
        case .isEqual: return "is"
        case .notEqual: return "is not"
        case .beginsWith: return "begins with"
        case .endsWith: return "ends with"
        case .greater: return "is greater than"
        case .less: return "is less than"
        }
    }

    static func available(for kind: FilterField.Kind) -> [FilterOp] {
        switch kind {
        case .text: return [.contains, .notContains, .isEqual, .notEqual, .beginsWith, .endsWith]
        case .number: return [.isEqual, .notEqual, .greater, .less]
        case .category: return [.isEqual, .notEqual]
        }
    }
}

struct FilterRule: Codable, Equatable {
    var field: FilterField = .path
    var op: FilterOp = .contains
    var value = ""

    var isActive: Bool { !value.trimmingCharacters(in: .whitespaces).isEmpty }

    func matches(_ row: FileRow) -> Bool {
        let needle = value.trimmingCharacters(in: .whitespaces)
        switch field.kind {
        case .text:
            let hay: String
            switch field {
            case .path: hay = row.path
            case .processName: hay = row.process
            case .processPath: hay = row.processPath
            case .eventType: hay = row.eventType
            default: hay = row.signingId
            }
            let h = hay.lowercased(), n = needle.lowercased()
            switch op {
            case .contains: return h.contains(n)
            case .notContains: return !h.contains(n)
            case .isEqual: return h == n
            case .notEqual: return h != n
            case .beginsWith: return h.hasPrefix(n)
            case .endsWith: return h.hasSuffix(n)
            default: return true
            }
        case .number:
            let number: Int?
            switch field {
            case .pid: number = row.pid >= 0 ? row.pid : nil
            case .fileOwner: number = row.uid
            default: number = row.actorUid >= 0 ? row.actorUid : nil
            }
            guard let wanted = Int(needle) else { return true } //= not a number yet: do not hide everything while typing
            guard let have = number else { return op == .notEqual }
            switch op {
            case .isEqual: return have == wanted
            case .notEqual: return have != wanted
            case .greater: return have > wanted
            case .less: return have < wanted
            default: return true
            }
        case .category:
            let same = row.category == needle
            return op == .notEqual ? !same : same
        }
    }
}

struct FileFilter {
    var matchAll = true
    var rules = [FilterRule]()

    var active: [FilterRule] { rules.filter { $0.isActive } }
    var isActive: Bool { !active.isEmpty }

    func matches(_ row: FileRow) -> Bool {
        let list = active
        if list.isEmpty { return true }
        return matchAll ? list.allSatisfy { $0.matches(row) } : list.contains { $0.matches(row) }
    }
}

struct FilterTemplate: Codable {
    var name: String
    var matchAll: Bool
    var rules: [FilterRule]
}

//= saved templates live in UserDefaults as JSON
enum FilterTemplates {
    private static let key = "files.filterTemplates"

    static func load() -> [FilterTemplate] {
        guard let data = UserDefaults.standard.data(forKey: key),
            let list = try? JSONDecoder().decode([FilterTemplate].self, from: data) else { return [] }
        return list
    }

    static func save(_ list: [FilterTemplate]) {
        if let data = try? JSONEncoder().encode(list) { UserDefaults.standard.set(data, forKey: key) }
    }
}

//= category choices shown for the "Category" field: raw value, label
let filterCategoryChoices: [(raw: String, label: String)] = [
    ("created", "Created"), ("deleted", "Deleted"), ("modified", "Content Modified"), ("attributes", "Attributes Modified"),
    ("moved_from", "Moved From"), ("moved_to", "Moved To"), ("meta", "Meta Event"),
]

//= one editable rule: [field] [operator] [value] [-] [+]
final class RuleRow: NSStackView, NSTextFieldDelegate {
    var rule: FilterRule
    var onChange: (() -> Void)?
    var onAdd: ((RuleRow) -> Void)?
    var onRemove: ((RuleRow) -> Void)?

    private let fieldPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let opPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let valueField = NSTextField(string: "")
    private let choicePopup = NSPopUpButton(frame: .zero, pullsDown: false)

    init(rule: FilterRule) {
        self.rule = rule
        super.init(frame: .zero)
        orientation = .horizontal
        spacing = 6
        fieldPopup.addItems(withTitles: FilterField.allCases.map { $0.title })
        fieldPopup.target = self
        fieldPopup.action = #selector(fieldChanged)
        fieldPopup.toolTip = "What to test"
        opPopup.target = self
        opPopup.action = #selector(opChanged)
        opPopup.toolTip = "How to compare"
        valueField.delegate = self
        valueField.placeholderString = "value"
        valueField.toolTip = "Text or number to compare with (case-insensitive). An empty value is ignored."
        valueField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        choicePopup.addItems(withTitles: filterCategoryChoices.map { $0.label })
        choicePopup.target = self
        choicePopup.action = #selector(choiceChanged)
        let minus = NSButton(title: "-", target: self, action: #selector(removeClicked))
        minus.toolTip = "Remove this rule"
        let plus = NSButton(title: "+", target: self, action: #selector(addClicked))
        plus.toolTip = "Add a rule below this one"
        for view in [fieldPopup, opPopup, valueField, choicePopup, minus, plus] { addArrangedSubview(view) }
        fieldPopup.widthAnchor.constraint(equalToConstant: 150).isActive = true
        opPopup.widthAnchor.constraint(equalToConstant: 140).isActive = true
        choicePopup.widthAnchor.constraint(greaterThanOrEqualToConstant: 160).isActive = true
        refresh()
    }

    required init?(coder _: NSCoder) { fatalError("not used") }

    //= brings the controls in line with `rule`
    func refresh() {
        let kind = rule.field.kind
        if let index = FilterField.allCases.firstIndex(of: rule.field) { fieldPopup.selectItem(at: index) }
        let ops = FilterOp.available(for: kind)
        if !ops.contains(rule.op) { rule.op = ops[0] }
        opPopup.removeAllItems()
        opPopup.addItems(withTitles: ops.map { $0.title })
        if let index = ops.firstIndex(of: rule.op) { opPopup.selectItem(at: index) }
        valueField.isHidden = kind == .category
        choicePopup.isHidden = kind != .category
        if kind == .category {
            if let index = filterCategoryChoices.firstIndex(where: { $0.raw == rule.value }) { choicePopup.selectItem(at: index) }
            else { rule.value = filterCategoryChoices[choicePopup.indexOfSelectedItem].raw }
        } else {
            valueField.stringValue = rule.value
        }
    }

    @objc private func fieldChanged() {
        rule.field = FilterField.allCases[fieldPopup.indexOfSelectedItem]
        rule.value = rule.field.kind == .category ? filterCategoryChoices[0].raw : ""
        refresh()
        onChange?()
    }

    @objc private func opChanged() {
        let ops = FilterOp.available(for: rule.field.kind)
        rule.op = ops[max(0, min(opPopup.indexOfSelectedItem, ops.count - 1))]
        onChange?()
    }

    @objc private func choiceChanged() {
        rule.value = filterCategoryChoices[max(0, choicePopup.indexOfSelectedItem)].raw
        onChange?()
    }

    func controlTextDidChange(_: Notification) {
        rule.value = valueField.stringValue
        onChange?()                          //= live: the list follows every keystroke
    }

    @objc private func addClicked() { onAdd?(self) }
    @objc private func removeClicked() { onRemove?(self) }
}

//= a stack with a thin border whose colour follows light / dark mode (a CGColor taken once would go stale when the appearance changes)
final class BorderedStack: NSStackView {
    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        effectiveAppearance.performAsCurrentDrawingAppearance { layer?.borderColor = NSColor.separatorColor.cgColor }
    }
}

//= the filter editor: template menu, All/Any, rule rows, hidden folders
final class FilterPanel: NSObject {
    let view = BorderedStack()
    var onChange: (() -> Void)?
    var onRestoreHidden: (() -> Void)?

    private var rows = [RuleRow]()
    private let rowsStack = NSStackView()
    private let matchPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let templatePopup = NSPopUpButton(frame: .zero, pullsDown: true)
    private let hiddenLabel = NSTextField(wrappingLabelWithString: "")
    private let restoreButton = NSButton(title: "Restore All", target: nil, action: nil)
    private let hiddenBox = NSStackView()

    override init() {
        super.init()
        matchPopup.addItems(withTitles: ["All", "Any"])
        matchPopup.target = self
        matchPopup.action = #selector(matchChanged)
        matchPopup.toolTip = "All: every rule must match. Any: one matching rule is enough."
        templatePopup.target = self
        templatePopup.toolTip = "Apply a saved filter, or save the current one as a template"
        let clear = NSButton(title: "Clear Filter", target: self, action: #selector(clearAll))
        clear.toolTip = "Remove all rules"
        let top = NSStackView(views: [templatePopup, NSTextField(labelWithString: "Match"), matchPopup,
                                      NSTextField(labelWithString: "of the following rules"), clear])
        top.orientation = .horizontal
        rowsStack.orientation = .vertical
        rowsStack.alignment = .leading
        rowsStack.spacing = 4

        hiddenLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        hiddenLabel.textColor = .secondaryLabelColor
        hiddenLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        restoreButton.target = self
        restoreButton.action = #selector(restoreClicked)
        restoreButton.toolTip = "Show the hidden folders again (Command-Delete restores the last one)"
        hiddenBox.orientation = .horizontal
        hiddenBox.addArrangedSubview(hiddenLabel)
        hiddenBox.addArrangedSubview(restoreButton)
        hiddenBox.isHidden = true

        view.orientation = .vertical
        view.alignment = .leading
        view.spacing = 6
        view.edgeInsets = NSEdgeInsets(top: 6, left: 8, bottom: 6, right: 8)
        view.addArrangedSubview(top)
        view.addArrangedSubview(rowsStack)
        view.addArrangedSubview(hiddenBox)
        view.wantsLayer = true
        view.layer?.cornerRadius = 6
        view.layer?.borderWidth = 1
        view.layer?.borderColor = NSColor.separatorColor.cgColor
        addRow(FilterRule(), notify: false)
        rebuildTemplateMenu()
    }

    //= ---- model ---------------------------------------------------------------------------------------------
    func filter() -> FileFilter {
        FileFilter(matchAll: matchPopup.indexOfSelectedItem == 0, rules: rows.map { $0.rule })
    }

    func setFilter(_ f: FileFilter) {
        for row in rows { rowsStack.removeArrangedSubview(row); row.removeFromSuperview() }
        rows.removeAll()
        matchPopup.selectItem(at: f.matchAll ? 0 : 1)
        for rule in (f.rules.isEmpty ? [FilterRule()] : f.rules) { addRow(rule, notify: false) }
        onChange?()
    }

    //= adds a rule (used by the right-click menu); an untouched empty rule is replaced
    func addRule(_ rule: FilterRule) {
        if rows.count == 1, !rows[0].rule.isActive {
            rows[0].rule = rule
            rows[0].refresh()
            onChange?()
        } else {
            addRow(rule, notify: true)
        }
    }

    private func addRow(_ rule: FilterRule, notify: Bool, after: RuleRow? = nil) {
        let row = RuleRow(rule: rule)
        row.onChange = { [weak self] in self?.onChange?() }
        row.onAdd = { [weak self] source in self?.addRow(FilterRule(), notify: false, after: source) }
        row.onRemove = { [weak self] target in self?.removeRow(target) }
        if let after = after, let index = rows.firstIndex(where: { $0 === after }) {
            rows.insert(row, at: index + 1)
            rowsStack.insertArrangedSubview(row, at: index + 1)
        } else {
            rows.append(row)
            rowsStack.addArrangedSubview(row)
        }
        row.widthAnchor.constraint(equalTo: rowsStack.widthAnchor).isActive = true
        if notify { onChange?() }
    }

    private func removeRow(_ row: RuleRow) {
        if rows.count == 1 {                  //= the last rule is cleared, not removed
            row.rule = FilterRule()
            row.refresh()
        } else if let index = rows.firstIndex(where: { $0 === row }) {
            rows.remove(at: index)
            rowsStack.removeArrangedSubview(row)
            row.removeFromSuperview()
        }
        onChange?()
    }

    @objc private func matchChanged() { onChange?() }
    @objc private func clearAll() { setFilter(FileFilter()) }
    @objc private func restoreClicked() { onRestoreHidden?() }

    //= ---- hidden folders ------------------------------------------------------------------------------------
    func showHidden(_ folders: [String]) {
        hiddenBox.isHidden = folders.isEmpty
        hiddenLabel.stringValue = "Hidden folders (\(folders.count)): " + folders.joined(separator: ", ")
    }

    //= ---- templates -----------------------------------------------------------------------------------------
    private func rebuildTemplateMenu() {
        templatePopup.removeAllItems()
        templatePopup.addItem(withTitle: "Apply Filter Template")          //= the title item of a pull-down
        for template in FilterTemplates.load() {
            let item = NSMenuItem(title: template.name, action: #selector(applyTemplate(_:)), keyEquivalent: "")
            item.target = self
            templatePopup.menu?.addItem(item)
        }
        templatePopup.menu?.addItem(NSMenuItem.separator())
        let save = NSMenuItem(title: "Save Current Filter as Template...", action: #selector(saveTemplate), keyEquivalent: "")
        save.target = self
        templatePopup.menu?.addItem(save)
        let delete = NSMenuItem(title: "Delete a Template...", action: #selector(deleteTemplate), keyEquivalent: "")
        delete.target = self
        templatePopup.menu?.addItem(delete)
    }

    @objc private func applyTemplate(_ sender: NSMenuItem) {
        guard let template = FilterTemplates.load().first(where: { $0.name == sender.title }) else { return }
        setFilter(FileFilter(matchAll: template.matchAll, rules: template.rules))
    }

    @objc private func saveTemplate() {
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.placeholderString = "template name"
        let alert = NSAlert()
        alert.messageText = "Save the current filter as a template"
        alert.informativeText = "Saving under an existing name replaces that template."
        alert.accessoryView = field
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let name = field.stringValue.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        let current = filter()
        var list = FilterTemplates.load().filter { $0.name != name }
        list.append(FilterTemplate(name: name, matchAll: current.matchAll, rules: current.rules))
        FilterTemplates.save(list)
        rebuildTemplateMenu()
    }

    @objc private func deleteTemplate() {
        let list = FilterTemplates.load()
        guard !list.isEmpty else { return }
        let choice = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 280, height: 26), pullsDown: false)
        choice.addItems(withTitles: list.map { $0.name })
        let alert = NSAlert()
        alert.messageText = "Delete which template?"
        alert.accessoryView = choice
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn, let name = choice.titleOfSelectedItem else { return }
        FilterTemplates.save(list.filter { $0.name != name })
        rebuildTemplateMenu()
    }
}
