// Reusable components: page scaffolding, cards, rows, toggles, selectors,
// buttons, badges, toast, list editor sheet.

import SwiftUI
import AppKit

// MARK: - Page scaffolding

/// Scrollable page with a title. Content keeps at least the viewport height
/// so spacers still work, and scrolls when the window is short.
struct Page<Content: View>: View {
    var title: String?
    var centered = false
    @ViewBuilder var content: Content

    var body: some View {
        GeometryReader { geo in
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: Space.lg) {
                    if let title {
                        Text(title).font(Typo.pageTitle).foregroundStyle(Palette.text)
                            .accessibilityAddTraits(.isHeader)
                            .accessibilityIdentifier("page.title")
                    }
                    content
                }
                .padding(.horizontal, Space.lg)
                .padding(.top, Space.xs)
                .padding(.bottom, Space.xl)
                .frame(maxWidth: .infinity, minHeight: geo.size.height, alignment: centered ? .center : .top)
            }
            .scrollIndicators(.automatic)
            .accessibilityIdentifier("page.scroll")
        }
    }
}

/// A titled group of rows.
struct CardSection<Content: View>: View {
    var title: String?
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            if let title {
                Text(title.uppercased()).font(Typo.sectionHeader).tracking(0.6)
                    .foregroundStyle(Palette.textTertiary).padding(.leading, Space.xxs)
                    .accessibilityAddTraits(.isHeader)
            }
            Card { content }
        }
    }
}

/// Flat rounded surface; rows inside are separated by hairlines.
struct Card<Content: View>: View {
    @Environment(\.owTint) private var tint
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) {
            _VariadicView.Tree(DividedLayout()) { content }
        }
        .background(tint.surface, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
    }
}

private struct DividedLayout: _VariadicView_MultiViewRoot {
    func body(children: _VariadicView.Children) -> some View {
        let last = children.last?.id
        ForEach(children) { child in
            child
            if child.id != last {
                Rectangle().fill(Palette.hairline).frame(height: 1).padding(.leading, Space.md)
            }
        }
    }
}

// MARK: - Rows

/// Standard row: optional icon, title and subtitle on the left, trailing accessory.
struct Row<Trailing: View>: View {
    var icon: String?
    var title: String
    var subtitle: String?
    @ViewBuilder var trailing: Trailing

    init(icon: String? = nil, title: String, subtitle: String? = nil, @ViewBuilder trailing: () -> Trailing) {
        self.icon = icon; self.title = title; self.subtitle = subtitle; self.trailing = trailing()
    }

    var body: some View {
        HStack(alignment: .center, spacing: Space.sm) {
            if let icon {
                Image(systemName: icon).font(.system(size: 14, weight: .medium))
                    .foregroundStyle(Palette.textSecondary).frame(width: 20)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(Typo.rowTitle).foregroundStyle(Palette.text)
                    .fixedSize(horizontal: false, vertical: true)
                if let subtitle {
                    Text(subtitle).font(Typo.caption).foregroundStyle(Palette.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .layoutPriority(1)
            .accessibilityElement(children: .combine)
            Spacer(minLength: Space.xs)
            trailing
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(minHeight: Metrics.rowMinHeight)
        // Not .combine: that folds the trailing toggle or button into one element spanning the whole row,
        // so it loses its own identity and a click on the element's centre lands on the text.
        .accessibilityElement(children: .contain)
    }
}

extension Row where Trailing == EmptyView {
    init(icon: String? = nil, title: String, subtitle: String? = nil) {
        self.init(icon: icon, title: title, subtitle: subtitle) { EmptyView() }
    }
}

/// Read-only value row. Short values sit on the right; long ones (IPv6,
/// device IDs) move under the title so they never truncate in a narrow window.
struct ValueRow: View {
    var icon: String?
    var title: String
    var value: String?
    var mono = false
    var copyable = false

    private var stacked: Bool { title.count + (value?.count ?? 0) > 30 }

    var body: some View {
        HStack(alignment: .center, spacing: Space.sm) {
            if let icon {
                Image(systemName: icon).font(.system(size: 14, weight: .medium))
                    .foregroundStyle(Palette.textSecondary).frame(width: 20)
                    .accessibilityHidden(true)
            }
            if stacked {
                // Value gets the full row width; the copy button sits beside the title.
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: Space.xs) {
                        titleText
                        Spacer(minLength: 0)
                        if copyable, let value { CopyButton(value: value, label: title) }
                    }
                    valueText.lineLimit(1).minimumScaleFactor(0.8).truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                titleText.fixedSize()
                Spacer(minLength: Space.xs)
                valueText.lineLimit(1).truncationMode(.middle).layoutPriority(1)
                if copyable, let value { CopyButton(value: value, label: title) }
            }
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(minHeight: Metrics.rowMinHeight)
        // Explicit label and value: .combine dropped the (selectable) value and kept only the copy button.
        .accessibilityElement(children: .ignore)
        .accessibilityAddTraits(.isStaticText)   // a plain group exposes no value on macOS
        .accessibilityLabel(title)
        .accessibilityValue(value ?? "Unknown")
        .accessibilityIdentifier("value.\(title)")
        .modifier(CopyAction(value: copyable ? value : nil, label: title))
    }

    private var titleText: some View {
        Text(title).font(Typo.rowTitle).foregroundStyle(Palette.text)
    }

    private var valueText: some View {
        Text(value ?? "—")
            .font(mono ? Typo.mono : Typo.rowValue)
            .foregroundStyle(value == nil ? Palette.textTertiary : Palette.textSecondary)
            .textSelection(.enabled)
            .help(value ?? "")
    }
}

/// Adds a "Copy <label>" accessibility action when there is a value to copy.
private struct CopyAction: ViewModifier {
    var value: String?
    var label: String
    func body(content: Content) -> some View {
        if let value {
            content.accessibilityAction(named: "Copy \(label)") { Clipboard.copy(value) }
        } else {
            content
        }
    }
}

enum Clipboard {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

// MARK: - Buttons

enum ButtonKind { case primary, secondary, destructive, quiet }

struct FlatButtonStyle: ButtonStyle {
    var kind: ButtonKind = .secondary
    var fullWidth = false
    @Environment(\.owTint) private var tint
    @Environment(\.isEnabled) private var enabled
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12.5, weight: .semibold))
            .lineLimit(1)
            .fixedSize(horizontal: !fullWidth, vertical: false)
            .foregroundStyle(foreground)
            .padding(.horizontal, Space.sm)
            .padding(.vertical, 6)
            .frame(maxWidth: fullWidth ? .infinity : nil, minHeight: 28)
            .background(background(configuration.isPressed), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .opacity(enabled ? 1 : 0.45)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .contentShape(RoundedRectangle(cornerRadius: Radius.sm))
            .onHover { hovering = $0 }
            .animation(Motion.quick, value: configuration.isPressed)
            .animation(Motion.quick, value: hovering)
    }

    private var foreground: Color {
        switch kind {
        case .primary: Palette.onAccent
        case .destructive: Palette.danger.color
        case .secondary, .quiet: Palette.text
        }
    }

    private func background(_ pressed: Bool) -> Color {
        let lift = (hovering && enabled ? 0.06 : 0) + (pressed ? 0.04 : 0)
        switch kind {
        case .primary: return tint.accent.mix(RGB(0xFFFFFF), lift).color
        case .destructive: return Palette.danger.color.opacity(0.14 + lift)
        case .secondary: return Palette.hover.mix(RGB(0xFFFFFF), lift).color
        case .quiet: return Color.white.opacity(hovering ? 0.06 : 0)
        }
    }
}

extension ButtonStyle where Self == FlatButtonStyle {
    static func flat(_ kind: ButtonKind = .secondary, fullWidth: Bool = false) -> FlatButtonStyle {
        FlatButtonStyle(kind: kind, fullWidth: fullWidth)
    }
}

/// Small icon button that copies a value and confirms with a checkmark.
struct CopyButton: View {
    var value: String
    var label: String
    @State private var copied = false
    var body: some View {
        Button {
            Clipboard.copy(value)
            copied = true
            Task { try? await Task.sleep(nanoseconds: 1_400_000_000); copied = false }
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .font(.system(size: 11, weight: .semibold))
                .frame(width: 22, height: 22)
                .contentTransition(.symbolEffect(.replace))
        }
        .buttonStyle(.flat(.quiet))
        .foregroundStyle(copied ? Palette.success.color : Palette.textSecondary)
        .help("Copy \(label)")
        .accessibilityLabel("Copy \(label)")
    }
}

// MARK: - Toggle

/// Flat pill switch; the "on" track uses the current mode accent.
struct PillToggleStyle: ToggleStyle {
    @Environment(\.owTint) private var tint
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: Space.sm) {
                configuration.label
                ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                    Capsule().fill(configuration.isOn ? tint.accentColor : Palette.hover.color)
                    Circle().fill(configuration.isOn ? Palette.onAccent : Palette.textSecondary)
                        .frame(width: 14, height: 14).padding(3)
                }
                .frame(width: 36, height: 20)
                .motion(Motion.spring, value: configuration.isOn)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .opacity(enabled ? 1 : 0.45)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}

// MARK: - Segmented selector

struct Segmented<T: Hashable>: View {
    var options: [(T, String)]
    var selection: T
    var onSelect: (T) -> Void
    @Environment(\.owTint) private var tint
    @Namespace private var ns

    var body: some View {
        HStack(spacing: 2) {
            ForEach(options, id: \.0) { value, label in
                let on = value == selection
                Button { if !on { onSelect(value) } } label: {
                    Text(label).font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(on ? Palette.onAccent : Palette.textSecondary)
                        .frame(maxWidth: .infinity, minHeight: 26)
                        .background {
                            if on {
                                RoundedRectangle(cornerRadius: 6, style: .continuous).fill(tint.accentColor)
                                    .matchedGeometryEffect(id: "seg", in: ns)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? .isSelected : [])
                .accessibilityIdentifier("segment.\(value)")
            }
        }
        .padding(2)
        .background(Palette.hover.color.opacity(0.6), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .motion(Motion.spring, value: selection)
    }
}

// MARK: - Accordion reveal

/// Expands/collapses its content by animating a measured height inside a clip,
/// so the card and everything below move together with the content (no overlap).
/// Toggle `open` inside `withAnimation` (see `Accordion.toggle`).
struct Reveal<Content: View>: View {
    var open: Bool
    @ViewBuilder var content: Content
    @State private var height: CGFloat = 0

    var body: some View {
        content
            .fixedSize(horizontal: false, vertical: true)
            .background(GeometryReader { g in
                Color.clear.preference(key: RevealHeightKey.self, value: g.size.height)
            })
            .onPreferenceChange(RevealHeightKey.self) { height = $0 }
            .frame(height: open ? height : 0, alignment: .top)
            .clipped()
            .opacity(open ? 1 : 0)
            .allowsHitTesting(open)
            .accessibilityHidden(!open)
    }
}

private struct RevealHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

enum Accordion {
    /// One animation transaction for the whole layout; instant with Reduce Motion.
    static func toggle(_ open: Binding<Bool>, reduceMotion: Bool) {
        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.28)) { open.wrappedValue.toggle() }
    }
}

// MARK: - Expandable single-choice row

/// Row that expands inline into a list of options (used instead of a dropdown).
struct ChoiceRow: View {
    var icon: String?
    var title: String
    var options: [(String, String)]
    var selection: String
    var onSelect: (String) -> Void
    @State private var open = false
    @Environment(\.owTint) private var tint
    @Environment(\.owReduceMotion) private var reduce

    var body: some View {
        VStack(spacing: 0) {
            Button { Accordion.toggle($open, reduceMotion: reduce) } label: {
                Row(icon: icon, title: title) {
                    HStack(spacing: 6) {
                        Text(options.first { $0.0 == selection }?.1 ?? selection)
                            .font(Typo.rowValue).foregroundStyle(Palette.textSecondary).lineLimit(1)
                        Image(systemName: "chevron.down").font(.system(size: 10, weight: .bold))
                            .foregroundStyle(Palette.textTertiary)
                            .rotationEffect(.degrees(open ? 180 : 0))
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityHint(open ? "Collapse options" : "Show options")
            .accessibilityIdentifier("choice.\(title)")

            Reveal(open: open) {
                VStack(spacing: 2) {
                    ForEach(options, id: \.0) { value, label in
                        let on = value == selection
                        Button {
                            onSelect(value)
                            Accordion.toggle($open, reduceMotion: reduce)
                        } label: {
                            HStack {
                                Text(label).font(Typo.body).foregroundStyle(on ? Palette.text : Palette.textSecondary)
                                Spacer()
                                if on { Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(tint.accentColor) }
                            }
                            .padding(.horizontal, Space.sm).padding(.vertical, Space.xs)
                            .background(on ? tint.soft : .clear, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(on ? .isSelected : [])
                        .accessibilityIdentifier("choice.option.\(value)")
                    }
                }
                .padding(.horizontal, Space.xs).padding(.bottom, Space.xs)
            }
        }
    }
}

// MARK: - Disclosure section

/// Collapsible card section (used for Advanced settings).
struct DisclosureSection<Content: View>: View {
    var title: String
    @ViewBuilder var content: Content
    @State private var open = false
    @Environment(\.owReduceMotion) private var reduce
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button { Accordion.toggle($open, reduceMotion: reduce) } label: {
                HStack(spacing: 6) {
                    Text(title.uppercased()).font(Typo.sectionHeader).tracking(0.6)
                    Image(systemName: "chevron.right").font(.system(size: 9, weight: .bold))
                        .rotationEffect(.degrees(open ? 90 : 0))
                    Spacer()
                }
                .foregroundStyle(Palette.textTertiary).padding(.leading, Space.xxs)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(.isHeader)
            .accessibilityHint(open ? "Collapse" : "Expand")
            Reveal(open: open) {
                Card { content }.padding(.top, Space.xs)
            }
        }
    }
}

// MARK: - Status badge

struct StatusBadge: View {
    var state: ConnState
    var label: String
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(label).font(.system(size: 11.5, weight: .semibold))
        }
        .foregroundStyle(color)
        .padding(.horizontal, Space.xs).padding(.vertical, 4)
        .background(color.opacity(0.14), in: Capsule())
        .motion(Motion.standard, value: state)
    }
    var color: Color {
        switch state {
        case .connected: Palette.success.color
        case .connecting: Palette.warning.color
        case .paused: Palette.warning.color
        case .retrying, .disconnected: Palette.danger.color
        case .unknown: Palette.textTertiary
        }
    }
}

// MARK: - Toast

struct ToastBanner: View {
    var toast: Toast
    var dismiss: () -> Void
    var body: some View {
        let c = toast.kind == .error ? Palette.danger : Palette.success
        HStack(alignment: .top, spacing: Space.xs) {
            Image(systemName: toast.kind == .error ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(c.color)
            Text(toast.text).font(Typo.caption).foregroundStyle(Palette.text)
                .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                .accessibilityIdentifier("toast.text")
            Spacer(minLength: 0)
            Button(action: dismiss) {
                Image(systemName: "xmark").font(.system(size: 9, weight: .bold)).frame(width: 18, height: 18)
            }
            .buttonStyle(.flat(.quiet)).foregroundStyle(Palette.textSecondary)
            .accessibilityLabel("Dismiss")
        }
        .padding(Space.sm)
        .background(Palette.raised.mix(c, 0.10).color, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous).strokeBorder(c.color.opacity(0.25)))
        // A container, not a combined element: combining folds the message into the
        // Dismiss button, and assistive technology then reads only "Dismiss".
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(toast.kind == .error ? "toast.error" : "toast.success")
    }
}

// MARK: - List editor sheet

/// Sheet for editing a list setting (trusted SSIDs, split tunnel, fallback domains).
struct ListEditorSheet<Header: View>: View {
    var title: String
    var help: String
    var placeholder: String
    var items: [String]
    var add: (String) -> Void
    var remove: (String) -> Void
    var reset: () -> Void
    @ViewBuilder var header: Header
    @Environment(\.dismiss) private var dismiss
    @Environment(\.owTint) private var tint
    @State private var draft = ""
    @State private var confirmReset = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            VStack(alignment: .leading, spacing: Space.xxs) {
                Text(title).font(.system(size: 17, weight: .semibold)).foregroundStyle(Palette.text)
                Text(help).font(Typo.caption).foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            header
            HStack(spacing: Space.xs) {
                TextField(placeholder, text: $draft)
                    .textFieldStyle(.plain).font(Typo.body)
                    .padding(.horizontal, Space.sm).frame(height: 30)
                    .background(Palette.raised.color, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                    .onSubmit(commit)
                Button("Add", action: commit).buttonStyle(.flat(.primary))
                    .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    if items.isEmpty {
                        Text("No entries").font(Typo.caption).foregroundStyle(Palette.textTertiary)
                            .frame(maxWidth: .infinity).padding(Space.lg)
                    }
                    ForEach(items, id: \.self) { item in
                        HStack {
                            Text(item).font(Typo.mono).foregroundStyle(Palette.text)
                                .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            Spacer()
                            Button { remove(item) } label: {
                                Image(systemName: "minus.circle").frame(width: 22, height: 22)
                            }
                            .buttonStyle(.flat(.quiet)).foregroundStyle(Palette.danger.color)
                            .accessibilityLabel("Remove \(item)")
                        }
                        .padding(.horizontal, Space.sm).padding(.vertical, 6)
                        Rectangle().fill(Palette.hairline).frame(height: 1)
                    }
                }
            }
            .background(Palette.surface.color, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .clipShape(RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            HStack {
                Button("Restore defaults") { confirmReset = true }.buttonStyle(.flat(.secondary))
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(.flat(.primary)).keyboardShortcut(.defaultAction)
            }
        }
        .padding(Space.lg)
        .frame(width: 340, height: 500)
        .background(Palette.base.color)
        .confirmationDialog("Restore the default \(title.lowercased()) list?", isPresented: $confirmReset) {
            Button("Restore defaults", role: .destructive, action: reset)
        }
    }

    private func commit() {
        let d = draft.trimmingCharacters(in: .whitespaces)
        if !d.isEmpty { add(d) }
        draft = ""
    }
}

extension ListEditorSheet where Header == EmptyView {
    init(title: String, help: String, placeholder: String, items: [String],
         add: @escaping (String) -> Void, remove: @escaping (String) -> Void, reset: @escaping () -> Void) {
        self.init(title: title, help: help, placeholder: placeholder, items: items,
                  add: add, remove: remove, reset: reset) { EmptyView() }
    }
}

func human(_ n: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary) }
