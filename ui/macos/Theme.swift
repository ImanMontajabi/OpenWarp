// Design tokens: palette, mode accents, spacing, radii, typography, motion.
// Dark, matte, muted pastels (Catppuccin-inspired, no purple, no glow).

import SwiftUI
import AppKit

// MARK: - Colour helpers

struct RGB: Equatable {
    var r: Double, g: Double, b: Double
    init(_ hex: UInt32) {
        r = Double((hex >> 16) & 0xFF) / 255
        g = Double((hex >> 8) & 0xFF) / 255
        b = Double(hex & 0xFF) / 255
    }
    init(r: Double, g: Double, b: Double) { self.r = r; self.g = g; self.b = b }
    var color: Color { Color(.sRGB, red: r, green: g, blue: b, opacity: 1) }
    var nsColor: NSColor { NSColor(srgbRed: r, green: g, blue: b, alpha: 1) }
    /// Linear blend toward `other` by `t` (0…1).
    func mix(_ other: RGB, _ t: Double) -> RGB {
        RGB(r: r + (other.r - r) * t, g: g + (other.g - g) * t, b: b + (other.b - b) * t)
    }
}

// MARK: - Palette

enum Palette {
    static let base = RGB(0x1B1C21)       // window background (uniform, incl. title area)
    static let surface = RGB(0x24252B)    // cards
    static let raised = RGB(0x2E2F36)     // controls, idle tiles
    static let hover = RGB(0x373840)
    static let cloudIdle = RGB(0x4B4D57)

    static let text = Color(red: 0.91, green: 0.91, blue: 0.93)
    static let textSecondary = Color(red: 0.64, green: 0.65, blue: 0.70)
    static let textTertiary = Color(red: 0.45, green: 0.46, blue: 0.51)
    static let onAccent = Color(red: 0.11, green: 0.11, blue: 0.13) // dark text on pastel fills
    static let hairline = Color.white.opacity(0.06)

    static let danger = RGB(0xE8898C)
    static let success = RGB(0xA6D99B)
    static let warning = RGB(0xEED49F)
}

// MARK: - Connection modes (the seven real daemon modes)

struct ModeInfo: Identifiable {
    let id: String          // daemon mode id (openwarp mode <id>)
    let title: String       // short tile title
    let detail: String      // protocol caption
    let fullName: String    // label used by the official client / CLI
    let icon: String        // SF Symbol
    let accent: RGB

    static let all: [ModeInfo] = [
        .init(id: "warp", title: "Traffic and DNS", detail: "UDP", fullName: "Traffic and DNS (UDP)",
              icon: "square.stack.3d.up", accent: RGB(0xF4AD86)),        // peach
        .init(id: "warp+doh", title: "Traffic and DNS", detail: "HTTPS", fullName: "Traffic and DNS (HTTPS)",
              icon: "square.stack.3d.up", accent: RGB(0xA6D99B)),        // green
        .init(id: "warp+dot", title: "Traffic and DNS", detail: "TLS", fullName: "Traffic and DNS (TLS)",
              icon: "square.stack.3d.up", accent: RGB(0x8FD3C6)),        // teal
        .init(id: "doh", title: "DNS only", detail: "HTTPS", fullName: "DNS only (HTTPS)",
              icon: "shield", accent: RGB(0x8DB2EE)),                    // blue
        .init(id: "dot", title: "DNS only", detail: "TLS", fullName: "DNS only (TLS)",
              icon: "shield", accent: RGB(0xEDD39C)),                    // yellow
        .init(id: "tunnel_only", title: "Traffic only", detail: "No DNS", fullName: "Traffic only",
              icon: "arrow.up.arrow.down", accent: RGB(0xEEA0A6)),       // rose
        .init(id: "proxy", title: "Local proxy", detail: "SOCKS5 / HTTP", fullName: "Local proxy (SOCKS5/HTTP)",
              icon: "network", accent: RGB(0xBFC8D8)),                   // slate
    ]

    static func find(_ id: String) -> ModeInfo { all.first { $0.id == id } ?? all[0] }
}

// MARK: - Layout tokens

enum Space {
    static let xxs: CGFloat = 4
    static let xs: CGFloat = 8
    static let sm: CGFloat = 12
    static let md: CGFloat = 16
    static let lg: CGFloat = 20
    static let xl: CGFloat = 24
    static let xxl: CGFloat = 32
}

enum Radius {
    static let sm: CGFloat = 8
    static let md: CGFloat = 12
    static let lg: CGFloat = 16
}

enum Metrics {
    static let windowWidth: CGFloat = 380
    static let windowHeight: CGFloat = 760
    static let minWidth: CGFloat = 360
    static let minHeight: CGFloat = 620
    static let maxWidth: CGFloat = 460       // keeps the portrait panel proportions
    static let titleBarHeight: CGFloat = 32
    static let trafficLightInset: CGFloat = 78   // clears the native window buttons
    static let rowMinHeight: CGFloat = 44
    static let navHeight: CGFloat = 56
    static let tileHeight: CGFloat = 76
    static let cloudWidth: CGFloat = 156
}

// MARK: - Typography

enum Typo {
    static let pageTitle = Font.system(size: 22, weight: .semibold)
    static let sectionHeader = Font.system(size: 12, weight: .semibold)
    static let rowTitle = Font.system(size: 13, weight: .medium)
    static let rowValue = Font.system(size: 13)
    static let caption = Font.system(size: 11.5)
    static let mono = Font.system(size: 12, design: .monospaced)
    static let statusTitle = Font.system(size: 26, weight: .semibold)
    static let body = Font.system(size: 13)
    static let navLabel = Font.system(size: 10.5, weight: .medium)
}

// MARK: - Motion

enum Motion {
    static let quick = Animation.easeOut(duration: 0.18)
    static let standard = Animation.easeInOut(duration: 0.25)
    static let accent = Animation.easeInOut(duration: 0.35)
    static let spring = Animation.spring(response: 0.3, dampingFraction: 0.85)
}

extension View {
    /// Applies `animation` unless Reduce Motion is on.
    func motion<V: Equatable>(_ animation: Animation, value: V) -> some View {
        modifier(MotionModifier(animation: animation, value: value))
    }
}

private struct MotionModifier<V: Equatable>: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduce
    var animation: Animation
    var value: V
    func body(content: Content) -> some View {
        content.animation(reduce ? .linear(duration: 0.12) : animation, value: value)
    }
}

// MARK: - Contextual theme (derived from mode + connection state)

/// Colours that follow the selected mode. Selection shows the accent on
/// selected controls; only a real connection tints surfaces and the cloud.
struct Tint: Equatable {
    var accent: RGB
    var engaged: Bool   // true only when the daemon reports Connected

    var accentColor: Color { accent.color }
    var background: Color { (engaged ? Palette.base.mix(accent, 0.045) : Palette.base).color }
    var surface: Color { (engaged ? Palette.surface.mix(accent, 0.05) : Palette.surface).color }
    var raised: Color { (engaged ? Palette.raised.mix(accent, 0.06) : Palette.raised).color }
    var soft: Color { accent.color.opacity(0.16) }
}

private struct TintKey: EnvironmentKey {
    static let defaultValue = Tint(accent: ModeInfo.all[0].accent, engaged: false)
}

extension EnvironmentValues {
    var owTint: Tint {
        get { self[TintKey.self] }
        set { self[TintKey.self] = newValue }
    }
}
