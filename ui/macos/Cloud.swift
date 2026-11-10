// The interactive cloud: the Home page's connect/disconnect control.
// Flat matte shape; colour and motion follow the real daemon state.

import SwiftUI

/// Flat cloud silhouette (union of a rounded base and three circles).
struct CloudShape: Shape {
    static let aspect: CGFloat = 0.64   // height / width

    func path(in rect: CGRect) -> Path {
        let u = min(rect.width, rect.height / Self.aspect)
        let ox = rect.midX - u / 2, oy = rect.midY - u * Self.aspect / 2
        func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: ox + x * u, y: oy + y * u) }
        func circle(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat) -> CGRect {
            CGRect(x: ox + (x - r) * u, y: oy + (y - r) * u, width: 2 * r * u, height: 2 * r * u)
        }
        var p = Path()
        let base = CGRect(origin: pt(0.04, 0.36), size: CGSize(width: 0.92 * u, height: 0.28 * u))
        p.addRoundedRect(in: base, cornerSize: CGSize(width: 0.14 * u, height: 0.14 * u))
        p.addEllipse(in: circle(0.31, 0.41, 0.19))
        p.addEllipse(in: circle(0.57, 0.31, 0.27))
        p.addEllipse(in: circle(0.80, 0.47, 0.17))
        return p
    }
}

/// Visual state of the cloud, derived from the daemon status.
enum CloudLook: Equatable {
    case idle, connecting, connected, paused, error, disabled

    init(_ s: ConnState, registered: Bool) {
        guard registered else { self = .disabled; return }
        switch s {
        case .connected: self = .connected
        case .connecting: self = .connecting
        case .retrying: self = .error
        case .paused: self = .paused
        case .disconnected, .unknown: self = .idle
        }
    }

    var glyph: String {
        switch self {
        case .idle, .disabled: "power"
        case .connecting: "ellipsis"
        case .connected: "checkmark"
        case .paused: "pause.fill"
        case .error: "exclamationmark"
        }
    }
}

struct CloudButton: View {
    var look: CloudLook
    var accent: RGB
    var enabled: Bool
    var label: String
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            CloudFigure(look: look, accent: accent)
        }
        .buttonStyle(CloudPressStyle())
        .disabled(!enabled)
        .accessibilityLabel(label)
        .accessibilityIdentifier("cloud")
        .help(label)
    }
}

private struct CloudPressStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    @Environment(\.owReduceMotion) private var reduce
    @State private var hovering = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(reduce ? 1 : (configuration.isPressed ? 0.96 : (hovering && enabled ? 1.025 : 1)))
            .brightness(hovering && enabled ? 0.04 : 0)
            .opacity(enabled ? 1 : 0.55)
            .onHover { hovering = $0 }
            .animation(Motion.spring, value: configuration.isPressed)
            .animation(Motion.standard, value: hovering)
    }
}

/// Cloud + glyph + rain. Continuous motion only runs while connecting or connected.
private struct CloudFigure: View {
    var look: CloudLook
    var accent: RGB
    @Environment(\.owReduceMotion) private var reduce
    @Environment(\.owPageActive) private var pageActive

    private var animating: Bool { !reduce && pageActive && (look == .connecting || look == .connected) }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30, paused: !animating)) { ctx in
            let t = ctx.date.timeIntervalSinceReferenceDate
            VStack(spacing: 0) {
                ZStack {
                    CloudShape().fill(fill(t).color)
                    Image(systemName: look.glyph)
                        .font(.system(size: 30, weight: .bold))
                        .foregroundStyle(glyphColor)
                        .offset(y: Metrics.cloudWidth * 0.07)
                        .contentTransition(.symbolEffect(.replace))
                }
                .frame(width: Metrics.cloudWidth, height: Metrics.cloudWidth * CloudShape.aspect)
                .offset(y: look == .connecting && !reduce ? CGFloat(sin(t * 2.2)) * 2 : 0)
                .contentShape(CloudShape())

                Rain(active: look == .connected, color: accent.color, time: reduce ? nil : t)
                    .frame(width: Metrics.cloudWidth * 0.7, height: 34)
                    .allowsHitTesting(false)
            }
        }
        .motion(Motion.accent, value: look)
        .motion(Motion.accent, value: accent)
    }

    private func fill(_ t: TimeInterval) -> RGB {
        switch look {
        case .idle, .disabled: return Palette.cloudIdle
        case .connected: return accent
        case .paused: return Palette.cloudIdle.mix(accent, 0.35)
        case .error: return Palette.cloudIdle.mix(Palette.danger, 0.35)
        case .connecting:
            let wave = reduce ? 0.5 : (sin(t * 2.2) + 1) / 2
            return Palette.cloudIdle.mix(accent, 0.2 + 0.3 * wave)
        }
    }

    private var glyphColor: Color {
        switch look {
        case .connected: Palette.onAccent.opacity(0.85)
        default: Palette.text.opacity(0.85)
        }
    }
}

/// Subtle rain under the cloud. `time == nil` (Reduce Motion) draws static drops.
private struct Rain: View {
    var active: Bool
    var color: Color
    var time: TimeInterval?

    private static let columns: [(x: CGFloat, phase: Double, speed: Double)] = [
        (0.06, 0.10, 0.80), (0.20, 0.55, 0.95), (0.34, 0.30, 0.85), (0.48, 0.80, 1.00),
        (0.62, 0.15, 0.90), (0.76, 0.65, 0.82), (0.90, 0.40, 0.97),
    ]

    var body: some View {
        Canvas { gc, size in
            guard active else { return }
            for c in Self.columns {
                let progress = time.map { ($0 * c.speed * 0.9 + c.phase).truncatingRemainder(dividingBy: 1) } ?? c.phase
                let y = CGFloat(progress) * (size.height - 8)
                let x = c.x * size.width
                var p = Path()
                p.move(to: CGPoint(x: x, y: y))
                p.addLine(to: CGPoint(x: x - 1.5, y: y + 8))
                let alpha = 0.7 * (1 - progress)
                gc.stroke(p, with: .color(color.opacity(alpha)), style: StrokeStyle(lineWidth: 2.4, lineCap: .round))
            }
        }
        .opacity(active ? 1 : 0)
        .animation(Motion.accent, value: active)
        .accessibilityHidden(true)
    }
}
