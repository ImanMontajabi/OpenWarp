// About: minimal branding, protocols, legal links, disclaimer, bundle version.

import SwiftUI

struct AboutView: View {
    @Environment(\.owTint) private var tint
    private var version: String? {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    }

    var body: some View {
        Page(centered: true) {
            VStack(spacing: Space.xs) {
                CloudShape().fill(tint.accentColor)
                    .frame(width: 64, height: 64 * CloudShape.aspect)
                    .padding(.bottom, Space.xs)
                    .accessibilityHidden(true)
                Text("OpenWarp").font(.system(size: 22, weight: .semibold))
                Text("An open client for the Cloudflare WARP network.")
                    .font(Typo.body).foregroundStyle(Palette.textSecondary).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.bottom, Space.xs)

            CardSection {
                Row(icon: "square.stack.3d.up", title: "Protocols", subtitle: "MASQUE (HTTP/3 CONNECT-IP) and WireGuard")
                LinkRow(icon: "doc.text", title: "Cloudflare WARP Terms of Service",
                        url: "https://www.cloudflare.com/application/terms/")
                LinkRow(icon: "hand.raised", title: "Privacy policy",
                        url: "https://www.cloudflare.com/application/privacypolicy/")
            }

            VStack(spacing: Space.xxs) {
                Text("Not affiliated with or endorsed by Cloudflare.")
                if let version { Text("Version \(version)") }
            }
            .font(Typo.caption).foregroundStyle(Palette.textTertiary)
            .frame(maxWidth: .infinity)
        }
    }
}

private struct LinkRow: View {
    var icon: String
    var title: String
    var url: String
    var body: some View {
        Link(destination: URL(string: url)!) {
            Row(icon: icon, title: title) {
                Image(systemName: "arrow.up.right").font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Palette.textTertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHint("Opens in your browser")
    }
}
