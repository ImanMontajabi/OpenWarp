// Profile: account and license, devices on the license, network identity,
// and registration deletion.

import SwiftUI

struct ProfileView: View {
    @EnvironmentObject var store: Store
    @State private var revealLicense = false
    @State private var editingLicense = false
    @State private var confirmDelete = false
    @Environment(\.owTint) private var tint

    var body: some View {
        let r = store.registration
        Page(title: "Profile") {
            if let r {
                CardSection(title: "Account") {
                    ValueRow(icon: "person.crop.circle", title: "Account type",
                             value: r.account_type == "free" ? "WARP" : "WARP+ (\(r.account_type))")
                    if r.account_type != "free" {
                        ValueRow(icon: "chart.pie", title: "WARP+ data",
                                 value: ByteCountFormatter.string(fromByteCount: r.premium_data, countStyle: .decimal))
                    }
                    ValueRow(icon: "desktopcomputer", title: "Device ID", value: r.id, mono: true, copyable: true)
                    ValueRow(icon: "key", title: "Tunnel key type",
                             value: r.key_type == "secp256r1" ? "secp256r1 (MASQUE)" : "curve25519 (WireGuard)")
                }

                CardSection(title: "License") {
                    HStack(spacing: Space.sm) {
                        Image(systemName: "key.horizontal").font(.system(size: 14, weight: .medium))
                            .foregroundStyle(Palette.textSecondary).frame(width: 20)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("License key").font(Typo.rowTitle)
                            Text(revealLicense ? r.license : masked(r.license))
                                .font(Typo.mono).foregroundStyle(Palette.textSecondary)
                                .lineLimit(1).truncationMode(.middle)
                                .textSelection(.enabled)
                                .accessibilityLabel(revealLicense ? r.license : "Hidden")
                        }
                        Spacer(minLength: Space.xs)
                        HStack(spacing: Space.xxs) {
                            Button { revealLicense.toggle() } label: {
                                Image(systemName: revealLicense ? "eye.slash" : "eye")
                                    .font(.system(size: 11, weight: .semibold)).frame(width: 22, height: 22)
                            }
                            .buttonStyle(.flat(.quiet)).foregroundStyle(Palette.textSecondary)
                            .help(revealLicense ? "Hide license key" : "Show license key")
                            .accessibilityLabel(revealLicense ? "Hide license key" : "Show license key")
                            CopyButton(value: r.license, label: "license key")
                        }
                    }
                    .padding(.horizontal, Space.md).padding(.vertical, Space.sm)
                    .frame(minHeight: Metrics.rowMinHeight)
                    Row(icon: "arrow.left.arrow.right", title: "Change license key",
                        subtitle: "Attach this device to another WARP or WARP+ account.") {
                        Button("Change") { editingLicense = true }.buttonStyle(.flat())
                    }
                }

                CardSection(title: "Devices using your license key") {
                    if !store.devicesLoaded {
                        Row(title: "Not loaded") {
                            Button("Load devices") { Task { await store.loadDevices() } }.buttonStyle(.flat())
                        }
                    } else if store.devices.isEmpty {
                        Row(title: "No devices returned")
                    }
                    ForEach(store.devices) { d in
                        let mine = d.id == r.id
                        Row(icon: icon(for: d.type), title: d.type,
                            subtitle: [d.model, d.name, d.active ? nil : "inactive"]
                                .compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: " · ")) {
                            if mine {
                                Text("This device").font(.system(size: 11, weight: .semibold))
                                    .foregroundStyle(Palette.onAccent)
                                    .padding(.horizontal, Space.xs).padding(.vertical, 3)
                                    .background(tint.accentColor, in: Capsule())
                            }
                        }
                    }
                }

                CardSection(title: "Network") {
                    ValueRow(icon: "4.circle", title: "Client Interface IPv4", value: r.interface_v4, mono: true, copyable: true)
                    ValueRow(icon: "6.circle", title: "Client Interface IPv6", value: r.interface_v6, mono: true, copyable: true)
                    if let n = store.status?.network, !n.isEmpty {
                        ValueRow(icon: "wifi", title: "Connection type", value: n)
                    }
                }

                Button { confirmDelete = true } label: {
                    Label("Delete registration", systemImage: "trash").frame(minHeight: 32)
                }
                .buttonStyle(.flat(.destructive, fullWidth: true))
                .disabled(store.busy)
                .accessibilityHint("Removes this device from Cloudflare")
            } else {
                CardSection {
                    VStack(spacing: Space.sm) {
                        Text("Not registered").font(Typo.rowTitle)
                        Text("Register this device with Cloudflare WARP to see account details.")
                            .font(Typo.caption).foregroundStyle(Palette.textSecondary).multilineTextAlignment(.center)
                        Button("Accept Terms of Service & Register") { store.act(["registration", "new", "--accept-tos"]) }
                            .buttonStyle(.flat(.primary, fullWidth: true))
                            .disabled(store.busy || store.daemonError != nil)
                    }
                    .padding(Space.md)
                }
            }
        }
        .task { if store.registration != nil && !store.devicesLoaded { await store.loadDevices() } }
        .sheet(isPresented: $editingLicense) { LicenseSheet().environmentObject(store) }
        .confirmationDialog("Delete this registration?", isPresented: $confirmDelete) {
            Button("Delete registration", role: .destructive) {
                store.act(["registration", "delete"], success: "Registration deleted.")
            }
        } message: {
            Text("This device is removed from Cloudflare and disconnected. You will need to register again to use WARP.")
        }
    }

    private func masked(_ s: String) -> String {
        guard s.count > 8 else { return String(repeating: "•", count: s.count) }
        return String(s.prefix(4)) + String(repeating: "•", count: 8) + String(s.suffix(4))
    }

    private func icon(for type: String) -> String {
        switch type.lowercased() {
        case "android", "ios": "iphone"
        case "macos", "windows", "linux", "pc": "laptopcomputer"
        default: "desktopcomputer"
        }
    }
}

private struct LicenseSheet: View {
    @EnvironmentObject var store: Store
    @Environment(\.dismiss) private var dismiss
    @State private var key = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            VStack(alignment: .leading, spacing: Space.xxs) {
                Text("Change license key").font(.system(size: 17, weight: .semibold))
                Text("Attach this device to another WARP / WARP+ account.")
                    .font(Typo.caption).foregroundStyle(Palette.textSecondary)
            }
            TextField("xxxxxxxx-xxxxxxxx-xxxxxxxx", text: $key)
                .textFieldStyle(.plain).font(Typo.mono)
                .padding(.horizontal, Space.sm).frame(height: 32)
                .background(Palette.raised.color, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                .onSubmit(apply)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(.flat()).keyboardShortcut(.cancelAction)
                Button("Apply", action: apply).buttonStyle(.flat(.primary)).keyboardShortcut(.defaultAction)
                    .disabled(key.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(Space.lg)
        .frame(width: 340)
        .background(Palette.base.color)
    }

    private func apply() {
        let k = key.trimmingCharacters(in: .whitespaces)
        guard !k.isEmpty else { return }
        store.act(["registration", "license", k], success: "License key updated.")
        dismiss()
    }
}
