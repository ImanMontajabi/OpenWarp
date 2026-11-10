// Renders the DMG window background in OpenWarp's palette (matte dark, one pastel accent):
//
//   swift scripts/dmg-background.swift assets/dmg
//
// writes background.png (640x400) and background@2x.png (1280x800). make-dmg.sh combines them into a
// HiDPI TIFF. The icon positions in make-dmg.sh (OpenWarp.app at x=170, Applications at x=470, y=190)
// must match the gap the arrow points across.
import AppKit

let size = CGSize(width: 640, height: 400)
let base = NSColor(srgbRed: 0x1B / 255, green: 0x1C / 255, blue: 0x21 / 255, alpha: 1)
let surface = NSColor(srgbRed: 0x24 / 255, green: 0x25 / 255, blue: 0x2B / 255, alpha: 1)
let peach = NSColor(srgbRed: 0xF4 / 255, green: 0xAD / 255, blue: 0x86 / 255, alpha: 1)
let text = NSColor(srgbRed: 0.91, green: 0.91, blue: 0.93, alpha: 1)
let secondary = NSColor(srgbRed: 0.64, green: 0.65, blue: 0.70, alpha: 1)

func render(scale: CGFloat) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = size
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    defer { NSGraphicsContext.restoreGraphicsState() }

    base.setFill()
    NSRect(origin: .zero, size: size).fill()

    // Finder's coordinates start at the top left; AppKit's at the bottom left.
    func y(_ top: CGFloat) -> CGFloat { size.height - top }

    // A soft panel behind the two icons.
    surface.setFill()
    NSBezierPath(roundedRect: NSRect(x: 40, y: y(300), width: 560, height: 220), xRadius: 22, yRadius: 22).fill()

    // Arrow from the app to Applications.
    let arrow = NSBezierPath()
    arrow.lineWidth = 3
    arrow.lineCapStyle = .round
    arrow.lineJoinStyle = .round
    arrow.move(to: NSPoint(x: 268, y: y(190)))
    arrow.line(to: NSPoint(x: 372, y: y(190)))
    arrow.move(to: NSPoint(x: 356, y: y(178)))
    arrow.line(to: NSPoint(x: 372, y: y(190)))
    arrow.line(to: NSPoint(x: 356, y: y(202)))
    peach.setStroke()
    arrow.stroke()

    func draw(_ s: String, font: NSFont, color: NSColor, top: CGFloat) {
        let style = NSMutableParagraphStyle()
        style.alignment = .center
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color, .paragraphStyle: style]
        let h = (s as NSString).size(withAttributes: attrs).height
        (s as NSString).draw(in: NSRect(x: 0, y: y(top) - h, width: size.width, height: h), withAttributes: attrs)
    }
    draw("Install OpenWarp", font: .systemFont(ofSize: 20, weight: .semibold), color: text, top: 26)
    draw("Drag OpenWarp into the Applications folder", font: .systemFont(ofSize: 13), color: secondary, top: 54)
    draw("Then open it from Applications. The first launch may need System Settings → Privacy & Security → Open Anyway.",
         font: .systemFont(ofSize: 11), color: secondary, top: 330)
    draw("Independent open-source client · not affiliated with Cloudflare",
         font: .systemFont(ofSize: 10), color: secondary.withAlphaComponent(0.7), top: 368)

    return rep.representation(using: .png, properties: [:])!
}

let dir = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "assets/dmg")
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
try render(scale: 1).write(to: dir.appendingPathComponent("background.png"))
try render(scale: 2).write(to: dir.appendingPathComponent("background@2x.png"))
print("wrote \(dir.path)/background.png and background@2x.png")
