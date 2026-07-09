import AppKit

// Renders the fob app icon (a white key on a blue squircle, matching the menu-bar
// glyph) into an .iconset directory. Zero third-party deps — Core Graphics + the
// system SF Symbol. Usage: swift make-icon.swift <output.iconset-dir>

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "fob.iconset"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

func renderPNG(px: Int) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: px, height: px)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(px)

    // Rounded-rect ("squircle") background with a vertical blue gradient.
    let inset = s * 0.085
    let rect = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let bg = NSBezierPath(roundedRect: rect, xRadius: rect.width * 0.2237, yRadius: rect.width * 0.2237)
    bg.addClip()
    let gradient = NSGradient(
        starting: NSColor(srgbRed: 0.38, green: 0.56, blue: 1.00, alpha: 1),
        ending:   NSColor(srgbRed: 0.11, green: 0.31, blue: 0.85, alpha: 1))!
    gradient.draw(in: bg, angle: -90)

    // Centered white key glyph.
    let config = NSImage.SymbolConfiguration(pointSize: s * 0.52, weight: .semibold)
        .applying(NSImage.SymbolConfiguration(paletteColors: [.white]))
    if let sym = NSImage(systemSymbolName: "key.fill", accessibilityDescription: nil)?
        .withSymbolConfiguration(config) {
        let sz = sym.size
        sym.draw(at: NSPoint(x: (s - sz.width) / 2, y: (s - sz.height) / 2),
                 from: .zero, operation: .sourceOver, fraction: 1)
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let entries: [(String, Int)] = [
    ("icon_16x16", 16),   ("icon_16x16@2x", 32),
    ("icon_32x32", 32),   ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
for (name, px) in entries {
    try! renderPNG(px: px).write(to: URL(fileURLWithPath: "\(out)/\(name).png"))
}
print("wrote \(entries.count) PNGs to \(out)")
