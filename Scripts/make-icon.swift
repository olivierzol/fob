import AppKit

// Renders fob's icons with the drawn-key logo (bow ring + stem + tooth), matching
// Sources/FobApp/FobKeyGlyph.swift. Zero third-party deps — Core Graphics only.
//
//   swift make-icon.swift <appiconset-dir> [<menubar-imageset-dir>]
//
// Writes the app-icon PNGs (white key on a blue squircle) to arg1, and — if arg2 is
// given — a monochrome menu-bar template (black key on transparent) to arg2.

let appIconOut = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "fob.iconset"
let menuBarOut = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : nil
try? FileManager.default.createDirectory(atPath: appIconOut, withIntermediateDirectories: true)
if let menuBarOut { try? FileManager.default.createDirectory(atPath: menuBarOut, withIntermediateDirectories: true) }

/// Draws the key (bow ring + stem + tooth) centered in `region`, in AppKit's
/// bottom-left coordinate space. `boxH` is the key's height; proportions follow the
/// prototype's 9×14 unit box.
func drawKey(in region: CGRect, boxH: CGFloat, color: NSColor) {
    let u = boxH / 14
    let boxW = 9 * u
    let boxLeft = region.minX + (region.width - boxW) / 2
    let boxBottom = region.minY + (region.height - boxH) / 2
    let boxTop = boxBottom + boxH // top edge, measured from the bottom
    color.setFill(); color.setStroke()

    // Bow: 8u box, 2u border-box ring → stroke the 6u midline circle.
    let bow = NSBezierPath(ovalIn: CGRect(x: boxLeft + 0.5 * u, y: boxTop - 8 * u, width: 8 * u, height: 8 * u)
        .insetBy(dx: u, dy: u))
    bow.lineWidth = 2 * u
    bow.stroke()
    // Stem (bottom of the box).
    NSBezierPath(roundedRect: CGRect(x: boxLeft + 3.7 * u, y: boxBottom, width: 2 * u, height: 7 * u),
                 xRadius: u, yRadius: u).fill()
    // Tooth (right of the stem).
    NSBezierPath(roundedRect: CGRect(x: boxLeft + 5.7 * u, y: boxTop - 11.5 * u, width: 3 * u, height: 2 * u),
                 xRadius: u, yRadius: u).fill()
}

func newRep(_ px: Int) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: px, height: px)
    return rep
}

func appIconPNG(px: Int) -> Data {
    let rep = newRep(px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(px)
    let inset = s * 0.085
    let squircle = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    NSGraphicsContext.current?.saveGraphicsState()
    let bg = NSBezierPath(roundedRect: squircle, xRadius: squircle.width * 0.2237, yRadius: squircle.width * 0.2237)
    bg.addClip()
    NSGradient(starting: NSColor(srgbRed: 0.227, green: 0.608, blue: 1.0, alpha: 1),
               ending: NSColor(srgbRed: 0.039, green: 0.435, blue: 0.878, alpha: 1))!
        .draw(in: bg, angle: -90)
    NSGraphicsContext.current?.restoreGraphicsState()
    drawKey(in: squircle, boxH: squircle.height * 0.62, color: .white)
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

func menuBarPNG(px: Int) -> Data {
    let rep = newRep(px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    // Template image: black key on transparent, filling most of the frame.
    drawKey(in: CGRect(x: 0, y: 0, width: CGFloat(px), height: CGFloat(px)),
            boxH: CGFloat(px) * 0.9, color: .black)
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let appEntries: [(String, Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
for (name, px) in appEntries {
    try! appIconPNG(px: px).write(to: URL(fileURLWithPath: "\(appIconOut)/\(name).png"))
}
print("wrote \(appEntries.count) app-icon PNGs to \(appIconOut)")

if let menuBarOut {
    try! menuBarPNG(px: 16).write(to: URL(fileURLWithPath: "\(menuBarOut)/menubar.png"))
    try! menuBarPNG(px: 32).write(to: URL(fileURLWithPath: "\(menuBarOut)/menubar@2x.png"))
    print("wrote 2 menu-bar template PNGs to \(menuBarOut)")
}
