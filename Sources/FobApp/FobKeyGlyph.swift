import SwiftUI

/// The fob logo: a blue-gradient rounded square with a white key (bow ring + stem +
/// tooth), drawn to the same proportions as the app icon and notification icon.
/// `size` is the square's side in points.
struct FobKeyGlyph: View {
    var size: CGFloat = 23

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .fill(LinearGradient(
                    colors: [Color(.sRGB, red: 0.227, green: 0.608, blue: 1.0),    // #3a9bff
                             Color(.sRGB, red: 0.039, green: 0.435, blue: 0.878)],  // #0a6fe0
                    startPoint: .top, endPoint: .bottom))
                .shadow(color: Color(.sRGB, red: 0.039, green: 0.435, blue: 0.878).opacity(0.4),
                        radius: size * 0.045, y: size * 0.04)
            KeyMark()
        }
        .frame(width: size, height: size)
    }
}

/// The white key alone, centered in its frame — reused by the menu-bar template too
/// (tinted by `foregroundStyle`). Proportions come from the prototype's 9×14 unit box.
struct KeyMark: View {
    var color: Color = .white

    var body: some View {
        Canvas { ctx, size in
            let boxH = size.height * 0.62
            let u = boxH / 14
            let boxW = 9 * u
            let ox = (size.width - boxW) / 2
            let oy = (size.height - boxH) / 2
            let shading = GraphicsContext.Shading.color(color)
            // Bow: an 8u box with a 2u border-box ring → stroke the 6u midline circle.
            let bow = CGRect(x: ox + 0.5 * u, y: oy, width: 8 * u, height: 8 * u)
                .insetBy(dx: u, dy: u)
            ctx.stroke(Path(ellipseIn: bow), with: shading, lineWidth: 2 * u)
            // Stem.
            ctx.fill(Path(roundedRect: CGRect(x: ox + 3.7 * u, y: oy + 7 * u, width: 2 * u, height: 7 * u),
                          cornerRadius: u), with: shading)
            // Tooth.
            ctx.fill(Path(roundedRect: CGRect(x: ox + 5.7 * u, y: oy + 9.5 * u, width: 3 * u, height: 2 * u),
                          cornerRadius: u), with: shading)
        }
    }
}
