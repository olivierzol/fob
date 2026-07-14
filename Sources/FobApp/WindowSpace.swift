import AppKit
import SwiftUI

/// Makes a window follow you to whatever Space/display is active when it opens, instead of
/// yanking you over to the Space where it happened to be last. A menu-bar utility should
/// appear where you're working; `.moveToActiveSpace` tells macOS "bring this window to the
/// active Space" rather than "switch Spaces to reveal it".
private struct ActiveSpaceFollower: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        // The NSView isn't in a window yet during make; defer until it's attached.
        DispatchQueue.main.async { [weak view] in view?.window?.collectionBehavior.insert(.moveToActiveSpace) }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        // Re-assert on updates — SwiftUI can recreate the backing window and reset behavior.
        nsView.window?.collectionBehavior.insert(.moveToActiveSpace)
    }
}

extension View {
    /// Pin this window to the Space/display that's active when it appears.
    func followsActiveSpace() -> some View { background(ActiveSpaceFollower()) }
}
