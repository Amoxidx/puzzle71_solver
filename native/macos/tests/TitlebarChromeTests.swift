import AppKit
import Foundation
import WebKit

@main
enum TitlebarChromeTests {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)

        let (window, root) = Puzzle71TestHooks.makeUnloadedChrome()
        defer {
            window.close()
            Puzzle71TestHooks.tearDown()
        }

        var failures = 0
        func check(_ condition: @autoclosure () -> Bool, _ message: String) {
            if !condition() {
                fputs("FAIL: \(message)\n", stderr)
                failures += 1
            }
        }

        check(window.styleMask.contains(.titled), "styleMask contains .titled")
        check(window.styleMask.contains(.closable), "styleMask contains .closable")
        check(window.styleMask.contains(.miniaturizable), "styleMask contains .miniaturizable")
        check(window.styleMask.contains(.resizable), "styleMask contains .resizable")
        check(window.styleMask.contains(.fullSizeContentView), "styleMask contains .fullSizeContentView")
        check(window.titleVisibility == .hidden, "titleVisibility is .hidden")
        check(window.titlebarAppearsTransparent, "titlebarAppearsTransparent is true")
        check(window.titlebarSeparatorStyle == .none, "titlebarSeparatorStyle is .none")

        let closeButton = window.standardWindowButton(.closeButton)
        let miniaturizeButton = window.standardWindowButton(.miniaturizeButton)
        let zoomButton = window.standardWindowButton(.zoomButton)
        check(closeButton != nil && closeButton?.isHidden == false, "close button is visible")
        check(miniaturizeButton != nil && miniaturizeButton?.isHidden == false, "miniaturize button is visible")
        check(zoomButton != nil && zoomButton?.isHidden == false, "zoom button is visible")

        root.needsLayout = true
        root.layoutSubtreeIfNeeded()

        let drag = root.dragRegion
        check(!drag.frame.isEmpty && drag.frame.width > 0 && drag.frame.height > 0, "drag region is non-empty")
        check(abs(drag.frame.maxY - root.bounds.maxY) < 0.5, "drag region occupies the top edge")
        check(drag.mouseDownCanMoveWindow, "drag region advertises mouseDownCanMoveWindow")

        if let zoomButton {
            let zoomInRoot = root.convert(zoomButton.convert(zoomButton.bounds, to: nil), from: nil)
            check(drag.frame.minX + 0.5 >= zoomInRoot.maxX, "drag region starts to the right of the traffic lights")
        } else {
            check(false, "zoom button required to locate the drag inset")
        }

        let webViews = root.subviews.compactMap { $0 as? WKWebView }
        check(webViews.count == 1, "root hosts the real WKWebView")
        check(webViews.first?.url == nil, "dashboard URL was not loaded")
        if let webView = webViews.first {
            let topGap = root.bounds.maxY - webView.frame.maxY
            check(abs(topGap) < 0.5, "WKWebView reaches the root top edge")
            let scripts = webView.configuration.userContentController.userScripts
            check(scripts.count == 1, "exactly one user script is configured")
            if let script = scripts.first {
                check(script.injectionTime == .atDocumentEnd, "user script is injected at document end")
                check(script.isForMainFrameOnly, "user script is main-frame-only")
            } else {
                check(false, "user script required to inspect injection")
            }
        } else {
            check(false, "WKWebView required to measure bounds and user scripts")
        }

        do {
            let margin = try Puzzle71TestHooks.loadCSPFixtureAndReadMargin(timeout: 5)
            check(margin == "12px", "computed .app-container margin-top is 12px, got \(margin)")
        } catch {
            check(false, "CSP fixture navigation/evaluation failed: \(error.localizedDescription)")
        }

        if failures > 0 {
            fputs("\(failures) assertion(s) failed\n", stderr)
            exit(1)
        }
        fputs("OK: titlebar chrome and drag region\n", stdout)
    }
}
