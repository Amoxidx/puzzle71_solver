import AppKit
import WebKit

#if !PUZZLE71_TESTING
@main
#endif
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var dashboard: DashboardSession?

    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        withExtendedLifetime(delegate) {
            app.run()
        }
    }

    func applicationDidFinishLaunching(_ _: Notification) {
        installMainMenu()
        let session = DashboardSession()
        dashboard = session
        session.show()
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ _: NSApplication) -> Bool {
        true
    }

    func applicationSupportsSecureRestorableState(_ _: NSApplication) -> Bool {
        true
    }

    private func installMainMenu() {
        let appName = "Puzzle #71 Solver"
        let mainMenu = NSMenu()

        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(
            withTitle: "\(appName) ausblenden",
            action: #selector(NSApplication.hide(_:)),
            keyEquivalent: "h"
        )
        let hideOthers = NSMenuItem(
            title: "Andere ausblenden",
            action: #selector(NSApplication.hideOtherApplications(_:)),
            keyEquivalent: "h"
        )
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(hideOthers)
        appMenu.addItem(withTitle: "Alle einblenden", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(
            withTitle: "\(appName) beenden",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        appItem.submenu = appMenu
        mainMenu.addItem(appItem)

        let fileItem = NSMenuItem()
        let fileMenu = NSMenu(title: "Ablage")
        fileMenu.addItem(withTitle: "Schließen", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        fileItem.submenu = fileMenu
        mainMenu.addItem(fileItem)

        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: "Bearbeiten")
        editMenu.addItem(withTitle: "Widerrufen", action: Selector(("undo:")), keyEquivalent: "z")
        let redo = NSMenuItem(title: "Wiederholen", action: Selector(("redo:")), keyEquivalent: "z")
        redo.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(redo)
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(withTitle: "Ausschneiden", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Kopieren", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Einsetzen", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Alles auswählen", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        mainMenu.addItem(editItem)

        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Fenster")
        windowMenu.addItem(withTitle: "Im Dock ablegen", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoomen", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windowMenu.addItem(
            withTitle: "Vollbild",
            action: #selector(NSWindow.toggleFullScreen(_:)),
            keyEquivalent: "f"
        )
        windowMenu.items.last?.keyEquivalentModifierMask = [.command, .control]
        windowMenu.addItem(NSMenuItem.separator())
        windowMenu.addItem(
            withTitle: "Alle nach vorne bringen",
            action: #selector(NSApplication.arrangeInFront(_:)),
            keyEquivalent: ""
        )
        windowItem.submenu = windowMenu
        mainMenu.addItem(windowItem)

        NSApp.mainMenu = mainMenu
        NSApp.windowsMenu = windowMenu
    }
}

private enum Puzzle71Chrome {
    static let contentTopSpacing: CGFloat = 12

    static var contentSpacingUserScript: WKUserScript {
        let pixels = Int(contentTopSpacing)
        let source = """
        (function() {
          var el = document.querySelector(".app-container");
          if (!el || !el.style || typeof el.style.setProperty !== "function") return;
          el.style.setProperty("margin-top", "\(pixels)px", "important");
        })();
        """
        return WKUserScript(source: source, injectionTime: .atDocumentEnd, forMainFrameOnly: true)
    }
}

final class TitlebarDragView: NSView {
    override var isOpaque: Bool { false }
    override var mouseDownCanMoveWindow: Bool { true }
    override var acceptsFirstResponder: Bool { false }

    override func acceptsFirstMouse(for _: NSEvent?) -> Bool {
        true
    }

    override func mouseDown(with event: NSEvent) {
        window?.performDrag(with: event)
    }
}

final class DashboardRootView: NSView {
    let dragRegion = TitlebarDragView()

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        addSubview(dragRegion)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) is not used")
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        needsLayout = true
    }

    override func layout() {
        super.layout()
        layoutDragRegion()
    }

    private func layoutDragRegion() {
        guard let window else {
            dragRegion.frame = .zero
            return
        }

        if window.styleMask.contains(.fullScreen) {
            dragRegion.frame = .zero
            return
        }

        var excluded = NSRect.null
        for buttonType: NSWindow.ButtonType in [.closeButton, .miniaturizeButton, .zoomButton] {
            guard let button = window.standardWindowButton(buttonType), !button.isHidden else { continue }
            let inRoot = convert(button.convert(button.bounds, to: nil), from: nil)
            guard inRoot.origin.x.isFinite, inRoot.origin.y.isFinite,
                  inRoot.size.width.isFinite, inRoot.size.height.isFinite,
                  inRoot.width > 0, inRoot.height > 0
            else { continue }
            excluded = excluded.union(inRoot)
        }
        let hasVisibleButtons = !excluded.isNull && excluded.width > 0 && excluded.height > 0

        let layoutRect = convert(window.contentLayoutRect, from: nil)
        var fromLayout = bounds.maxY - layoutRect.maxY
        if !fromLayout.isFinite {
            fromLayout = 0
        }
        fromLayout = max(0, fromLayout)

        let titlebarHeight: CGFloat
        if hasVisibleButtons {
            titlebarHeight = max(fromLayout, 28)
        } else {
            titlebarHeight = fromLayout
        }
        guard titlebarHeight.isFinite, titlebarHeight > 1 else {
            dragRegion.frame = .zero
            return
        }

        var x = bounds.minX
        if hasVisibleButtons {
            x = excluded.maxX + 8
        }
        x = max(bounds.minX, x)
        let maxX = bounds.maxX
        let width = maxX - x
        let y = bounds.maxY - titlebarHeight
        let proposed = NSRect(x: x, y: y, width: width, height: titlebarHeight)
        let clamped = proposed.intersection(bounds)
        guard clamped.origin.x.isFinite, clamped.origin.y.isFinite,
              clamped.size.width.isFinite, clamped.size.height.isFinite,
              clamped.width > 0, clamped.height > 0
        else {
            dragRegion.frame = .zero
            return
        }
        dragRegion.frame = clamped
    }
}

private final class DashboardSession: NSObject, WKNavigationDelegate, WKUIDelegate {
    private static let dashboardURL = URL(string: "http://127.0.0.1:8080")!
    private static let dashboardHost = "127.0.0.1"
    private static let dashboardPort = 8080
    private static let backgroundColor = NSColor(srgbRed: 10.0 / 255.0, green: 10.0 / 255.0, blue: 11.0 / 255.0, alpha: 1)
    private static let preferredContentSize = NSSize(width: 900, height: 1400)

    fileprivate let window: NSWindow
    private let webView: WKWebView
    fileprivate let root: DashboardRootView
    #if PUZZLE71_TESTING
    fileprivate var testNavigationResult: Result<Void, Error>?
    #endif

    override init() {
        let root = DashboardRootView(frame: .zero)
        root.wantsLayer = true
        root.layer?.backgroundColor = Self.backgroundColor.cgColor

        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        configuration.userContentController.addUserScript(Puzzle71Chrome.contentSpacingUserScript)

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.allowsBackForwardNavigationGestures = false
        webView.allowsMagnification = true
        webView.allowsLinkPreview = false
        webView.underPageBackgroundColor = Self.backgroundColor
        webView.wantsLayer = true
        webView.layer?.backgroundColor = Self.backgroundColor.cgColor
        webView.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(webView, positioned: .below, relativeTo: root.dragRegion)
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: root.topAnchor),
            webView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: root.bottomAnchor),
        ])

        let window = NSWindow(
            contentRect: Self.initialContentRect(),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Puzzle #71 Solver"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.backgroundColor = Self.backgroundColor
        window.appearance = NSAppearance(named: .darkAqua)
        window.isOpaque = true
        window.isMovableByWindowBackground = true
        window.minSize = NSSize(width: 720, height: 640)
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.isReleasedWhenClosed = false
        window.contentView = root

        self.window = window
        self.webView = webView
        self.root = root
        super.init()

        webView.navigationDelegate = self
        webView.uiDelegate = self
    }

    fileprivate func presentChromeWithoutLoading() {
        window.center()
        window.makeKeyAndOrderFront(nil)
        root.needsLayout = true
        root.layoutSubtreeIfNeeded()
        window.makeFirstResponder(webView)
    }

    func show() {
        presentChromeWithoutLoading()
        webView.load(URLRequest(url: Self.dashboardURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 8))
    }

    func webView(
        _ _: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        preferences: WKWebpagePreferences,
        decisionHandler: @escaping @MainActor @Sendable (WKNavigationActionPolicy, WKWebpagePreferences) -> Void
    ) {
        if Self.isAllowedURL(navigationAction.request.url) {
            decisionHandler(.allow, preferences)
        } else {
            decisionHandler(.cancel, preferences)
        }
    }

    func webView(
        _ _: WKWebView,
        decidePolicyFor navigationResponse: WKNavigationResponse,
        decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
    ) {
        guard let url = navigationResponse.response.url else {
            decisionHandler(.allow)
            return
        }
        if Self.isAllowedURL(url) {
            decisionHandler(.allow)
        } else {
            decisionHandler(.cancel)
        }
    }

    func webView(_ _: WKWebView, didFinish _: WKNavigation!) {
        #if PUZZLE71_TESTING
        if testNavigationResult == nil {
            testNavigationResult = .success(())
        }
        #endif
    }

    func webView(_ _: WKWebView, didFailProvisionalNavigation _: WKNavigation!, withError error: Error) {
        #if PUZZLE71_TESTING
        if testNavigationResult == nil {
            testNavigationResult = .failure(error)
            return
        }
        #endif
        presentLoadFailure(error)
    }

    func webView(_ _: WKWebView, didFail _: WKNavigation!, withError error: Error) {
        #if PUZZLE71_TESTING
        if testNavigationResult == nil {
            testNavigationResult = .failure(error)
            return
        }
        #endif
        presentLoadFailure(error)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        webView.reload()
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith _: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures _: WKWindowFeatures
    ) -> WKWebView? {
        if Self.isAllowedURL(navigationAction.request.url) {
            webView.load(navigationAction.request)
        }
        return nil
    }

    private func presentLoadFailure(_ error: Error) {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorCancelled {
            return
        }

        let detail = htmlEscaped(nsError.localizedDescription)
        let html = """
        <!DOCTYPE html>
        <html lang="de">
        <head>
          <meta charset="utf-8">
          <title>Dashboard nicht erreichbar</title>
          <style>
            html, body {
              margin: 0;
              background: #0A0A0B;
              color: #EDEDEF;
              font: 14px/1.5 -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
            }
            main { padding: 56px 24px 24px; max-width: 40rem; }
            h1 { font-size: 18px; font-weight: 600; margin: 0 0 12px; }
            p { margin: 0 0 12px; color: #86868C; }
            code, a { color: #EDEDEF; }
            code { font-family: ui-monospace, "SF Mono", Menlo, monospace; }
          </style>
        </head>
        <body>
          <main>
            <h1>Lokales Dashboard nicht erreichbar</h1>
            <p>Die App konnte <code>http://127.0.0.1:8080</code> nicht laden. Der Puzzle-#71-Solver muss lokal laufen, bevor dieses Fenster Inhalt anzeigen kann.</p>
            <p>Fehler: \(detail)</p>
            <p><a href="http://127.0.0.1:8080">Erneut versuchen</a></p>
          </main>
        </body>
        </html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }

    private static func isAllowedURL(_ url: URL?) -> Bool {
        guard let url else { return false }
        if url.scheme?.lowercased() == "about" {
            return true
        }
        guard url.scheme?.lowercased() == "http" else { return false }
        guard url.host == dashboardHost else { return false }
        let port = url.port ?? 80
        return port == dashboardPort
    }

    private static func initialContentRect() -> NSRect {
        let visible = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let margin: CGFloat = 24
        let width = min(preferredContentSize.width, max(720, visible.width - margin))
        let height = min(preferredContentSize.height, max(640, visible.height - margin))
        return NSRect(
            x: visible.midX - width / 2,
            y: visible.midY - height / 2,
            width: width,
            height: height
        )
    }

    private func htmlEscaped(_ string: String) -> String {
        string
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }

    #if PUZZLE71_TESTING
    fileprivate func loadCSPFixtureAndReadMarginTop(timeout: TimeInterval) throws -> String {
        testNavigationResult = nil
        let html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'">
        </head>
        <body>
          <div class="app-container">fixture</div>
        </body>
        </html>
        """
        webView.loadHTMLString(html, baseURL: nil)
        let navigationDeadline = Date().addingTimeInterval(timeout)
        while testNavigationResult == nil, Date() < navigationDeadline {
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
        }
        guard let navigation = testNavigationResult else {
            throw NSError(
                domain: "Puzzle71TestHooks",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "timed out waiting for WKWebView navigation"]
            )
        }
        try navigation.get()

        var finished = false
        var margin: String?
        var evaluationError: Error?
        webView.evaluateJavaScript(
            "getComputedStyle(document.querySelector('.app-container')).marginTop"
        ) { result, error in
            if let error {
                evaluationError = error
            } else if let value = result as? String {
                margin = value
            } else {
                evaluationError = NSError(
                    domain: "Puzzle71TestHooks",
                    code: 2,
                    userInfo: [
                        NSLocalizedDescriptionKey: "unexpected JavaScript result: \(String(describing: result))"
                    ]
                )
            }
            finished = true
        }
        let evaluationDeadline = Date().addingTimeInterval(timeout)
        while !finished, Date() < evaluationDeadline {
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
        }
        if !finished {
            throw NSError(
                domain: "Puzzle71TestHooks",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "timed out waiting for getComputedStyle"]
            )
        }
        if let evaluationError {
            throw evaluationError
        }
        guard let margin else {
            throw NSError(
                domain: "Puzzle71TestHooks",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "missing computed margin-top"]
            )
        }
        return margin
    }
    #endif
}

#if PUZZLE71_TESTING
enum Puzzle71TestHooks {
    private static var session: DashboardSession?

    static func makeUnloadedChrome() -> (window: NSWindow, root: DashboardRootView) {
        let created = DashboardSession()
        created.presentChromeWithoutLoading()
        session = created
        return (created.window, created.root)
    }

    static func loadCSPFixtureAndReadMargin(timeout: TimeInterval) throws -> String {
        guard let session else {
            throw NSError(
                domain: "Puzzle71TestHooks",
                code: 5,
                userInfo: [NSLocalizedDescriptionKey: "chrome session was not created"]
            )
        }
        return try session.loadCSPFixtureAndReadMarginTop(timeout: timeout)
    }

    static func tearDown() {
        session?.testNavigationResult = nil
        session = nil
    }
}
#endif
