import AppKit
import CoreFoundation
import WebKit

// This executable is compiled only with PUZZLE71_TESTING. Its supervisor owns a
// disposable rehearsal backend and Bitcoin Core; the UI uses real HTTP throughout.
@main
@MainActor
enum WalletRegtestTests {
    static let caseIDs = [
        "initial_offline_retry", "initial_no_send", "invalid_destination", "prepare_a_exact", "edit_revokes",
        "prepare_b_exact", "reload_revokes", "lost_ack_double_click", "restart_recovers",
        "mine_confirms", "provider_outage_stale", "provider_restore_fresh",
        "reorg_returns_submitted", "remine_confirms", "backend_offline_poll",
        "backend_poll_reconnect", "native_load_failure", "native_retry_recovers",
    ]
    struct Configuration: Decodable {
        let backend_url: String
        let destination_a: String
        let destination_b: String
        let control_dir: String
        let results_path: String
        let screenshots_dir: String
        let expected_funding_sat: UInt64
        let keystone_only: Bool?
    }
    struct ResponseHeader: Decodable {
        let sequence: Int
        let ok: Bool
    }
    static var configuration: Configuration!
    static var view: WKWebView!
    static var sequence = 0
    static var cases: [[String: Any]] = []
    static var errors: [String] = []

    static func failure(_ message: String) -> NSError {
        NSError(domain: "WalletRegtestTests", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw failure(message) }
    }
    static func pump() {
        _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
    }
    static func js(_ source: String) throws -> Any? {
        var done = false; var result: Any?; var error: Error?
        view.evaluateJavaScript(source) { value, failed in result = value; error = failed; done = true }
        let deadline = Date().addingTimeInterval(5)
        while !done && Date() < deadline { pump() }
        guard done else { throw failure("JavaScript evaluation timed out") }
        if let error { throw error }
        return result
    }
    static func wait(_ expression: String, _ description: String, seconds: Double = 20) throws {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if (try? js(expression)) as? Bool == true { return }
            pump()
        }
        throw failure("Timed out: " + description)
    }
    static func quoted(_ value: String) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: [value])
        return String(decoding: data, as: UTF8.self).dropFirst().dropLast().description
    }
    static func integer(_ value: Any?, _ label: String) throws -> UInt64 {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let result = UInt64(number.stringValue) else { throw failure("Missing unsigned integer: " + label) }
        return result
    }
    static func btcSatoshis(_ text: String) throws -> UInt64 {
        let fields = text.split(separator: " ")
        guard fields.count == 2, fields[1] == "BTC" else { throw failure("Invalid BTC display: " + text) }
        let parts = fields[0].split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[1].count == 8, let whole = UInt64(parts[0]),
              whole <= 21_000_000, let fraction = UInt64(parts[1]) else { throw failure("Invalid exact BTC amount") }
        return whole * 100_000_000 + fraction
    }
    static func ipc(_ action: String, _ params: [String: Any] = [:]) throws -> [String: Any] {
        sequence += 1
        let directory = URL(fileURLWithPath: configuration.control_dir, isDirectory: true)
        let request = directory.appendingPathComponent(String(format: "request-%04d.json", sequence))
        let response = directory.appendingPathComponent(String(format: "response-%04d.json", sequence))
        try require(!FileManager.default.fileExists(atPath: request.path) && !FileManager.default.fileExists(atPath: response.path), "IPC sequence already exists")
        try JSONSerialization.data(withJSONObject: ["sequence": sequence, "action": action, "params": params], options: [.sortedKeys]).write(to: request, options: .atomic)
        let deadline = Date().addingTimeInterval(30)
        while !FileManager.default.fileExists(atPath: response.path) && Date() < deadline { pump() }
        guard FileManager.default.fileExists(atPath: response.path) else { throw failure("IPC timeout: " + action) }
        let data = try Data(contentsOf: response)
        let header = try JSONDecoder().decode(ResponseHeader.self, from: data)
        try require(header.sequence == sequence, "IPC response sequence mismatch")
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw failure("Invalid IPC response") }
        guard header.ok else { throw failure("Supervisor rejected \(action): \(String(describing: object["error"]))") }
        guard let result = object["result"] as? [String: Any] else { throw failure("Missing IPC result: " + action) }
        return result
    }
    static func ui() throws -> [String: Any] {
        let source = """
        JSON.stringify(Object.fromEntries(['claim-summary-destination','claim-summary-inputs',
        'claim-summary-fee','claim-summary-payout','claim-preview-status','claim-result-status',
        'claim-result-txid','claim-result-detail','claim-destination-error','claim-confirm-error',
        'status-text'].map(id=>[id,document.getElementById(id)?.textContent ?? null])))
        """
        guard let text = try js(source) as? String,
              let result = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { throw failure("Missing UI snapshot") }
        return result
    }
    static func noSend(_ snapshot: [String: Any]) throws {
        for key in ["send_attempts", "forwarded_submits", "accepted_submits", "dropped_submit_replies"] {
            try require(integer(snapshot[key], key) == 0, "Unexpected pre-send activity: " + key)
        }
        try require((snapshot["mempool_txids"] as? [String]) == [], "Unexpected pre-send mempool transaction")
    }
    static func oneSend(_ snapshot: [String: Any], txid: String) throws {
        for key in ["send_attempts", "forwarded_submits", "accepted_submits", "dropped_submit_replies"] {
            try require(integer(snapshot[key], key) == 1, "Expected exactly one submit/ACK fault: " + key)
        }
        try require(snapshot["last_submitted_txid"] as? String == txid, "Submission identity changed")
    }
    static func fill(_ destination: String) throws {
        _ = try js("document.getElementById('claim-destination').value=" + quoted(destination) + ";document.getElementById('claim-destination').dispatchEvent(new Event('input',{bubbles:true}));void 0")
    }
    static func prepare(_ destination: String) throws -> [String: Any] {
        try wait("document.getElementById('btn-claim-prepare')?.disabled === false", "Prepare enabled")
        try fill(destination)
        _ = try js("document.getElementById('btn-claim-prepare').click();void 0")
        try wait("document.getElementById('btn-claim-confirm')?.disabled === false", "Fresh preview authorized")
        let snapshot = try ipc("snapshot_counts")
        try noSend(snapshot)
        guard let status = snapshot["backend_status"] as? [String: Any], let claim = status["claim"] as? [String: Any],
              let prepared = claim["Prepared"] as? [String: Any], let summary = prepared["summary"] as? [String: Any] else { throw failure("Real backend is not Prepared") }
        // ClaimSummary classifies every non-mainnet address as "test"; the
        // supervisor independently requires the actual Core chain to be regtest.
        try require(summary["network"] as? String == "test", "Prepared transaction has a mainnet/unknown address classification")
        try require(summary["destination"] as? String == destination, "Backend destination mismatch")
        let total = try integer(summary["total_input_sat"], "total_input_sat")
        let output = try integer(summary["output_sat"], "output_sat")
        let fee = try integer(summary["fee_sat"], "fee_sat")
        let vsize = try integer(summary["vsize"], "vsize")
        try require(total == configuration.expected_funding_sat && output < total && fee == total - output, "Preview funding/fee conservation mismatch")
        try require(vsize > 0 && fee / vsize >= 2000, "Preview fee violates 2000 sat/vB policy")
        let visible = try ui()
        try require(visible["claim-summary-destination"] as? String == destination, "Visible destination mismatch")
        try require(btcSatoshis(visible["claim-summary-payout"] as? String ?? "") == output, "Visible payout mismatch")
        let inputs = (visible["claim-summary-inputs"] as? String ?? "").components(separatedBy: " · ")
        try require(inputs.count == 2 && UInt64(inputs[0]) == integer(summary["input_count"], "input_count"), "Visible input count mismatch")
        try require(btcSatoshis(inputs[1]) == total, "Visible input total mismatch")
        let feeText = (visible["claim-summary-fee"] as? String ?? "").components(separatedBy: " sat · ")
        try require(feeText.count == 2 && UInt64(feeText[0].replacingOccurrences(of: ".", with: "")) == fee, "Visible fee mismatch")
        return summary
    }
    static func verify(_ summary: [String: Any], txid: String) throws -> [String: Any] {
        let proof = try ipc("verify_transaction", ["txid": txid, "destination": configuration.destination_b, "expected_output_sat": integer(summary["output_sat"], "output_sat")])
        try require(proof["txid"] as? String == txid && proof["destination"] as? String == configuration.destination_b, "Node transaction identity mismatch")
        for key in ["total_input_sat", "output_sat", "fee_sat", "vsize", "input_count"] {
            try require(integer(proof[key], key) == integer(summary[key], key), "Node/preview mismatch: " + key)
        }
        try require((try js("document.getElementById('claim-result-txid')?.textContent")) as? String == txid, "UI transaction identity mismatch")
        return proof
    }
    static func confirmedProof(_ summary: [String: Any], txid: String) throws -> [String: Any] {
        let proof = try verify(summary, txid: txid)
        try require(integer(proof["confirmations"], "confirmations") > 0, "Node not confirmed")
        let height = try integer(proof["block_height"], "block_height")
        try require((try js("document.getElementById('claim-result-status')?.textContent")) as? String == "Bestätigt in Block \(height)", "UI confirmation height disagrees with Core")
        return proof
    }
    static func writeResults(passed: Bool) throws {
        let object: [String: Any] = ["schema": 1, "passed": passed, "cases": cases, "errors": errors]
        try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: configuration.results_path), options: .atomic)
    }
    static func record(_ id: String, _ action: () throws -> [String: Any]) throws {
        let start = ISO8601DateFormatter().string(from: Date())
        do {
            let evidence = try action()
            cases.append(["id": id, "passed": true, "start_utc": start, "end_utc": ISO8601DateFormatter().string(from: Date()), "evidence": evidence])
            try writeResults(passed: false)
        } catch {
            var failed: [String: Any] = ["id": id, "passed": false, "start_utc": start,
                                         "end_utc": ISO8601DateFormatter().string(from: Date()),
                                         "error": error.localizedDescription]
            if view != nil, let visible = try? ui() { failed["ui"] = visible }
            cases.append(failed)
            throw error
        }
    }
    static func screenshot(_ name: String) throws {
        // Stabilize capture only, after behavioral assertions; never change selection or API behavior.
        _ = try js("document.querySelectorAll('.btn-mode').forEach(e=>e.style.setProperty('transition','none','important'));void document.body.offsetHeight")
        var done = false; var image: NSImage?; var error: Error?
        view.takeSnapshot(with: nil) { value, failed in image = value; error = failed; done = true }
        let deadline = Date().addingTimeInterval(10)
        while !done && Date() < deadline { pump() }
        if let error { throw error }
        guard done, let data = image?.tiffRepresentation, let bitmap = NSBitmapImageRep(data: data),
              let png = bitmap.representation(using: .png, properties: [:]) else { throw failure("Snapshot failed") }
        try png.write(to: URL(fileURLWithPath: configuration.screenshots_dir, isDirectory: true).appendingPathComponent(name + ".png"))
    }
    static func main() {
        if CommandLine.arguments == [CommandLine.arguments[0], "--list-cases"] {
            let data = try! JSONSerialization.data(withJSONObject: ["schema": 1, "case_ids": caseIDs, "keystone_case_ids": Array(caseIDs.prefix(8))], options: [.sortedKeys])
            print(String(decoding: data, as: UTF8.self)); return
        }
        do {
            try require(CommandLine.arguments.count == 2, "Usage: WalletRegtestTests <private-config.json> | --list-cases")
            configuration = try JSONDecoder().decode(Configuration.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
            _ = try Puzzle71TestHooks.validateRegtestEndpoint(configuration.backend_url)
            try require(configuration.destination_a != configuration.destination_b && configuration.expected_funding_sat > 0, "Invalid test funding/destinations")
            for path in [configuration.control_dir, configuration.results_path, configuration.screenshots_dir] {
                try require(path.hasPrefix("/"), "Test paths must be absolute")
            }
            // Stop before the first Session exists: the old testing callback would
            // swallow this first failure, so later reloads cannot substitute for it.
            _ = try ipc("stop_backend")
            let app = NSApplication.shared; app.setActivationPolicy(.accessory)
            let chrome = try Puzzle71TestHooks.makeUnloadedRegtestChrome(endpoint: configuration.backend_url)
            chrome.window.title = "REGTEST — Puzzle71 Wallet E2E"; chrome.window.titleVisibility = .visible
            chrome.window.setFrameOrigin(NSPoint(x: -20000, y: -20000)); chrome.window.setContentSize(NSSize(width: 900, height: 1050))
            defer { chrome.window.close(); Puzzle71TestHooks.tearDown() }
            guard let webView = chrome.root.subviews.compactMap({ $0 as? WKWebView }).first else { throw failure("Missing real native WKWebView") }
            view = webView
            var summaryA: [String: Any] = [:]; var summaryB: [String: Any] = [:]; var txid = ""
            try record("initial_offline_retry") {
                try Puzzle71TestHooks.loadDashboard()
                try wait("document.querySelector('h1')?.textContent === 'Lokales Dashboard nicht erreichbar'", "First native navigation renders real failure page")
                try require((try js("document.querySelector('a')?.getAttribute('href') === " + quoted(configuration.backend_url))) as? Bool == true, "First failure Retry points to wrong endpoint")
                try screenshot("initial-native-offline")
                _ = try ipc("start_backend")
                _ = try js("document.querySelector('a').click();void 0")
                try wait("document.getElementById('claim-panel')?.classList.contains('hidden') === false && document.getElementById('btn-claim-prepare')?.disabled === false", "Initial real Retry reaches rehearsal")
                let snapshot = try ipc("snapshot_counts"); try noSend(snapshot)
                guard let status = snapshot["backend_status"] as? [String: Any] else { throw failure("Missing initial backend state") }
                try require(status["claim"] as? String == "AwaitingOwner", "Initial Retry did not reach AwaitingOwner")
                return ["node": snapshot, "ui": try ui()]
            }
            try record("initial_no_send") {
                try wait("document.getElementById('claim-panel')?.classList.contains('hidden') === false && document.getElementById('btn-claim-prepare')?.disabled === false", "Initial real rehearsal page")
                let snapshot = try ipc("snapshot_counts"); try noSend(snapshot)
                try require((try js("document.getElementById('btn-claim-confirm').disabled")) as? Bool == true, "Initial page authorizes Send")
                return snapshot
            }
            try record("invalid_destination") {
                try fill("not-a-bitcoin-address"); _ = try js("document.getElementById('btn-claim-prepare').click();void 0")
                try wait("document.getElementById('claim-destination-error')?.textContent === 'Ungültige Bitcoin-Adresse'", "Real invalid-address rejection")
                let snapshot = try ipc("snapshot_counts"); try noSend(snapshot); return ["ui": try ui(), "node": snapshot]
            }
            try record("prepare_a_exact") { summaryA = try prepare(configuration.destination_a); return ["summary": summaryA, "ui": try ui()] }
            try record("edit_revokes") {
                try fill(configuration.destination_b)
                try require((try js("document.getElementById('btn-claim-confirm').disabled && document.getElementById('claim-step-summary').classList.contains('hidden')")) as? Bool == true, "Destination B did not revoke A")
                try fill(configuration.destination_a)
                try require((try js("document.getElementById('btn-claim-confirm').disabled")) as? Bool == true, "Typing A restores authorization")
                let snapshot = try ipc("snapshot_counts"); try noSend(snapshot); return snapshot
            }
            try record("prepare_b_exact") {
                summaryB = try prepare(configuration.destination_b)
                try require(summaryA["txid"] as? String != summaryB["txid"] as? String, "Different destination kept same transaction identity")
                return ["summary": summaryB, "ui": try ui()]
            }
            try record("reload_revokes") {
                view.reloadFromOrigin()
                try wait("document.readyState === 'complete' && document.getElementById('claim-preview-status')?.textContent.includes('erneut prüfen') === true", "Actual WK reload of Prepared")
                try require((try js("document.getElementById('btn-claim-confirm').disabled")) as? Bool == true, "Reload preserved Send authorization")
                try fill(configuration.destination_b)
                try require((try js("document.getElementById('btn-claim-confirm').disabled")) as? Bool == true, "Reload plus typing authorizes Send")
                let snapshot = try ipc("snapshot_counts"); try noSend(snapshot); return ["ui": try ui(), "node": snapshot]
            }
            try record("lost_ack_double_click") {
                summaryB = try prepare(configuration.destination_b)
                guard let preparedID = summaryB["txid"] as? String, preparedID.count == 64 else { throw failure("Missing prepared txid") }
                txid = preparedID; _ = try ipc("arm_drop_next_submit_reply")
                _ = try js("document.getElementById('btn-claim-confirm').click();document.getElementById('btn-claim-confirm').click();void 0")
                try wait("document.getElementById('claim-result-status')?.textContent === 'Eingereicht' && document.getElementById('claim-result-txid')?.textContent === " + quoted(txid), "Lost ACK recovered by real status polling")
                let snapshot = try ipc("snapshot_counts"); try oneSend(snapshot, txid: txid)
                let proof = try verify(summaryB, txid: txid); try screenshot("submitted")
                return ["summary": summaryB, "node": snapshot, "transaction": proof, "ui": try ui()]
            }
            if configuration.keystone_only != true {
                try record("restart_recovers") {
                    _ = try ipc("restart_backend")
                    let watermark = try integer(js("Math.ceil(performance.now())"), "post-restart poll watermark")
                    try wait("performance.getEntriesByType('resource').some(e=>new URL(e.name).pathname==='/api/status' && e.startTime >= \(watermark)) && consecutivePollFailures === 0 && document.getElementById('claim-result-status')?.textContent === 'Eingereicht' && document.getElementById('claim-result-txid')?.textContent === " + quoted(txid), "Backend restart recovers exact transaction after a new real poll")
                    let snapshot = try ipc("snapshot_counts"); try oneSend(snapshot, txid: txid)
                    guard let status = snapshot["backend_status"] as? [String: Any], let claim = status["claim"] as? [String: Any],
                          let submitted = claim["Submitted"] as? [String: Any] else { throw failure("Restarted backend has not recovered Submitted") }
                    try require(submitted["txid"] as? String == txid, "Restarted backend recovered a different transaction")
                    return ["node": snapshot, "transaction": try verify(summaryB, txid: txid)]
                }
                try record("mine_confirms") {
                    let mined = try ipc("mine", ["blocks": 1])
                    try wait("document.getElementById('claim-result-status')?.textContent.startsWith('Bestätigt in Block ') === true", "Real mined confirmation")
                    let proof = try confirmedProof(summaryB, txid: txid)
                    try screenshot("confirmed"); return ["mine": mined, "transaction": proof, "ui": try ui()]
                }
                try record("provider_outage_stale") {
                    _ = try ipc("status_outage", ["enabled": true])
                    try wait("document.getElementById('claim-result-status')?.classList.contains('claim-status-stale') === true && document.getElementById('claim-result-status')?.textContent.startsWith('Zuletzt bekannt: bestätigt in Block ') === true", "Real provider outage is qualified")
                    let snapshot = try ipc("snapshot_counts"); try oneSend(snapshot, txid: txid)
                    try require(integer(snapshot["blocked_status_requests"], "blocked_status_requests") > 0, "No actual provider request blocked")
                    try screenshot("provider-stale"); return ["node": snapshot, "ui": try ui()]
                }
                try record("provider_restore_fresh") {
                    _ = try ipc("status_outage", ["enabled": false])
                    try wait("document.getElementById('claim-result-status')?.textContent.startsWith('Bestätigt in Block ') === true && !document.getElementById('claim-result-status')?.classList.contains('claim-status-stale')", "Provider freshness recovers")
                    return ["transaction": try confirmedProof(summaryB, txid: txid), "ui": try ui()]
                }
                try record("reorg_returns_submitted") {
                    let reorg = try ipc("reorg_last_confirmation", ["txid": txid])
                    try wait("document.getElementById('claim-result-status')?.textContent === 'Eingereicht' && !document.getElementById('claim-result-status')?.classList.contains('claim-status-confirmed')", "Real reorg clears confirmation")
                    let proof = try verify(summaryB, txid: txid); try require(integer(proof["confirmations"], "confirmations") == 0, "Reorg transaction remains confirmed")
                    let snapshot = try ipc("snapshot_counts"); try oneSend(snapshot, txid: txid); return ["reorg": reorg, "transaction": proof]
                }
                try record("remine_confirms") {
                    _ = try ipc("mine", ["blocks": 1])
                    try wait("document.getElementById('claim-result-status')?.textContent.startsWith('Bestätigt in Block ') === true", "Remine confirms")
                    return ["transaction": try confirmedProof(summaryB, txid: txid), "ui": try ui()]
                }
                try record("backend_offline_poll") {
                    _ = try ipc("stop_backend")
                    try wait("document.getElementById('status-text')?.textContent === 'VERBINDUNG GETRENNT'", "Actual backend loss without reload")
                    return ["ui": try ui()]
                }
                try record("backend_poll_reconnect") {
                    _ = try ipc("start_backend")
                    try wait("document.getElementById('status-text')?.textContent === 'TREFFER — SUCHE BEENDET' && document.getElementById('claim-result-status')?.textContent.startsWith('Bestätigt in Block ') === true", "Real poll reconnection")
                    return ["transaction": try confirmedProof(summaryB, txid: txid), "ui": try ui()]
                }
                try record("native_load_failure") {
                    _ = try ipc("stop_backend"); view.reloadFromOrigin()
                    try wait("document.querySelector('h1')?.textContent === 'Lokales Dashboard nicht erreichbar'", "Real native navigation failure page")
                    let expected = try quoted(configuration.backend_url)
                    try require((try js("document.querySelector('a')?.getAttribute('href') === " + expected)) as? Bool == true, "Native retry points to wrong endpoint")
                    try screenshot("native-offline"); return ["failure_page_title": try js("document.title") as? String ?? ""]
                }
                try record("native_retry_recovers") {
                    _ = try ipc("start_backend"); _ = try js("document.querySelector('a').click();void 0")
                    try wait("document.getElementById('claim-result-status')?.textContent.startsWith('Bestätigt in Block ') === true && document.getElementById('claim-result-txid')?.textContent === " + quoted(txid), "Actual native Retry link recovers")
                    let snapshot = try ipc("snapshot_counts"); try oneSend(snapshot, txid: txid)
                    return ["node": snapshot, "transaction": try confirmedProof(summaryB, txid: txid), "ui": try ui()]
                }
            }
            let expected = configuration.keystone_only == true ? Array(caseIDs.prefix(8)) : caseIDs
            try require(cases.compactMap { $0["id"] as? String } == expected, "Missing or duplicate case execution")
            try writeResults(passed: true)
            print("OK: real native/regtest wallet \(cases.count) cases")
        } catch {
            errors.append(error.localizedDescription)
            if configuration != nil { try? writeResults(passed: false) }
            fputs("FAIL: \(error.localizedDescription)\n", stderr); exit(1)
        }
    }
}
