# Native macOS-Wrapper

Einzelne Swift-Quelle für den WKWebView-Wrapper der lokalen App `Puzzle71.app`. Das Fenster lädt ausschließlich `http://127.0.0.1:8080`, legt die WebView vollflächig unter eine transparente Titelleiste und hält den Seitenhintergrund bis zum Fensterrand durch. Zwölf Pixel Abstand setzt ein Main-Frame-Userscript am Document-Ende per CSSOM (`element.style.setProperty`) auf `.app-container`; das bleibt mit `style-src 'self'` gültig, weil kein `<style>`-Element und kein Inline-Stylesheet eingefügt wird. Fehlt `.app-container`, passiert nichts. Die nativen Schließen-, Minimieren- und Zoom/Vollbild-Knöpfe bleiben. Dieser Text beschreibt nur den manuellen Build und die manuelle Installation; er behauptet nicht, dass die App bereits gebaut oder installiert wurde.

## Bauen

Aus dem Repository-Root, mit Xcode/Swift des Hosts:

```sh
mkdir -p /tmp/puzzle71-native
xcrun swiftc -parse-as-library -O -target arm64-apple-macos14.0 \
  -framework AppKit -framework WebKit \
  native/macos/Puzzle71.swift \
  -o /tmp/puzzle71-native/Puzzle71
```

`-parse-as-library` ist erforderlich, weil die Quelle `@main` verwendet. Ohne dieses Flag erzeugt `swiftc` ein implizites `main` und lehnt die Datei ab.

Typecheck ohne Executable:

```sh
xcrun swiftc -typecheck -parse-as-library -target arm64-apple-macos14.0 \
  -framework AppKit -framework WebKit -warnings-as-errors \
  native/macos/Puzzle71.swift
```

## Regressionstest

Eigenständiger Swift-Lauf ohne SwiftPM, ohne Solver und ohne Dashboard-URL. `-D PUZZLE71_TESTING` ersetzt `@main` der App durch den Testdriver und darf nicht in den Produktionsbuild.

```sh
mkdir -p /tmp/puzzle71-native
xcrun swiftc -parse-as-library -D PUZZLE71_TESTING -O \
  -target arm64-apple-macos14.0 \
  -framework AppKit -framework WebKit -warnings-as-errors \
  native/macos/Puzzle71.swift \
  native/macos/tests/TitlebarChromeTests.swift \
  -o /tmp/puzzle71-native/TitlebarChromeTests
/tmp/puzzle71-native/TitlebarChromeTests
```

Der Lauf erzeugt ein echtes AppKit-Fenster, prüft Titelleiste, Drag-Bereich und vollflächige WKWebView und lädt danach ein lokales HTML-Fixture mit `style-src 'self'`. Per `getComputedStyle` muss `.app-container` genau `12px` `margin-top` haben. Erwartete Ausgabe: `OK: titlebar chrome and drag region`.

Zusätzlich prüft er die Endpunkt- und Navigationsgrenzen des Testbuilds ohne HTTP-Aufruf: Der normale Wrapper akzeptiert weiterhin nur seinen Produktionsport. Ein ausdrücklich erzeugtes Regtest-Testfenster akzeptiert ausschließlich den konfigurierten HTTP-Port auf `127.0.0.1`. Der Testendpunkt muss eine kanonische Root-URL auf Port 1024 bis 65535 außer 8080 sein; Credentials, andere Hosts, HTTPS, Pfade, Query und Fragment werden als Konfiguration abgelehnt.

## Wallet mit echter WKWebView und Bitcoin Core prüfen

`scripts/native-regtest-e2e.py` baut `WalletRegtestTests.swift` zusammen mit der echten Wrapperquelle und `PUZZLE71_TESTING`. Er betreibt ausschließlich eigene temporäre Regtest-Komponenten: Bitcoin Core, einen RPC-Fehlerproxy und den `rehearsal serve-regtest`-Server. Dieser Server verwendet denselben Claim-Dienst und dieselben eingebetteten Dashboard-Dateien wie das Produkt. Im Swift-Driver gibt es keine Fetch- oder Status-Mocks. Er bedient die tatsächlichen Wallet-Buttons, liest die Vorschau in ganzen Satoshi und vergleicht sie mit der realen Core-Transaktion.

Die Python-Sicherheitsprüfungen des Supervisors werden aus dem Repository-Root mit `python3 -m unittest discover -s scripts/tests -v` ausgeführt.

Voraussetzungen sind ein macOS-GUI-Kontext, Swift/WebKit, Python 3, ein erreichbarer Docker-Daemon und ein vorher gebautes `rehearsal`-Binary aus dem zu prüfenden Quellstand. Mit `--docker-ssh-host` kann ausschließlich der eigene Core-Container auf einen separaten Docker-Host ausgelagert werden. Der Solver und die installierte App werden nicht gestartet, gestoppt oder ersetzt. Port 8080 ist als Testendpunkt verboten; die Freigabe für einen anderen Port existiert ausschließlich im Testcompile. Der Produktionsbuild hat keine Umgebungs- oder CLI-Option zur Änderung seiner festen URL.

Zuerst den kurzen vollständigen Weg bis zur echten Einreichung prüfen, dann denselben Driver mit allen Recovery-Fällen ausführen. Beide Aufrufe brauchen ein neues Ausgabeverzeichnis; die folgenden Namen werden unter einem frisch erzeugten privaten Elternverzeichnis angelegt:

```sh
P71_NATIVE_EVIDENCE_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/p71-native-wallet.XXXXXX")"
python3 scripts/native-regtest-e2e.py \
  --rehearsal-bin /absoluter/pfad/zum/rehearsal \
  --docker-ssh-host macpro \
  --output "$P71_NATIVE_EVIDENCE_PARENT/keystone" --keystone-only
python3 scripts/native-regtest-e2e.py \
  --rehearsal-bin /absoluter/pfad/zum/rehearsal \
  --docker-ssh-host macpro \
  --output "$P71_NATIVE_EVIDENCE_PARENT/full"
```

Ohne `--docker-ssh-host` nutzt der Runner den lokalen Docker-Daemon. `--timeout SECONDS` begrenzt den Lauf. Ausgabe, tatsächliche Befehle, Exitcodes, Quell-/Assetbindung, Ergebnisse und eigene WK-Screenshots liegen im jeweiligen Evidence-Verzeichnis. Private Backend-/Kontrolldateien gehören nicht in den HTTP-Berichtroot. Der Supervisor beendet seine eigenen Prozesse, Tunnel und Container auch bei einem Fehler.

Die Fallliste kommt aus `WalletRegtestTests --list-cases`, ohne App- oder Backendstart. Die ersten acht Fälle bilden den kurzen Lauf: erste Navigation bei gestopptem Backend mit echter nativer Fehlerseite und Retry-Link, initial kein Senden, ungültige Adresse, exakte Vorschau für A, Widerruf bei Adressänderung, neue Vorschau für B, echter WK-Reload ohne Sendefreigabe und verlorene Einreichungsantwort plus Doppelklick mit genau einer Node-Einreichung. Der volle Lauf ergänzt Backendneustart, Mining/Bestätigung, tatsächlichen Anbieterstatus-Ausfall und Wiederherstellung, Reorg/Remining, Offline-Polling/Reconnect sowie die native Fehlerseite mit anschließendem Retry. Bestätigte Blockhöhen werden gegen Core geprüft. Eine Farbtransition wird ausschließlich für den Screenshot in der privaten Testseite abgeschaltet; Klassen, ARIA-Werte und Statuslogik bleiben dabei unverändert.

Der private Swift-Aufruf erhält genau einen JSON-Konfigurationspfad mit `backend_url`, `destination_a`, `destination_b`, `control_dir`, `results_path`, `screenshots_dir`, `expected_funding_sat` und optional `keystone_only`. Backend/Core-Aktionen laufen über atomare `request-NNNN.json`/`response-NNNN.json`-Dateien mit identischer fortlaufender `sequence`, `action`, `params` und `ok`/`result` beziehungsweise `error`; es gibt dafür keinen zusätzlichen HTTP-Steuerdienst. Auf Antworten wird begrenzt gewartet, während der AppKit-RunLoop weiterläuft. Der Regtest-Testmodus durchläuft auch beim allerersten Navigationsfehler die normale native Fehlerseite; der bestehende CSP-Fixture-Test behält seine gezielte Callback-Auswertung.

Dies ist ein echter nativer Wallet-/Core-Integrationslauf mit einem öffentlich bekannten Regtest-Schlüssel. Er ist kein Mainnet-Payout, kein Test realer gefundener Schlüssel, kein Stromausfalltest und kein Nachweis vollständiger Edgecase-Abdeckung oder Fehlerfreiheit. Die Ausführung des installierten Release-App-Binaries und dessen Fensterlebenszyklus bleiben gesonderte Prüfungen.

## Installation

Nur das Executable ersetzen. `Info.plist`, Icon und Ressourcen bleiben unangetastet. Nicht in eine laufende App schreiben.

### Gestagte Kopie zum Prüfen

`mktemp` legt ein eigenes Verzeichnis an. Kein `rm -rf` auf einem festen Pfad.

```sh
APP_SRC="/Users/josh-agends/Applications/Puzzle71.app"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/puzzle71-stage.XXXXXX")"
STAGE="$STAGE_DIR/Puzzle71.app"

ditto "$APP_SRC" "$STAGE"
install -m 0755 /tmp/puzzle71-native/Puzzle71 "$STAGE/Contents/MacOS/Puzzle71"
codesign --force --sign - "$STAGE"
```

Die gestagte App von dort starten. Das temporäre Verzeichnis bleibt liegen, bis es der Rechner selbst aufräumt.

### Finaler Tausch im bestehenden Bundle

Erst den laufenden Wrapper nachweisen, dann erst ersetzen. Nicht `cp` auf das live Executable.

```sh
APP="/Users/josh-agends/Applications/Puzzle71.app"
BIN="$APP/Contents/MacOS/Puzzle71"
NEW="$BIN.new"

if pgrep -f "$BIN" >/dev/null; then
  echo "Puzzle71 läuft noch; erst beenden, dann erneut versuchen." >&2
  exit 1
fi
if lsof "$BIN" >/dev/null 2>&1; then
  echo "Executable ist noch geöffnet; erst beenden, dann erneut versuchen." >&2
  exit 1
fi

install -m 0755 /tmp/puzzle71-native/Puzzle71 "$NEW"
mv -f "$NEW" "$BIN"
codesign --force --sign - "$APP"
```

`install` schreibt nach `Puzzle71.new`. `mv` auf demselben Volume ersetzt die Datei atomar. Danach ad-hoc signieren (`--sign -`). `--deep` ist für dieses Ein-Executable-Bundle nicht nötig.

Der Solver muss separat auf `http://127.0.0.1:8080` laufen. Ist der Endpunkt nicht erreichbar, zeigt das Fenster eine lokale Fehlerseite statt eines leeren weißen Inhalts.
