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
