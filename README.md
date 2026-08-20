# Bitcoin Puzzle #71 Solver Control Center

Lokaler Solver für Bitcoin Puzzle #71 mit Metal-Beschleunigung und einem eingebetteten Web-Dashboard. Das Projekt ist auf Apple Silicon unter macOS ausgelegt und sucht ausschließlich im fest im Code definierten Schlüsselbereich von Puzzle #71.

## Zweck und realistische Einordnung

Der Solver prüft Kandidaten für die konfigurierte P2PKH-Zieladresse von Puzzle #71. Der Suchbereich ist unveränderlich auf `2^70` bis `2^71 - 1` gesetzt (`2^70` mögliche Schlüssel, also rund `1,18 × 10^21` Kandidaten). Blöcke werden kryptografisch zufällig ausgewählt und nach vollständig abgeschlossener Prüfung im Checkpoint als erledigt markiert.

Das ist ein Brute-Force-Suchprogramm, keine Ertrags- oder Gewinnzusage. Ein Treffer, eine vollständige Abdeckung des Suchraums oder eine bestimmte Laufzeit kann nicht zugesichert werden. Die im Projekt angezeigte Reward-Angabe ist lediglich ein fest hinterlegter Puzzle-Parameter; sie ist keine Zusage über Anspruch, Auszahlung, Marktwert oder Erfolg.

## Voraussetzungen

- macOS auf Apple Silicon mit verfügbarer Metal-GPU
- Rust und Cargo mit Unterstützung für Edition 2024
- Schreibrechte im aktuellen Arbeitsverzeichnis für `puzzle71_checkpoint.json` und bei einem Treffer für `FOUND_KEY.txt`

Der Hauptsuchlauf benötigt ein erfolgreich initialisiertes Metal-Gerät. Der CPU-Code dient unter anderem der Kryptografie, dem Mini-Puzzle-Selbsttest und der unabhängigen Trefferprüfung; ein CPU-Fallback für die vollständige Suche ist nicht implementiert.

## Bauen und starten

Im Repository-Root:

```sh
cargo build --release
cargo run --release -- --help
cargo run --release -- --mode auto
```

Nach einem normalen Solver-Start führt das Programm zunächst den verpflichtenden Kryptografie- und 24-Bit-Mini-Puzzle-Selbsttest aus. Danach startet es den Solver und das Dashboard. Die separaten Modi `--bench` und `--test-mini` führen ihre jeweilige Aufgabe aus und beenden sich anschließend. Das kompilierte Programm liegt nach dem Release-Build unter `target/release/puzzle71_solver`.

### Unterstützte Optionen

```text
--mode <eco|balanced|high|full|auto>   Power-Profil, Standard: auto
--host <host>                         Loopback-Adresse, Standard: 127.0.0.1
--port <port>                         Dashboard-Port, Standard: 8080
--no-tui                              Terminal-Anzeige deaktivieren
--bench                               CPU-/Metal-Power-Benchmark ausführen und beenden
--test-mini                           24-Bit-CPU-Mini-Puzzle testen und beenden
--electricity-price <EUR/kWh>         Kostenparameter für die Anzeige, Standard: 0.34
--block-size <keys>                   Teiler von 2^70 für die Suchblöcke
--help, -h                            Hilfe anzeigen
```

`--host` akzeptiert nur `127.0.0.1`, `localhost` oder `::1`; eine Bindung an eine öffentliche Adresse wird abgelehnt. `--block-size` muss größer als null sein, `2^70` exakt teilen und darf höchstens `2^64 - 1` Blöcke erzeugen. Ohne Angabe verwendet der Solver `2^24` Schlüssel pro Block (`16.777.216`). Der CLI-Kostenparameter beeinflusst ausschließlich TUI und Benchmark, nicht die Suche. Das Dashboard besitzt dafür ein separates, lokal änderbares Eingabefeld.

Beispiele:

```sh
# Dashboard ohne ANSI-Terminalanzeige
cargo run --release -- --mode balanced --no-tui

# Anderen lokalen Port verwenden
cargo run --release -- --host 127.0.0.1 --port 9090

# Nur die lokalen Prüfungen beziehungsweise den Benchmark ausführen
cargo run --release -- --test-mini
cargo run --release -- --electricity-price 0.34 --bench
```

## Dashboard

Standardmäßig ist das Dashboard unter [http://127.0.0.1:8080](http://127.0.0.1:8080) erreichbar. Es wird zusammen mit dem Solver gestartet und zeigt unter anderem Laufstatus, Power-Modus, Keys/s, geprüfte Blöcke, Laufzeit, geschätzte Package-Power, geschätzte SoC-Temperatur, CPU-Last, GPU-Duty-Limit und den Zeitpunkt des letzten Checkpoints.

Die Oberfläche kann die Suche pausieren/fortsetzen, den Power-Modus ändern und den 24-Bit-CPU-Selbsttest auslösen. Die eingebettete HTTP-API stellt dafür nur lokale Status- und Steuerpfade bereit (`/api/status`, `/api/start`, `/api/stop`, `/api/mode`, `/api/selftest`). Für POST-Anfragen wird zusätzlich eine passende lokale Origin geprüft. Es gibt keine Anmeldung, keine TLS-Schicht und keine Berechtigungstrennung: Wer Zugriff auf den lokalen Dienst hat, kann ihn steuern. Das Dashboard darf deshalb nicht über einen Proxy oder eine öffentliche Netzwerkschnittstelle exponiert werden.

## Power-Modi und Duty-Limit

Alle Profile sind global auf höchstens 90 % GPU-Duty begrenzt. Nach jedem Metal-Durchlauf wird eine errechnete Leerlaufzeit eingehalten; dadurch ist `FULL` nicht gleichbedeutend mit dauerhaft 100 % GPU-Auslastung.

| Modus | Ziel-Duty im Code | Verhalten |
| --- | ---: | --- |
| `eco` | 40 % | geringere Aktivzeit, kleinere Dispatches |
| `balanced` | 70 % | ausgewogenes Standardprofil |
| `high` | 85 % | höhere Aktivzeit und größere Dispatches |
| `full` | 90 % (Obergrenze) | größter Dispatch, weiterhin mit Duty-Begrenzung |
| `auto` | startet bei 70 % | passt sich per Systemlast und geschätzter Package-Power geglättet an |

Die Power- und Temperaturwerte im Dashboard sind Schätzwerte aus Prozess-/Systemlast und einem Modell; sie sind keine Messung eines externen Wattmeters oder Temperatursensors.

## Checkpoints und Fortsetzen

Der Standard-Checkpoint heißt `puzzle71_checkpoint.json` und liegt im aktuellen Arbeitsverzeichnis. Der Solver speichert während des Laufs periodisch (alle zehn Sekunden), beim Pausieren und beim kontrollierten Beenden. Geschrieben wird über temporäre Datei, `fsync` und atomisches Umbenennen; die Datei erhält Unix-Rechte `0600`.

Gespeichert werden Puzzle-Nummer, Laufzeit, Zähler und sortierte, nicht überlappende Intervalle vollständig geprüfter Blöcke. Beim nächsten Start wird der Checkpoint geladen, auf Puzzle #71 und die gewählte Blockgröße validiert und zur Fortsetzung verwendet. Ungültige oder inkonsistente Daten werden nicht stillschweigend ignoriert; der Start bricht mit einem Fehler ab. Ein laufender Block wird erst nach vollständigem Abschluss dauerhaft als abgedeckt markiert.

## Trefferverhalten und Geheimnisse

Bei einem Metal-Kandidaten stoppt der Suchlauf und leitet eine unabhängige, reine CPU-Verifikation der Adresse und des HASH160 ein. Nur bei erfolgreicher Prüfung wird die private Information lokal in `FOUND_KEY.txt` (oder einem kollisionsfreien Fallback-Namen) mit `0600` gespeichert. Bestehende Trefferdateien werden nicht überschrieben.

Die Web-API und der Dashboard-Status enthalten bei einem Treffer ausschließlich Bitcoin-Adresse, lokalen Dateinamen und Zeitstempel — niemals den Private Key. Checkpoints enthalten keine privaten Schlüssel. Trotzdem ist das Arbeitsverzeichnis vertraulich zu behandeln: `FOUND_KEY.txt` enthält den Private Key im Klartext. Nicht hochladen, nicht teilen und nicht in Logs, Screenshots oder Backups ohne geeignete Schutzmaßnahmen übernehmen. Für eine eventuelle Weiterverwendung ist eine offline beziehungsweise air-gapped Vorgehensweise erforderlich.

## Sicherheits- und Privacy-Grenzen

- Der Code enthält keinen Telemetrie- oder automatischen Broadcast-Pfad; das Dashboard stellt nur den lokalen HTTP-Dienst bereit.
- Loopback-Bindung und lokale Origin-Prüfung reduzieren die Angriffsfläche, ersetzen aber keine Authentifizierung oder TLS.
- Der Prozess vertraut den Dateirechten und der Sicherheit des macOS-Benutzerkontos. Andere Prozesse mit ausreichenden lokalen Rechten können Dateien oder Prozessdaten weiterhin lesen.
- Private Keys werden nicht im Dashboard ausgegeben, aber die Trefferdatei enthält sie absichtlich vollständig.
- Ein gültiger Treffer ist eine technische Verifikation des Kandidaten. Eigentum, Anspruch, Netzwerkzustand, Auszahlung und rechtliche Fragen werden vom Solver nicht geprüft.

## Architekturüberblick

```text
CLI / TUI ───────┐
                 ├─ gemeinsamer Solver-Zustand ── Loopback-HTTP-Dashboard
Power Governor ──┤
                 └─ MetalSolver → Metal-Kernel → Blockfortschritt
                                      │
                                      ├─ Checkpoint (atomar, 0600)
                                      └─ CPU-Verifikation → FOUND_KEY.txt (0600)
```

Der Startpfad ist in `src/main.rs` gebündelt. `src/metal_engine` dispatcht die Batch-Suche auf Metal, `src/search` verwaltet Zufallsblockwahl, Fortschritt, Duplikatfilter und Checkpoints, `src/power` steuert Duty und Lastanpassung, und `src/web` liefert die statischen Dashboard-Dateien sowie die lokale API. Kryptografische Primitive und CPU-Verifikation liegen unter `src/crypto` und `src/hit_handler.rs`.

## Tests und Qualitätsprüfungen

Rust-Tests:

```sh
cargo fmt --check
cargo test --all-targets
```

Die Tests decken unter anderem Hash-/Adressvektoren, den 24-Bit-Mini-Puzzle-End-to-End-Test, Checkpoint-Validierung und -Rechte, Trefferdatei-Rechte und Nichtüberschreiben sowie Metal/CPU-Cross-Validation und exakte Dispatch-Größen ab. Die Metal-Tests benötigen ein verfügbares Metal-Gerät.

Für die Dashboard-Tests muss der Solver separat laufen. Die Suite startet ihn nicht selbst:

```sh
cargo run --release -- --host 127.0.0.1 --port 8080 --no-tui
cd web-tests
npm install
npx playwright install chromium
npm test
```

Die Playwright-Tests prüfen unter anderem Laden, responsive Layouts, Tastaturfokus, lokale Netzwerkisolation, Moduswechsel, Duty-Limit, Selbsttest sowie, dass ein simuliertes Trefferobjekt keinen Private Key an Seite oder Status-Payload weitergibt.

## Lizenz und Status

In `Cargo.toml` ist derzeit keine Lizenz, Repository-URL oder Veröffentlichungsmetadaten angegeben. Vor einer Weiterverteilung sollte daher eine passende Lizenz- und Herkunftsentscheidung ergänzt werden. Diese README beschreibt den Stand des Codes; sie ersetzt weder eine Sicherheitsprüfung noch eine Finanz-, Steuer- oder Rechtsberatung.
