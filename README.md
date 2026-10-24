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

Der GPU-Kernel verarbeitet je Thread bis zu 16 aufeinanderfolgende Punkte gemeinsam. Eine Montgomery-Batch-Inversion ersetzt dabei die einzelne Feldinversion pro Kandidat. Teilbatches, ungültige Infinity-Punkte und die exakte Anzahl gültiger Schlüssel werden berücksichtigt; Suchbereich und Auswahl der Zufallsblöcke bleiben gleich.

## Auszahlung an deine Wallet

Nach einem verifizierten und dauerhaft lokal gespeicherten Treffer gibst du im Dashboard die Empfangsadresse deiner Bitcoin-Wallet ein. „Adresse prüfen“ lädt aktuelle UTXOs aus zwei unabhängigen Quellen und zeigt die vollständige Zieladresse, Auszahlung und Gebühr. Erst „Transaktion an MARA Slipstream senden“ reicht genau diese Vorschau ein. Es gibt keinen Telegram-Code und keine Hardware-Wallet-Pflicht. Eine Eingabe, Vorbereitung oder ein Neustart sendet keine Transaktion.

Änderst du die Adresse, bereitest erneut vor oder ändert ein anderer Tab die Vorschau, musst du die neue Vorschau erneut prüfen. Vor dem Senden werden UTXOs und Mindestgebühr erneut abgefragt. Unveränderliche, anhand ihrer Transaktions-ID geprüfte Finanzierungstransaktionen werden begrenzt zwischengespeichert; die aktuellen UTXO-Listen werden nie aus diesem Cache übernommen. Bei einer unklaren Einreichung bleibt `CLAIM_SUBMITTED.json` als Schutz vor einer abweichenden zweiten Transaktion bestehen. „Eingereicht“ bedeutet noch keine Blockbestätigung. Die tatsächliche Verfügbarkeit und Verarbeitung bei MARA ist damit nicht garantiert.

Kann ein bestätigter Treffer noch nicht dauerhaft gespeichert werden, hält der Solver den Schlüssel im Speicher und wiederholt die Speicherung. Das Dashboard zeigt „Speicherung wird wiederholt“ und sperrt die Auszahlung bis zum Erfolg. Den Prozess währenddessen nicht beenden; noch nicht gespeicherte Daten überleben keinen Prozessabbruch.

Eine isolierte Generalprobe nutzt denselben Claim-Dienst mit einem bekannten öffentlichen Testschlüssel, Regtest-Adressen und ausschließlich lokalem Bitcoin-Core-RPC:

```bash
cargo run --bin rehearsal -- write-hit --dir /tmp/p71-regtest-probe
cargo run --bin rehearsal -- serve-regtest --dir /tmp/p71-regtest-probe --rpc 127.0.0.1:18543 --port 18080
```

Das Verzeichnis muss vorher frisch angelegt und die ausgegebene Regtest-Puzzle-Adresse mit lokalen Test-Coins finanziert und bestätigt sein. Der Server prüft das Netz des RPC-Knotens und startet nur bei `regtest`. Er hat keinen Telegram- oder Mainnet-Einreichpfad. Im Browser kann anschließend eine Regtest-Empfangsadresse eingegeben, die Vorschau geprüft und die Testtransaktion ausdrücklich gesendet werden.

## Bauen und starten

Im Repository-Root:

```sh
cargo build --release
cargo run --release --bin puzzle71_solver -- --help
cargo run --release --bin puzzle71_solver -- --mode auto
```

Nach einem normalen Solver-Start führt das Programm zunächst den verpflichtenden CPU-Kryptografie- und Mini-Puzzle-Selbsttest mit einem 24-Bit-Schlüssel aus. Dieser prüft nicht den vollständigen Suchraum von `2^24` Schlüsseln und ersetzt keinen GPU-Test. Vor der eigentlichen Suche prüft ein zusätzlicher Metal-Selbsttest deshalb einen unabhängig mit libsecp256k1 abgeleiteten Zielschlüssel im Puzzle-Bereich. Schlägt er fehl, startet die Suche nicht. Die separaten Modi `--bench`, `--test-mini` und `--telegram-test` führen ihre jeweilige Aufgabe aus und beenden sich anschließend. Das kompilierte Programm liegt nach dem Release-Build unter `target/release/puzzle71_solver`.

### Unterstützte Optionen

```text
--mode <eco|balanced|high|full|auto>   Power-Profil, Standard: auto
--host <host>                         Loopback-Adresse, Standard: 127.0.0.1
--port <port>                         Dashboard-Port, Standard: 8080
--no-tui                              Terminal-Anzeige deaktivieren
--bench                               CPU-/Metal-Power-Benchmark ausführen und beenden
--test-mini                           24-Bit-CPU-Mini-Puzzle testen und beenden
--telegram-test                      Telegram-Testnachricht senden und beenden
--electricity-price <EUR/kWh>         Kostenparameter für die Anzeige, Standard: 0.34
--block-size <keys>                   Teiler von 2^70 für die Suchblöcke
--help, -h                            Hilfe anzeigen
```

`--host` akzeptiert nur `127.0.0.1`; eine Bindung an `localhost`, `::1` oder eine öffentliche Adresse wird abgelehnt. `--block-size` muss größer als null sein, `2^70` exakt teilen und darf höchstens `2^64 - 1` Blöcke erzeugen. Ohne Angabe verwendet der Solver `2^24` Schlüssel pro Block (`16.777.216`). Der CLI-Kostenparameter beeinflusst ausschließlich TUI und Benchmark, nicht die Suche. Das Dashboard besitzt dafür ein separates, lokal änderbares Eingabefeld.

Beispiele:

```sh
# Dashboard ohne ANSI-Terminalanzeige
cargo run --release --bin puzzle71_solver -- --mode balanced --no-tui

# Anderen lokalen Port verwenden
cargo run --release --bin puzzle71_solver -- --host 127.0.0.1 --port 9090

# Nur die lokalen Prüfungen beziehungsweise den Benchmark ausführen
cargo run --release --bin puzzle71_solver -- --test-mini
cargo run --release --bin puzzle71_solver -- --electricity-price 0.34 --bench
```

## Dashboard

Standardmäßig ist das Dashboard unter [http://127.0.0.1:8080](http://127.0.0.1:8080) erreichbar. Es wird zusammen mit dem Solver gestartet und zeigt unter anderem Laufstatus, Power-Modus, Keys/s, geprüfte Blöcke, Laufzeit, geschätzte Package-Power, geschätzte SoC-Temperatur, CPU-Last, GPU-Duty-Limit und den Zeitpunkt des letzten Checkpoints.

Die Oberfläche kann die Suche pausieren/fortsetzen, den Power-Modus ändern und den CPU-Selbsttest auslösen. Die eingebettete HTTP-API stellt lokale Status- und Steuerpfade bereit (`/api/status`, `/api/start`, `/api/stop`, `/api/mode`, `/api/selftest`). Bei einem verifizierten Treffer kommen die Claim-Pfade für Vorbereitung und ausdrückliches Senden hinzu. Für POST-Anfragen wird zusätzlich eine passende lokale Origin geprüft. Es gibt keine Anmeldung, keine TLS-Schicht und keine Berechtigungstrennung: Wer Zugriff auf den lokalen Dienst hat, kann ihn steuern. Das Dashboard darf deshalb nicht über einen Proxy oder eine öffentliche Netzwerkschnittstelle exponiert werden.

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

Die Status-API meldet die tatsächlich gemessene Leerlaufzeit des letzten Dispatchs; der angezeigte Dispatch-Anteil verwendet diese Messung. Das Duty-Limit bestimmt die mindestens angeforderte Pause; der macOS-Scheduler kann sie verlängern. Die Startdienst-Einstellung `ProcessType` beeinflusst diese Zeitsteuerung und weitere CPU-/I/O-Beschränkungen. `Interactive` hebt gegenüber `Standard` solche Beschränkungen auf; das konfigurierte GPU-Duty-Limit bleibt bestehen. Eine höhere Suchrate ist kein Nachweis gleicher Leistungsaufnahme.

## Checkpoints und Fortsetzen

Der Standard-Checkpoint heißt `puzzle71_checkpoint.json` und liegt im aktuellen Arbeitsverzeichnis. Bestehende JSON-Checkpoints bleiben lesbar. Neue vollständige Blöcke werden mit `fsync` in `puzzle71_checkpoint.journal` protokolliert; Laufzeit-Updates erfolgen etwa alle zehn Sekunden sowie beim Pausieren und kontrollierten Beenden. Beide Dateien erhalten Unix-Rechte `0600`. Eine exklusive Datei-Sperre verhindert zwei aktuelle Solver-Instanzen im selben Arbeitsverzeichnis.

Ein vollständiger JSON-Snapshot wird stündlich oder bei einem Journal von mindestens 1 MiB erstellt. Erst nach Synchronisierung der neuen Datei und ihres Verzeichnisses wird das Journal gekürzt. Dadurch wird die wachsende Intervallliste nicht mehr alle zehn Sekunden vollständig neu geschrieben. Für Sicherungen und Übertragungen gehören Snapshot und Journal zusammen; den laufenden Solver vorher kontrolliert beenden.

Beim Start werden Puzzle, Suchbereich, Blockgröße, Zähler und Journal-Prüfsummen validiert. Bereits übernommene Journal-Blöcke werden nicht doppelt gezählt. Ein unvollständiger letzter Datensatz wird konservativ entfernt; vollständige beschädigte Datensätze führen zu einem Fehler. Ein laufender Block wird erst nach vollständigem Abschluss dauerhaft als abgedeckt markiert.

Ein übernommener alter Checkpoint belegt weiterhin nur die damals gezählte Suchhistorie. Die korrigierte Metal-Feldarithmetik prüft diese früheren Kandidaten nicht rückwirkend erneut. Für eine vollständige erneute Prüfung ein frisches Arbeitsverzeichnis verwenden und die bisherige Historie getrennt sichern.

## Trefferverhalten und Geheimnisse

Bei einem Metal-Kandidaten stoppt der Suchlauf und leitet eine unabhängige, reine CPU-Verifikation der Adresse und des HASH160 ein. Nur bei erfolgreicher Prüfung wird die private Information lokal in `FOUND_KEY.txt` (oder einem kollisionsfreien Fallback-Namen) mit `0600` gespeichert. Bestehende Trefferdateien werden nicht überschrieben.

Ein Speicherfehler verwirft den bestätigten Kandidaten nicht: Der Prozess behält ihn geschützt im Speicher und wiederholt die Speicherung. Währenddessen zeigt das Dashboard den ausstehenden Speichervorgang und sperrt die Auszahlung. Vollständige sichere Tempdateien werden beim nächsten Start unabhängig verifiziert und erneut gespeichert. Kontrolliertes Beenden wartet auf erfolgreiche Speicherung. Ein erzwungenes Prozessende bei dauerhaft nicht verfügbarem Speicher bleibt eine Grenze dieser Wiederherstellung.

Die Web-API und der Dashboard-Status enthalten bei einem Treffer ausschließlich öffentliche Treffer- und Claim-Informationen — niemals den Private Key oder die signierte Transaktion. Checkpoints enthalten keine privaten Schlüssel. Trotzdem ist das Arbeitsverzeichnis vertraulich zu behandeln: `FOUND_KEY.txt` enthält den Private Key im Klartext. Nicht hochladen, nicht teilen und nicht in Logs, Screenshots oder Backups ohne geeignete Schutzmaßnahmen übernehmen. Eine manuelle Weiterverwendung des Schlüssels sollte offline erfolgen. Der eingebaute Claim-Pfad benötigt Netzwerkzugriff und reicht die signierte Transaktion ausschließlich bei MARA Slipstream ein.

## Sicherheits- und Privacy-Grenzen

- Die Suche und das Dashboard können lokal ohne externe Netzwerkverbindung arbeiten. Der Gesamtprozess ist nicht vollständig offline: Claim-Vorbereitung, Einreichung und Statusabfragen verwenden externe Dienste. Der separate optionale Aufruf `--telegram-test` sendet eine Testnachricht; die Auszahlung benötigt keine Telegram-Konfiguration. Eine Einreichung erfolgt erst nach ausdrücklicher Bestätigung im Dashboard.
- Der Claim-Pfad gleicht UTXOs über mempool.space und blockstream.info ab und reicht ausschließlich bei MARA Slipstream ein. Die Privatsphäre der Einreichung hängt auch vom Verhalten dieses Providers ab. Private Keys werden dafür nicht übertragen; die signierte Transaktion enthält den öffentlichen Schlüssel.
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
cargo run --release --bin puzzle71_solver -- --host 127.0.0.1 --port 8080 --no-tui
cd web-tests
npm install
npx playwright install chromium
npm test
```

Die Playwright-Tests prüfen unter anderem Laden, responsive Layouts, Tastaturfokus, lokale Netzwerkisolation, Moduswechsel, Duty-Limit, Selbsttest sowie, dass ein simuliertes Trefferobjekt keinen Private Key an Seite oder Status-Payload weitergibt.

## Lizenz und Status

In `Cargo.toml` ist derzeit keine Lizenz, Repository-URL oder Veröffentlichungsmetadaten angegeben. Vor einer Weiterverteilung sollte daher eine passende Lizenz- und Herkunftsentscheidung ergänzt werden. Diese README beschreibt den Stand des Codes; sie ersetzt weder eine Sicherheitsprüfung noch eine Finanz-, Steuer- oder Rechtsberatung.
