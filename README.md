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
--recheck-source <archive.json>        Gebundene Nachprüfung eines alten Checkpoints fortsetzen
--prepare-recheck-from <copy.json>     Neuen Nachprüfungsstand aus einer angehaltenen Historienkopie vorbereiten
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
| `high` | 85 % | höhere angeforderte GPU-Aktivzeit |
| `full` | 90 % (Obergrenze) | höchstes Duty-Limit, weiterhin mit Leerlaufzeit |
| `auto` | startet bei 70 % | passt sich per Systemlast und geschätzter Package-Power geglättet an |

Die Power- und Temperaturwerte im Dashboard sind Schätzwerte aus Prozess-/Systemlast und einem Modell; sie sind keine Messung eines externen Wattmeters oder Temperatursensors.

`BALANCED` und `AUTO` verwenden bis zu 2.097.152 Schlüssel pro Dispatch (2.048 Threads × 1.024 Schritte). Im begrenzten Vergleich auf einem Apple M4 mit festem `BALANCED`-Duty von 70 % stieg die dauerhaft verbuchte Suchrate in jeweils zwei Minuten um 18,51 %. Gegenläufige längere Messpaare ergaben 15,57 % und 16,50 %. Gleiche physische Leistungsaufnahme wurde dabei nicht nachgewiesen. Eine Pause wirkt nach dem laufenden Dispatch; im Test dauerte dies höchstens 0,227 Sekunden. Die Auto-Glättung erfolgt pro Dispatch und benötigt mit größeren Dispatches mehr Zeit.

Die Status-API meldet die tatsächlich gemessene Leerlaufzeit des letzten Dispatchs; der angezeigte Dispatch-Anteil verwendet diese Messung. Das Duty-Limit bestimmt die mindestens angeforderte Pause; der macOS-Scheduler kann sie verlängern. Die Startdienst-Einstellung `ProcessType` beeinflusst diese Zeitsteuerung und weitere CPU-/I/O-Beschränkungen. `Interactive` hebt gegenüber `Standard` solche Beschränkungen auf; das konfigurierte GPU-Duty-Limit bleibt bestehen. Eine höhere Suchrate ist kein Nachweis gleicher Leistungsaufnahme.

## Checkpoints und Fortsetzen

Der Standard-Checkpoint heißt `puzzle71_checkpoint.json` und liegt im aktuellen Arbeitsverzeichnis. Bestehende JSON-Checkpoints bleiben lesbar. Neue vollständige Blöcke werden mit `fsync` in `puzzle71_checkpoint.journal` protokolliert; Laufzeit-Updates erfolgen etwa alle zehn Sekunden sowie beim Pausieren und kontrollierten Beenden. Beide Dateien erhalten Unix-Rechte `0600`. Eine exklusive Datei-Sperre verhindert zwei aktuelle Solver-Instanzen im selben Arbeitsverzeichnis.

Ein vollständiger JSON-Snapshot wird stündlich oder bei einem Journal von mindestens 1 MiB erstellt. Erst nach Synchronisierung der neuen Datei und ihres Verzeichnisses wird das Journal gekürzt. Dadurch wird die wachsende Intervallliste nicht mehr alle zehn Sekunden vollständig neu geschrieben. Für Sicherungen und Übertragungen gehören Snapshot und Journal zusammen; den laufenden Solver vorher kontrolliert beenden.

Beim Start werden Puzzle, Suchbereich, Blockgröße, Zähler und Journal-Prüfsummen validiert. Bereits übernommene Journal-Blöcke werden nicht doppelt gezählt. Ein unvollständiger letzter Datensatz wird konservativ entfernt; vollständige beschädigte Datensätze führen zu einem Fehler. Ein laufender Block wird erst nach vollständigem Abschluss dauerhaft als abgedeckt markiert.

Ein übernommener alter Checkpoint belegt weiterhin nur die damals gezählte Suchhistorie. Die korrigierte Metal-Feldarithmetik prüft diese früheren Kandidaten nicht automatisch rückwirkend erneut. Für eine gezielte Nachprüfung wird ein neuer, an das genaue Archiv gebundener Arbeitsstand vorbereitet. Er prüft dessen Blöcke trotz bestehender globaler Einträge erneut und zählt sie dabei nicht nochmals als neue Abdeckung. Erst vollständig berechnete und synchronisierte Blöcke erhöhen den getrennten Nachprüfungszähler. Danach geht derselbe Arbeitsstand automatisch zur zufälligen Suche neuer Bereiche über.

Vorbereitung: Den laufenden Solver kontrolliert beenden, Snapshot **und** Journal gemeinsam in ein eigenes privates Kopieverzeichnis sichern und das unveränderte alte Archiv getrennt erhalten. Im folgenden Beispiel sind alle Pfade absolute Pfade; das aktuelle Verzeichnis `recheck-run` muss frisch sein. Die Blockgröße muss zur kopierten Historie und zum Archiv passen.

```sh
mkdir -m 700 recheck-run
cd recheck-run
/pfad/zum/puzzle71_solver --recheck-source /pfad/zum/legacy_source.json --prepare-recheck-from /pfad/zur/historienkopie/puzzle71_checkpoint.json --block-size 16777216
/pfad/zum/puzzle71_solver --recheck-source /pfad/zum/legacy_source.json --block-size 16777216 --mode balanced
```

Die Vorbereitung startet weder GPU-Suche noch Auszahlung. Sie verlangt vorhandene, gültige Snapshot-/Journalkopien und lehnt bereits vorhandene Zieldateien ab. Archive mit fehlenden Blöcken in der kopierten globalen Historie werden abgelehnt. Das Archiv wird nur gelesen; keine Produktionsdatei als Historienkopie angeben. Die Nachprüfung bindet genaue Archivbytes, Blockgröße, Puzzlebereich, Ziel-HASH160 und eingebetteten Kernel. Eine abweichende Quelle oder ein ungekennzeichneter Arbeitsstand startet keine frische Suche.

Für ausdrücklich **unbestätigte** Zielblöcke akzeptiert dasselbe `--recheck-source` außerdem einen versionierten JSON-Suchauftrag. Er ist kein Checkpoint und behauptet keine vergangene Abdeckung. Das folgende Beispiel verwendet `2^24` Schlüssel pro Block:

```json
{
  "type": "puzzle71-unverified-targets",
  "format": 1,
  "puzzle_number": 71,
  "range_min": "1180591620717411303424",
  "range_max": "2361183241434822606847",
  "block_size": "16777216",
  "target_hash160": "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8",
  "block_indices": [7, 2, 88, 1]
}
```

Alle Felder sind verpflichtend; zusätzliche Felder, unbekannte Typen oder Versionen, doppelte IDs und IDs außerhalb des Puzzlebereichs werden abgelehnt. Bereichsgrenzen und Blockgröße sind kanonische dezimale Strings, Block-IDs sind JSON-Integer vom Typ `u64`. Die Liste muss mindestens eine ID enthalten. Die Reihenfolge bleibt exakt erhalten, auch zwischen unsortierten Gruppen; sie wird nicht nach IDs sortiert. Öffentliche Herkunftsbelege und SHA256-Werte der Originalarchive können separat aufbewahrt werden. Sie ändern den Suchauftrag nicht in eine Bestätigung alter Sucharbeit.

Vorbereiten und starten erfolgt mit denselben Befehlen wie beim Archiv, mit dem Suchauftrag als Quelle. Die Vorbereitung übernimmt ausschließlich die echte kopierte Historie und fügt durch die Zielliste **keinen** globalen Block hinzu. Ein bereits global vorhandener Zielblock wird trotzdem erneut geprüft; ein bisher fehlender Zielblock erhöht erst nach vollständig abgeschlossener Berechnung und synchronisiertem Journaleintrag die globale Abdeckung. Pausen und Teilblöcke erhöhen den Zielcursor nicht. Bei Wiederaufnahme muss jeder Block des bereits abgeschlossenen Zielpräfixes global enthalten sein, einschließlich bei vollständig abgearbeiteter Liste. Der Legacy-Archivpfad verlangt weiterhin sämtliche Archivblöcke in der kopierten und fortgesetzten globalen Historie.

Für die Wiederaufnahme gehören die unveränderte Quelle, der neue Snapshot und sein Journal zusammen. Genaue Quelldateibytes, Kernel und Puzzleparameter bleiben gebunden. Die Oberfläche zeigt gezählte globale Historie und Nachprüfungsfortschritt getrennt. Legacy-Archivstände verwenden Wrapper-/Journalformat 2, Suchaufträge für unbestätigte Ziele verwenden Format 3. Ältere Programme können die jeweils neueren Stände nicht laden. Ein bestehender Format-2-Arbeitsstand wird nicht in einen neuen Suchauftrag umgewandelt; dafür ist eine neue Vorbereitung aus einer angehaltenen Legacy-Historienkopie erforderlich. Bei einem Rückbau müssen deshalb auch Startargumente und Arbeitsverzeichnis zum jeweiligen Programmstand passen. Einen bestehenden aktuellen Arbeitsstand weiter sichern; ihn nicht durch eine alte Kopie ersetzen.

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
