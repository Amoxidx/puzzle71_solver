# Dashboard-Tests (Playwright)

Die Suite spricht den bereits laufenden Solver auf Port 8080 an. Sie startet ihn nicht selbst.

Voraussetzung: Solver lokal gestartet

```
cd .. && ./puzzle71_solver --host 127.0.0.1 --port 8080 --no-tui
```

Dann:

```
cd web-tests && npm install && npx playwright install chromium && npm test
```

Chromium reicht. Die Tests laufen seriell (ein Worker), weil sie denselben Solver-Prozess umschalten und am Ende Modus sowie Lauf-Zustand auf die anfangs gelesenen Werte zurücksetzen. Für eine andere lokale Instanz kann `PLAYWRIGHT_BASE_URL` gesetzt werden.
