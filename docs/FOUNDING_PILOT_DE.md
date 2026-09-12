# Pausiert: Agent Handoff Safety Review — Founding Pilot

**Status seit 12.09.2026: pausiert, kein aktives Angebot.** Es werden über diese
Seite keine neuen Reviews, Zahlungen oder Termine angenommen. Die damaligen
149 € und die 48-Stunden-Frist unten dokumentieren nur den historischen Umfang;
sie sind keine aktuelle Preis- oder Lieferzusage. Bereits separat vereinbarte
Verpflichtungen werden durch diese Dokumentation nicht verändert.

Aktuell gesucht: zwei kostenlose, asynchrone Tests eines nicht vertraulichen
Handoffs, mit Feedback in
[Issue #3](https://github.com/mauricemohr88-debug/agent-trust-kit/issues/3).
Es gibt dafür keinen Verkaufscall. Der vollständige lokale OSS-Kern bleibt frei.

## Historischer Angebotsumfang — nicht buchbar

**149 € Festpreis** (zzgl. USt., falls anwendbar) · **Lieferung innerhalb von 48
Stunden** nach Zahlung, bereinigtem Intake und schriftlicher Scope-Bestätigung ·
zunächst 3 Plätze

Für Solo-Founder und kleine KI-Automationsagenturen, die Hermes, OpenClaw, Codex
oder andere Agenten an Repositories und Remote-Worker lassen.

## Das Problem

Ein Agent bekommt schnell zu viel Kontext, ein Archiv enthält versehentlich eine
`.env`, oder ein Worker meldet „Tests grün“, ohne dass der Controller es unabhängig
geprüft hat. Der Pilot macht einen konkreten Handoff enger, nachvollziehbarer und
reproduzierbar prüfbar.

## Enthalten

- Aufnahme eines echten Handoff-Workflows auf einer unveränderlichen Revision;
- statische Prüfung der Übergabe- und Datenabflussrisiken im vereinbarten Bereich;
- priorisierter Kurzreport mit P0/P1/P2-Befunden und Restrisiken;
- konkrete Include-/Deny-Policy für den gewählten Workflow;
- genau ein controllerseitig definierter, lokal reproduzierbarer Check;
- 30 Minuten Ergebnisübergabe und 7 Tage Rückfragen.

## Fester Umfang

- ein Python-, JavaScript- oder TypeScript-Repository;
- eine unveränderliche Revision und ein Handoff-Workflow;
- höchstens drei relevante Verzeichnisse beziehungsweise rund 20.000 relevante
  Codezeilen;
- Hermes-Plugin-Prüfung nur, wenn der vereinbarte Bereich tatsächlich ein
  Hermes-Plugin enthält.

Größere oder andere Umfänge werden vor Beginn separat angeboten.

## Nicht enthalten

Kein vollständiges Repository- oder Plugin-Sicherheitsaudit, kein
Penetrationstest, keine Zertifizierung, keine Rechts- oder Compliance-Beratung
und keine Garantie gegen Geheimnisse, Schadcode oder einen kompromittierten
Worker. Fix-Implementierung und CI-Integration sind nicht im Festpreis enthalten.
Produktivzugänge, echte API-Schlüssel und Kundendaten werden nicht benötigt und
sollen nicht geteilt werden.

## Ablauf

1. 15-minütiger Start: Workflow, Revision, Scope und wichtigster Risikofall.
2. Review und reproduzierbare Checks auf einem vereinbarten Teststand.
3. Bericht, Konfiguration und 30-minütige Übergabe binnen 48 Stunden.

Vor dem Start werden der [Intake](PILOT_INTAKE_DE.md) schriftlich bestätigt und
für die Lieferung die [Report-Vorlage](REVIEW_REPORT_TEMPLATE.md) verwendet.

## Founding-Preis

Der Preis gilt nur für den oben beschriebenen festen Umfang. Zusätzliche
Implementierung oder CI-Integration wird vor Beginn separat angeboten. Als
Gegenleistung für den Founding-Preis wünsche ich mir ehrliches Feedback; eine
öffentliche Nennung oder ein Testimonial ist freiwillig.

Der frühere DM-Aufruf ist zurückgezogen. Eine mögliche Wiederaufnahme dieses
Serviceangebots braucht eine neue ausdrückliche Entscheidung; dieses Dokument
startet weder Akquise noch eine Lieferfrist.
