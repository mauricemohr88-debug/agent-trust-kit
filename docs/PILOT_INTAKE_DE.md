# Intake — Agent Handoff Safety Review

Dieses kurze Formular wird **vor Zahlung und Start** gemeinsam ausgefüllt. Es ist
eine operative Scope-Bestätigung, keine Rechts- oder Compliance-Beratung.

## Kunde und Rechnung

- Name / Unternehmen:
- Rechnungsanschrift:
- E-Mail:
- Ansprechpartner für Rückfragen:

## Vereinbarter technischer Stand

- Repository und Sprache (Python, JavaScript oder TypeScript):
- Unveränderliche Revision (vollständige Commit-ID oder bereitgestelltes Archiv):
- Maximal drei relevante Verzeichnisse:
  1.
  2.
  3.
- Geschätzte relevante Codezeilen, maximal rund 20.000:
- Ein zu prüfender Handoff-Workflow:
- Wichtigster befürchteter Fehler oder Datenabfluss:
- Ein gewünschter controllerseitiger Check:
- Hermes-Plugin im Scope: ja / nein

## Sichere Bereitstellung

Der Kunde bestätigt:

- Er darf den vereinbarten Code für diesen Review bereitstellen.
- Der Teststand enthält keine echten API-Schlüssel, Zugangsdaten,
  Produktivzugänge oder unnötigen Kundendaten.
- Abhängigkeiten, Build-Artefakte und nicht benötigte Verzeichnisse wurden nach
  Möglichkeit entfernt.
- Maurice soll keine Befehle aus dem Repository ausführen, außer dem einen
  nachfolgend ausdrücklich vereinbarten Check.

Vereinbarter exakter Check oder „keiner“:

```text

```

## Lieferumfang und Abnahme

Für 149 € (zzgl. USt., falls anwendbar) werden geliefert:

- ein priorisierter Kurzreport auf der vereinbarten Revision;
- eine Include-/Deny-Policy für den vereinbarten Handoff;
- genau ein lokal reproduzierbarer Controller-Check;
- 30 Minuten Ergebnisübergabe;
- 7 Tage Rückfragen zum gelieferten Bericht.

Nicht enthalten sind Fix-Implementierung, CI-Integration, ein vollständiges
Repository- oder Plugin-Sicherheitsaudit, Penetrationstest, Zertifizierung oder
Erfolgsgarantie. Zusätzliche Arbeit braucht vorab ein separates Angebot.

Die 48-Stunden-Frist beginnt, wenn Zahlung, bereinigter Teststand und diese
schriftliche Scope-Bestätigung vollständig vorliegen.

- Scope bestätigt am:
- Zahlung geklärt am:
- Lieferfrist endet am:
- Bestätigt durch Kunde:
- Bestätigt durch Maurice:
