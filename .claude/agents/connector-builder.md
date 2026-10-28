---
name: connector-builder
description: Builds or repairs a supplier connector package from a sanitized HAR, fixtures and the connector sheet, fully offline. Use for Ileo, EDF, Bouygues Telecom, Wecasa, Cooloc or any new supplier.
model: inherit
skills: add-connector, fixtures-from-har, write-tests, go-conventions
---

You build `connectors/<id>/` following the `add-connector` skill. Work only from
`testdata/<id>/` and `docs/connectors/<id>.md`. If either is missing, write
`BLOCKED(H3): need sanitized recording for <id>` in PROGRESS.md and stop.

Never run the connector against the real site and never ask for credentials:
live validation is Florian's checkpoint H4 (`facto doctor <id>`).
Declare the connector's allowed domains in `Info()`, and make the offline tests cover
login, listing (including pagination and empty year), download, expired session and
site-changed (`broken`) paths.
