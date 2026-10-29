# 0007. J0 product decisions (spec gaps)

- Status: Accepted (Florian, 2026-10-28); may be revised in later milestones
- Date: 2026-10-28
- Deciders: Florian

## Context
Implementing J0 (inbox filing, config, orchestrator) hit questions `docs/spec.md` leaves
open. They are settled here so tests can pin the behaviour (plan T6; used by T13, T22,
T24, T25). No dependency is involved.

## Decisions

### D1. State directory
Default `~/.facto` (index, reports, logs, sessions), overridable with the `state_dir`
config key. Config validation refuses a state dir that is inside the output folder or
inside a synced folder (e.g. a Google Drive for desktop path).
*Rationale:* the spec says `.facto/` is "never synced, outside the output folder"; a
fixed home path makes that the default, and validation stops a user config from undoing
it. Overridable for multi-profile or test setups.

### D2. Inbox files identified only by subfolder
A file in `inbox/<provider>/` whose name and content give no date: no date is guessed
(no file mtime, no "today"). Interactive mode asks provider/date via the `Prompter`;
non-interactive mode leaves the file in `inbox/` with a warning in the report.
*Rationale:* a wrong date files a document in the wrong year, which is worse than a
visible leftover; the spec already leaves unknown files in `inbox/` in scheduled mode.

### D3. Factur-X provider id
When Factur-X gives the seller, provider id = slug of the seller name (same slug rules
as naming: lowercase ASCII, hyphens).
*Rationale:* deterministic, no lookup table in J0; a mapping to known connector ids can
come later without changing file names of known providers.

### D4. Unknown provider category
A provider with no configured category is filed under category `other`.
*Rationale:* the path stays `{year}/{category}/{provider}` without an empty segment, and
the spec rule "missing fields are omitted, never unknown" applies to file names, not to
the directory layout.

### D5. `collect` with zero connectors
`facto collect` with no enabled connector exits 0 (it still processes `inbox/`).
*Rationale:* in J0 the inbox is the only source; exit 2 is reserved for configuration
errors and an empty connector list is valid.

## Alternatives considered
- D1: state under the output folder (spec forbids, syncs secrets-adjacent data);
  OS-specific state dirs (`XDG_STATE_HOME`…): deferred, possible via `state_dir`.
- D2: use file mtime (unreliable after copy/download).
- D3: refuse unknown sellers (loses the main Factur-X benefit for inbox drops).
- D4: refuse the file; `unknown` category (contradicts the spirit of the naming rule).
- D5: exit 2 "nothing to do" (breaks scheduled runs on inbox-only setups).

## License
Not applicable (no dependency).

## Maintenance
Revisit at each milestone close; any change updates this ADR and the related tests.

## Consequences
Tests: `TestValidate_StateDirInsideOutputRefused`, `TestValidate_StateDirInSyncedFolderRefused`,
`TestInfer` table, `TestRun_*` exit codes, `inbox` e2e scenario (case e).
