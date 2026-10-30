# 0009. Session vault: XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`)

- Status: Accepted
- Date: 2026-10-29
- Deciders: Florian (via J1 plan T2)

## Context
The spec (Security, Data at rest) persists supplier cookies and tokens per connector,
AEAD-encrypted with a random 256-bit key kept in the OS keyring or password manager, so a
scheduled run can skip login while the session is valid. It named "XChaCha20-Poly1305 or
`age`" and a `<connector>.age` file without choosing. J1 builds `internal/vault` (T14,
T16) and needs one format, one key source, a rotation rule and an ephemeral mode.

Florian's J1 decisions bind this ADR: A1 (file extension `.sess` whatever the cipher),
A2 (new key and nonce on every successful login, crash-safe order), A3 (file key source
only behind the `e2e` build tag, no keyring in production means ephemeral sessions plus a
warning, systemd-creds deferred to J2), A13 (`sessions: ephemeral` deletes an existing
session file at startup without reading it, logged once).

Constraints: CLAUDE.md rule 5 (files only through `internal/fsx`, secrets only as
`secret.Secret`), rule 6 (no new dependency without an ADR), no CGO (ADR 0004). The
protected asset is a single small blob (cookie jar + tokens) per connector, written by
facto and read only by facto on the same machine: no interoperability with other tools
is needed.

Facts below were checked on 2026-10-29 with `go list -m -json <module>@latest`,
`go list -m -versions`, and a scratch module outside the repository (`go get` + `go list
-deps`); licenses were read from the module cache (`~/go/pkg/mod`). The repository's
`go.mod`/`go.sum` were not touched. Toolchain: `go 1.27.3` (repo `go.mod`).

## Decision
**XChaCha20-Poly1305 from `golang.org/x/crypto/chacha20poly1305` v0.58.0** (2026-10-09,
already in `go.mod` as `// indirect`; it becomes a direct requirement in T14, same
version, no new module in the build). Wrapped by `internal/vault`; nothing else imports
`chacha20poly1305`. API used: `chacha20poly1305.NewX(key)` (`xchacha20poly1305.go:24`),
`KeySize = 32`, `NonceSizeX = 24`, `Overhead = 16` (`chacha20poly1305.go:17,28,32`). The
package doc recommends XChaCha20-Poly1305 "whenever nonces are randomly generated"
(`xchacha20poly1305.go:20-23`): a 192-bit random nonce makes collisions negligible
without a counter to persist.

### File format (version 1)
```
offset  size  field
0       8     magic        ASCII "FACTOSES" (46 41 43 54 4F 53 45 53)
8       1     version      0x01
9       24    nonce        crypto/rand, fresh for every Seal
33      n+16  ciphertext   XChaCha20-Poly1305(key, nonce, plaintext, AAD), tag appended
```
- **AAD** = magic ‖ version ‖ install id ‖ connector id, raw bytes, no separator. Magic
  (8), version (1) and install id (32) are fixed-length; the connector id (ASCII, 1 to 40
  bytes) is the last field. The encoding is therefore unambiguous; the AAD is at most 81
  bytes. Consequences: a file copied from `sessions/edf.sess` to `sessions/ileo.sess`
  fails to open even if both keys were equal; a file copied from another state directory
  fails to open even under the right connector id; a header byte flipped from version 1
  to another value fails authentication instead of being parsed under other rules.
- **Install id:** 16 bytes from `crypto/rand`, stored as 32 lowercase hex chars in
  `<state_dir>/install-id` (0600, created once with `fsx.WriteNew`, never rewritten). Not
  a secret. A missing file means no saved session; a file that is not exactly 32
  lowercase hex chars disables persistent sessions for the run (one warning) and is not
  overwritten.
- The connector id must match the registry rule `^[a-z0-9]+(-[a-z0-9]+)*$`, at most 40
  bytes (`internal/connector`); Seal and Open refuse anything else.
- **Sizes.** The AAD is authenticated, not stored: it does not change the file size.
  Header 33 bytes, overhead 16, so minimum file 49 bytes (empty plaintext refused by
  Seal). Maximum file size **1 MiB (1 048 576 bytes)**, hence maximum plaintext
  1 048 527 bytes. Open reads through `io.LimitReader(f, max+1)` and refuses an oversized
  or truncated file before any decryption; Seal refuses an oversized plaintext. A session
  jar is a few KiB; the cap bounds memory on a hostile file.
- **Open order:** size check → magic → version == 1 → AEAD open with the AAD. A format or
  authentication failure returns one error (`vault.ErrInvalid`) with no detail about which
  check failed and no byte of the file in the message.
- **Unknown version.** A file with a version this binary does not know (for example
  written by a newer facto, then read after a downgrade) is `ErrInvalid`: never a
  fallback, the file is removed and the user logs in again.
- **Buffers.** Open decrypts in place and never returns partial output: on failure the
  caller gets `ErrInvalid` and no plaintext. Seal wipes the plaintext buffer after
  sealing. The plaintext encoding (cookie jar, tokens) is owned by T16 and is opaque
  here. Decrypted plaintext is returned as `secret.Secret` and wiped by the caller after
  use.

### Key source
- **Production:** one random 256-bit key per connector (`crypto/rand`), stored in the OS
  keyring under service `facto-session`, user `<install-id>/<connector-id>`, and resolved
  through `internal/secret` (keyring provider, ADR 0005) as a `secret.Secret`. The
  install id scopes the entry to one state directory: two state dirs on the same account
  never share or overwrite a key. Writing needs `Set`, ephemeral cleanup needs `Delete`;
  both are added to the keyring provider by T15 (SEC-J0-23), bounded like `Get`. The key
  never touches disk, a log, argv or env.
- **Key encoding.** The keyring holds strings, so the key is stored base64url without
  padding (43 chars). It is decoded with `base64.RawURLEncoding.Strict()` and must give
  exactly 32 bytes; anything else means "no session" (no Open is attempted, the file is
  kept for the next Save to replace).
- **Wiping is best effort.** go-keyring returns and takes the key as a Go string, so the
  encoded form lives in immutable memory facto cannot wipe. Only the decoded 32-byte
  buffer (after Seal/Open) and plaintext buffers are wiped.
- **e2e only:** a file key source in its own package `internal/vault/e2ekey` (key file
  0600 in a 0700 test directory via `internal/fsx`). It is registered only through a
  blank import in a `//go:build e2e` file; no config value or other runtime string can
  select it. `make release-e2e-check` (T17, run by `make verify`; separate from the goreleaser
  `make release-check`) fails if either check hits:
  `go list -deps` with the release build flags lists `internal/vault/e2ekey`, or
  `go tool nm` on the release binary shows the package's sentinel symbol (referenced at
  registration so the linker keeps it). Self-test: the same check run with `-tags e2e`
  must hit both, otherwise release-check fails (A3).
- **No keyring in production** (backend unavailable or unsupported, as opposed to "entry
  not found"): the run uses ephemeral sessions for every connector and logs **one**
  warning naming the cause. This fallback never deletes or writes anything, neither in
  `sessions/` nor in the keyring. No file key source, no derived or hard-coded key. A
  `systemd-creds` key source (spec: `secrets.fallback: file`) is deferred to J2 and will
  extend this ADR or supersede it.
- **Errors.** A missing file, a missing key, a malformed key or an `ErrInvalid` file all
  mean "no saved session": the connector logs in again (`needs_login` in non-interactive
  mode). Only `ErrInvalid` (format or authentication failure) removes the file, via
  `fsx`, and logs the fact (not the content). A read I/O error and a keyring backend
  error are distinct errors, not `ErrInvalid`: the file is kept and the run continues
  without the session.

### Rotation (A2)
On every successful login, Save generates a **new key and a fresh nonce**. Each (key,
nonce) pair is used once by construction: a key seals exactly one blob. Safety still
rests on `crypto/rand` for the key. Order, chosen to be crash-safe:

0. Take an exclusive per-connector lock through `fsx` (`sessions/<id>.lock`), held around
   steps 2 to 4. A scheduled `collect` and a manual `facto login` may save the same
   connector at once; without the lock, interleaved Set/write could pair a file with the
   other process's key, and the outcome would still only be a re-login.
1. Generate the new key and Seal the new blob in memory.
2. Write the new key to the keyring (`Set`, bounded by T15). If it fails: abort the save,
   leave the old file and old key untouched (still a consistent pair), log a warning. If
   it times out: abort the save the same way, but the state is unknown, because
   go-keyring's goroutine may still complete the write later. If it does, the old file
   fails authentication at the next Open, is removed, and the user logs in again.
3. Write `sessions/<id>.sess` with `fsx.WriteAtomic` (temp file 0600 + rename). This is the
   commit point.
4. If step 3 fails: remove the old file (it is now undecryptable) via `fsx`, log a warning.

Crash between 2 and 3: the old file is under a key that no longer exists, Open fails with
`ErrInvalid`, the file is removed and the user logs in again. Crash during 3: the atomic
rename leaves either the old file (same case) or the complete new one. The reverse order
(file first, then key) has the same crash outcome but a failed keyring `Set` would leave a
freshly written file nobody can open and the previous pair already destroyed; key-first
keeps the old pair intact on a reported keyring error and makes the atomic rename the
single commit point. In every case (failure, timeout, crash, concurrent save) the worst
outcome is a re-login, never plaintext on disk and never a reused (key, nonce).

**Anti-rollback.** Rotation replaces the key, so an older `.sess` (backup, synced copy,
restored snapshot) fails authentication once its key is replaced.

### Ephemeral mode (A13)
With `sessions: ephemeral`, at startup facto lists `sessions/` with `fsx` `ReadDir` and
removes every `*.sess` found, configured connector or not, **without opening or reading
it**. For each removed file whose name is a valid connector id, it deletes the keyring
entry `<install-id>/<connector-id>` with `Delete` (T15), **without reading it**. It logs
one line for the run (count removed, no content). Keys are deleted only when a keyring is
usable and `install-id` is valid; with `sessions: ephemeral` and no usable keyring, the
`*.sess` files are still removed unopened (the user chose ephemeral), no keyring call is
made, and the same single line is logged (J1 T16 decision). The "no keyring in
production" fallback above applies to persistent mode only. Nothing is written to `sessions/` and
no key is read or written in the keyring during the run.

Leftover keys are **not** harmless: any backup or synced copy of the `.sess` stays
decryptable while its key exists. That is why ephemeral mode deletes the keys too.

### File location (A1)
`<state_dir>/sessions/<connector-id>.sess`, directory 0700 created with
`fsx.MkdirPrivate`, file 0600 written with `fsx.WriteAtomic`, read with
`fsx.OpenRegular` (regular files only). The id is validated against the registry rule
before use and also passed through `fsx.SafeName` (traversal refused, T16
`_IDTraversalRefused`). The lock file `sessions/<id>.lock` (0600) holds no data.
`<state_dir>/install-id` is described under File format.

### Residual risk
Any process running as the same user can read the keyring entry and the file. The vault
protects against file leaks, backups and synced folders, not against malware running as
the user.

### Tests required
- **T14:** `TestOpen_OtherStateDirFileRejected` (same id and key, other install id in the
  AAD).
- **T15:** `Delete` gets the same bounded, cancellable tests as `Get` and `Set`.
- **T16:** `TestStore_EphemeralDeletesExistingUnread` (zero opens, zero `Get`, one
  `Delete` per id, one log line), `_EphemeralRemovesUnconfiguredSessions`,
  `_KeyringBackendErrorKeepsFile`, `_ReadErrorKeepsFile`,
  `_NoKeyringFallbackDeletesNothing`, `_SetTimeoutThenLateWriteMeansRelogin`,
  `_ConcurrentSavesLeaveOpenablePair`, `_MalformedKeyIsNoSession`,
  `_RollbackToPreviousFileFails`.
- **T17:** `TestReleaseBuild_HasNoE2EOnlyCode` plus its self-test (`-tags e2e` build must
  hit both `go list -deps` and the `go tool nm` sentinel).

### Never: `golang.org/x/crypto/openpgp`
Not an option and banned by depguard in all files, tests included (T3). Reasons: the
package is deprecated in place, its doc says "this package is unsafe by design, and has
numerous known security issues. It is not maintained, and should not be used"
(`golang.org/x/crypto@v0.58.0/openpgp/read.go:7-9`, same notice in `armor`, `packet`,
`s2k`, `clearsign`, `errors`; `elgamal` is deprecated with its own notice,
`elgamal.go:14`); `osv-scanner.toml` currently ignores
GO-2026-5932, which covers only `golang.org/x/crypto/openpgp/*`, on the claim that facto
never compiles it, and the depguard rule turns that claim into a gate; OpenPGP brings
packet parsing, key management and legacy ciphers we do not need for a single-reader blob.

## Alternatives
| Option | Why not |
| --- | --- |
| `filippo.io/age` v1.3.2 (2026-08-29) | Sound design, but it adds two modules to the build (`filippo.io/age`, `filippo.io/hpke` v0.4.0) for features we do not use (multi-recipient header, STREAM chunking, plugins). No AAD: binding a file to its connector would need an id inside the plaintext checked after decryption. Its scrypt mode takes the passphrase as `string` (`NewScryptRecipient(password string)`, `scrypt.go:39`) and costs ~1 s per open (work factor 18, `scrypt.go:46`); its X25519 mode with a "random key in keyring" means storing an `AGE-SECRET-KEY-1…` string and parsing it with `ParseX25519Identity(s string)` (`x25519.go:142`), i.e. an asymmetric layer (ephemeral X25519 + HKDF wrapping a random file key) on top of ChaCha20-Poly1305 to protect a blob encrypted and read by the same process. Internally it uses the same `x/crypto/chacha20poly1305` we use directly |
| stdlib AES-256-GCM (`crypto/cipher`) | No dependency. `cipher.NewGCMWithRandomNonce` exists in the toolchain (`$GOROOT/src/crypto/cipher/gcm.go:89`, go1.27.3): 96-bit random nonce prepended, Overhead 28, and its doc limits a key to 2^32 messages because of random-nonce collision risk. Acceptable with one Seal per key, but the 96-bit nonce leaves no margin if the one-key-one-seal rule is ever relaxed, while XChaCha20's 192-bit nonce is safe with random nonces at any volume; constant-time speed depends on AES hardware support, ChaCha20 does not. Kept as fallback if `x/crypto` ever has to leave the build |
| `golang.org/x/crypto/openpgp` | Never; see above |
| systemd-creds key source | Linux-only, needs its own design for scheduled runs; deferred to J2 (A3) |

## License
- `golang.org/x/crypto` v0.58.0: BSD-3-Clause (LICENSE read, "Neither the name of Google
  LLC" clause). Packages compiled: `chacha20poly1305`, `chacha20`, `internal/poly1305`,
  `internal/alias`.
- `golang.org/x/sys` v0.49.0: BSD-3-Clause, already in `go.mod` and already compiled.
  Packages used: `cpu` (by chacha20poly1305), `unix` (`Flock`) and `windows`
  (`LockFileEx`/`UnlockFileEx`) by `internal/fsx` for the session lock (T16, direct
  requirement since then).
- No other module is added. For reference, the rejected `filippo.io/age` v1.3.2 is
  BSD-3-Clause (LICENSE read: "Neither the name of the age project") and
  `filippo.io/hpke` v0.4.0 is BSD-3-Clause (LICENSE read).

## Maintenance
- `golang.org/x/crypto`: Go team, part of the Go project. Recent releases from the proxy:
  v0.55.0 (2026-08-11), v0.56.0 (2026-09-02), v0.57.0 (2026-09-08), v0.58.0 (2026-10-09,
  latest). Roughly monthly cadence. The repository already compiles the stdlib-vendored
  copy (`vendor/golang.org/x/crypto/chacha20poly1305`, imported by `crypto/tls` and
  `crypto/hpke`) and `golang.org/x/crypto/ocsp` (via pdfcpu).
- `filippo.io/age` (rejected): latest v1.3.2 (2026-08-29); v1.3.0 2025-12-27, v1.3.1
  2025-12-28, v1.2.1 2024-12-18, v1.2.0 2024-06-16; 19 tagged versions including betas
  and release candidates.
- Risk: a future x/crypto advisory affecting chacha20poly1305 is handled by govulncheck
  and a version bump; the file format does not depend on the library.

## Consequences
- `golang.org/x/sys` v0.49.0 moves from indirect to direct in `go.mod` (T16): `internal/fsx`
  uses `unix.Flock` and `windows.LockFileEx`/`UnlockFileEx` for the per-connector session
  lock. Same version, BSD-3-Clause, `go.sum` unchanged, no new module.
- `golang.org/x/crypto` moves from indirect to direct in `go.mod` (T14); `go.sum` already
  holds both v0.58.0 hashes (module and `go.mod`), so no new checksum is expected.
- `internal/vault` (T14): `Seal(ctx, installID, id, key, plaintext)` /
  `Open(ctx, installID, id, key, file)` with the tests listed in J1 T14 and under Tests
  required; the format is pinned by golden files. T16 adds the store, install id, key
  source, lock, rotation and ephemeral mode with the tests listed in J1 T16 and above.
- The J1 plan lists keyring `Get`/`Set` for T15; this ADR also needs `Delete` there.
- T3 adds the depguard ban on `golang.org/x/crypto/openpgp` and a lint self-test; the
  GO-2026-5932 ignore in `osv-scanner.toml` then rests on a gate, not a claim.
- A format change (new cipher, new AAD, larger cap) bumps the version byte; version 1
  files are then treated as "no session" (re-login), never migrated in clear.
- `docs/spec.md` now names `sessions/<connector>.sess` and points here.
- `Store.Delete(ctx, id)` (T18) drops a saved session the supplier rejected: id checked
  first, `sessions/` created 0700 if missing, then under the per-connector lock (always
  taken, like Save, so a Delete never races a first Save's key) `sessions/<id>.sess` is
  removed without being opened and the keyring key Deleted. Missing file or key is not an error; a keyring error
  wraps `ErrKeyring` (the file is already gone, the orphan key opens nothing); no-op when
  the store is not persistent.
- Headless Linux without Secret Service gets ephemeral sessions until the J2 systemd-creds
  key source exists.
