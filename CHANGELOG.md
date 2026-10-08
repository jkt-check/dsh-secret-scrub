# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-10-09

Kaya-parity release: user input is now scrubbed aggressively by default, and
the tier-0 net catches the generic key shapes that previously slipped through
(a pasted CN phone number, a lowercase `deepseek_api_key=sk_…` assignment).

### Added

- `inputLevel` config (default `aggressive`): admitted user messages at
  `agent/pre-step` are scrubbed at this depth regardless of `level`, so pasted
  PII and credentials are redacted with the full rule table even when tool
  output stays at `balanced`. `level` now governs tool output only.
- Tier-0 rules: `api-key` (generic `apikey` assignments — `=`, `:`, and JSON
  quoted forms, claimed inside longer names like `deepseek_api_key=…`),
  `rollbar-token`, `slack-signing-secret`, `slack-webhook-url`,
  `age-secret-key`, `docker-pat`, `notion-token`, `supabase-token`,
  `linear-api-key`, `private-key-truncated` (unclosed/orphaned PEM armor),
  `generic-sk-key` (`sk-`/`sk_` fallback after every provider-specific rule).
- Tier-1 rule: `key-assignment` — the `NAME=value` secret shape in any letter
  case (the lowercase/mixed-case forms `env-var-secret` cannot see), with a
  value filter that spares code shapes (`token = 5`, `token=computeToken()`,
  dotted identifier chains like `password=req.body.password`, PEM-armored
  public keys).

### Fixed

- `api-key` value class now includes `.`: `api_key=<jwt>` is redacted whole.
  Previously the match stopped after the JWT header segment, which also hid
  the intact token from `generic-bearer` — leaking payload and signature.
- `key-assignment`'s identifier-chain rejection is bounded to segments of at
  most 20 characters, so dotted credentials with a long random tail (Doppler's
  `dp.pt.…` family) stay redacted while code traversals pass through.
- Plugin-level regression tests for both motivating complaint scenarios (CN
  phone number, lowercase `deepseek_api_key`) plus the full 3-level × 2-arm
  gating matrix. 130 tests.

## [0.1.1] — 2026-09-02

### Added

- One-command install: the package declares `dsh.bundle.patch`, so
  `dsh plugin --profile <name> add dsh-secret-scrub` mounts the plugin at the
  default `balanced` level with no manual patch editing.

### Changed

- `tools/post-execute` spreads the accept decision when rewriting content.

## [0.1.0] — 2026-09-02

Initial release: irreversible regex scrubbing at `agent/pre-step`,
`tools/post-execute`, and `tools/ptc-dispatch-log` with a three-tier rule
table (`minimal`/`balanced`/`aggressive`), fail-loud config validation, and
the standalone `dsh-secret-scrub/rules` engine export.

[0.1.2]: https://github.com/jkt-check/dsh-secret-scrub/compare/v0.1.0...V0.1.2
[0.1.1]: https://github.com/jkt-check/dsh-secret-scrub/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jkt-check/dsh-secret-scrub/releases/tag/v0.1.0
