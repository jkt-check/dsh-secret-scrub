# dsh-secret-scrub

English | [中文](README.zh.md)

Irreversible secret-scrubbing guard plugin, extracted from [deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) (`packages/guard/secret-scrub`). It rewrites text on its way to the session log and the model: when a configured rule matches a secret-shaped fragment — an access key, a bearer token, a private key block — the fragment is replaced irreversibly with a `[REDACTED:<category>]` placeholder, so the durable log and the model request carry only the placeholder at the covered points.

## Install

```sh
npm install dsh-secret-scrub
```

Runtime dependencies are `@deepseek-ai/cordis` (peer) and `@deepseek-ai/schemastery`. The `@deepseek-ai/dsh-*` peer packages are type-only and optional.

## Use as a Cordis plugin

```ts
import { Context } from '@deepseek-ai/cordis'
import * as SecretScrub from 'dsh-secret-scrub'

const ctx = new Context()
await ctx.plugin(SecretScrub, {
  level: 'aggressive',               // scrub depth: minimal | balanced (default) | aggressive
  disabled: ['env-var-secret'],      // tier 1/2 built-in categories only — tier 0 cannot be disabled
  extra: [
    { category: 'internal-token', pattern: 'internal-[0-9]{4}' },
  ],
})
```

The plugin mounts three prepended waterfall listeners that delegate first and then scrub whatever the rest of the chain admitted:

- `agent/pre-step` rewrites each step's admitted user messages before they reach the session log and the model request.
- `tools/post-execute` rewrites an accepted tool result's plain content.
- `tools/ptc-dispatch-log` rewrites the durable `tool/code-dispatch` copy of a `run_code` sub-dispatch.

| Field | Default | Meaning |
|---|---|---|
| `level` | `balanced` | Scrub depth: `minimal` runs tier 0 only, `balanced` adds tier 1, `aggressive` adds tier 2 — PII and the high-entropy fallback |
| `disabled` | `[]` | Built-in tier 1/2 categories to turn off; a tier-0 core rule cannot be disabled and fails the load |
| `extra` | `[]` | Deployment-added rules, active at every level: a unique lowercase-dashed `category` plus a `pattern` compiled with `new RegExp(pattern, 'g')` |

Invalid configuration fails at startup with a clear error — an unknown or tier-0 `disabled` category, an `extra` pattern that does not compile, a category id that cannot appear in the placeholder, or a duplicate category — never a silent fall-back.

## Built-in rule tiers

`level` selects the highest active tier. Tiers 0–1 are prefix-anchored and tier 2 matches shapes (the patterns live in [`src/rules.ts`](src/rules.ts)):

| Tier | Active at | Categories |
|---|---|---|
| 0 — core secrets | every level; cannot be disabled | `private-key`, `aws-access-key`, `github-token`, `google-api-key`, `deepseek-key`, `openai-key`, `anthropic-key`, `gitlab-pat`, `stripe-key`, `slack-token`, `npm-token`, `pypi-token`, `sendgrid-key`, `twilio-key`, `digitalocean-token`, `shopify-token`, `telegram-bot-token`, `tavily-key`, `url-credentials` (connection-URL authority), `url-access-token` (OAuth callback token), `generic-bearer` (bearer tokens and JWTs) |
| 1 — assignment and cloud-provider keys | `balanced` and up | `env-var-secret` (uppercase assignments whose name carries KEY/SECRET/TOKEN/PASSWORD as a whole `_`-delimited segment), `azure-storage-key`, `alibaba-access-key` |
| 2 — PII and the high-entropy fallback | `aggressive` only | `email`, `phone-cn`, `phone-intl`, `id-cn`, `credit-card` (Luhn-checked), `ssn-us`, `high-entropy` |

## Use the engine directly

The pure scrubbing engine is exported from `dsh-secret-scrub/rules` and has no Cordis dependency:

```ts
import { BUILTIN_RULES, scrubText } from 'dsh-secret-scrub/rules'

const { text, redactions } = scrubText('key: AKIAIOSFODNN7EXAMPLE', BUILTIN_RULES)
// text       → 'key: [REDACTED:aws-access-key]'
// redactions → { 'aws-access-key': 1 }
```

## Known limitations

Redaction is one-way and regex-based. Unprefixed keys, secrets split across text blocks, and encoded forms (base64-wrapped, URL-escaped) evade the conservative rule shapes by design. The tier-2 rules match shapes, not proven secrets, so they trade false positives for coverage — an email address in a task instruction is redacted as if it were a secret, and hash-like text (git SHAs, SHA-256 digests) matches the `high-entropy` fallback at `aggressive`. Do not rely on this guard as the only control against credential leaks.

## Development

```sh
npm install
npm run typecheck
npm test
npm run build
```

## License

[MIT](LICENSE) — Copyright (c) 2026 DeepSeek
