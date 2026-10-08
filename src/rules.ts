/**
 * The secret-scrub rule table and the pure text scrubber; `src/index.ts`
 * resolves the active rule subset from the plugin config and applies
 * `scrubText` at its listeners. Rules are conservative: a false negative
 * is preferable to a false positive eating model context.
 * @module dsh-secret-scrub/rules
 */

/** One secret-matching rule: the category id carried by the placeholder and its global pattern. */
export interface SecretRule {
  readonly category: string
  readonly pattern: RegExp
  /**
   * Severity tier gating the rule: 0 = core secrets (active at every
   * level), 1 = env-var and cloud-provider keys (`balanced` and up),
   * 2 = PII and the high-entropy fallback (`aggressive` only).
   */
  readonly tier: 0 | 1 | 2
  /**
   * Post-filter on the whole match: the match is redacted only when this
   * returns true. A false return leaves the text unchanged and uncounted.
   */
  readonly validate?: (match: string) => boolean
}

/** Scrub depth selected by the plugin's `level` config. */
export type ScrubLevel = 'minimal' | 'balanced' | 'aggressive'

/**
 * The highest active tier for one level.
 * @param level - the configured scrub depth.
 * @returns 0 for `minimal`, 1 for `balanced`, 2 for `aggressive`.
 */
export function maxTier(level: ScrubLevel): 0 | 1 | 2 {
  switch (level) {
    case 'minimal': return 0
    case 'balanced': return 1
    case 'aggressive': return 2
  }
}

/**
 * The verbatim placeholder substituted for one redacted occurrence.
 * @param category - the rule's category id.
 * @returns the `[REDACTED:<category>]` literal.
 */
export function placeholder(category: string): string {
  return `[REDACTED:${category}]`
}

/**
 * Luhn checksum over the digits of one credit-card candidate; the pattern's
 * single space/dash group separators are stripped first.
 */
function luhnValid(candidate: string): boolean {
  const digits = candidate.replace(/[ -]/g, '')
  let sum = 0
  let double = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = digits.charCodeAt(index) - 48
    if (double) {
      digit *= 2
      if (digit > 9) digit -= 9
    }
    sum += digit
    double = !double
  }
  return sum % 10 === 0
}

/**
 * Env-var assignment names that hold no secret even though a keyword segment
 * makes them look sensitive.
 */
const SAFE_ENV_NAMES = new Set([
  'PASSWORD_STORE_DIR', // pass(1) store location — a path, not a password
])

/**
 * Whether one `env-var-secret` match should be redacted. The pattern accepts
 * any uppercase assignment (keeping the regex linear), so this filter owns
 * both name checks: the name must carry a sensitive keyword as a whole
 * `_`-delimited segment — `AWS_SECRET_ACCESS_KEY` and `MY_API_KEY` are
 * secrets, `KEYBOARD`, `MONKEY`, `APIKEY`, and `KEYS` are not — and a
 * deny-listed safe name survives. The match keeps its full assignment shape
 * (`export NAME=value`), so the name is everything before the first `=`,
 * minus the `export` keyword.
 */
function isSecretEnvAssignment(match: string): boolean {
  const assignment = match.trimStart().replace(/^export\s+/, '')
  const name = assignment.slice(0, assignment.indexOf('=')).trimEnd()
  if (!/(?:^|_)(?:KEY|SECRET|TOKEN|PASSWORD)(?:_|$)/.test(name)) return false
  return !SAFE_ENV_NAMES.has(name)
}

/**
 * Whether one `key-assignment` match should be redacted. The pattern accepts
 * any `name=value` shape (keeping the regex linear, like `env-var-secret`),
 * so this filter owns every semantic check:
 *
 * - the name must carry a sensitive keyword as a whole `_`-delimited segment
 *   (case-insensitive: `deepseek_api_key` and `MY_Token` are secrets,
 *   `monkey`, `keyboard`, and `apikey` are not);
 * - a deny-listed safe name survives (compared uppercase, so the lowercase
 *   form of `PASSWORD_STORE_DIR` is safe too);
 * - a PEM armor value (`PUBLIC_KEY=-----BEGIN …`) is not a secret;
 * - the value must mix at least two character classes with four or more
 *   distinct characters, and a pure-letter value must be at least 24 chars —
 *   shorter pure-letter values are usually identifiers (`token=computeToken()`),
 *   not credentials.
 */
function isSensitiveKeyAssignment(match: string): boolean {
  const eq = match.indexOf('=')
  const name = match.slice(0, eq)
  if (!/(?:^|_)(?:key|secret|token|password)(?:_|$)/i.test(name)) return false
  if (SAFE_ENV_NAMES.has(name.toUpperCase())) return false
  const value = match.slice(eq + 1).replace(/^["']|["']$/g, '')
  if (value.startsWith('---')) return false
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(pattern => pattern.test(value)).length
  if (classes < 2) return false
  if (new Set(value).size < 4) return false
  if (/^[A-Za-z]+$/.test(value) && value.length < 24) return false
  return true
}

/**
 * Substrings that mark a high-entropy candidate as a documentation
 * placeholder rather than a secret. `redacted` also covers fragments of
 * this scrubber's own `[REDACTED:<category>]` placeholders, keeping a
 * second pass idempotent.
 */
const FAKE_KEY_MARKERS = ['example', 'test', 'xxxx', 'your', 'placeholder', 'redacted']

/** Very common English words; two or more hits inside one run mark glued-together prose, not a token. */
const COMMON_WORDS = ['the', 'and', 'for', 'that', 'with', 'this', 'from']

/**
 * Post-filter for the `high-entropy` fallback; each rejection reason is
 * marked inline. Every check runs on the match alone, so a public-key PEM
 * body line (shareable by design) can still be redacted — the fallback is
 * the last resort and stays conservative.
 */
function isHighEntropyToken(match: string): boolean {
  const lower = match.toLowerCase()
  // Documentation/example placeholders ('your_api_key_here' style).
  if (FAKE_KEY_MARKERS.some(marker => lower.includes(marker))) return false
  // Character-class diversity: a real token mixes at least two of
  // lowercase / uppercase / digit / symbol (`+`/`=`); single-class runs
  // (`aaaa…`, long prose words, pure digit runs) are not secrets.
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(pattern => pattern.test(match)).length
  if (classes < 2) return false
  // Distinct-character floor: kills low-entropy repeats that still mix two
  // classes (`aaaaaaaaaaaaaaaaaaa1`).
  if (new Set(match).size < 4) return false
  // Natural-language-ish: two or more common words in one run is prose.
  if (COMMON_WORDS.filter(word => lower.includes(word)).length >= 2) return false
  return true
}

/**
 * Value fragments that mark an `api-key` assignment as a documentation
 * placeholder rather than a live credential (kaya parity: case-insensitive
 * substring match). The `<`/`>`/`${`/`}` markers can never appear in the
 * pattern's value class; they are kept for parity with the reference list.
 */
const FAKE_VALUE_MARKERS = [
  'xxx', '***', 'your_', 'your-', 'your_key', 'your-api-key',
  'test', 'example', 'placeholder', 'changeme', 'change_me',
  'redacted', 'null', 'none', 'undefined', '<', '>', '${', '}',
]

/**
 * Whether one `api-key` match should be redacted: the value — everything
 * after the first `=` or `:`, quotes stripped — must not be an obvious
 * documentation placeholder.
 */
function isRealApiKeyAssignment(match: string): boolean {
  const value = match.slice(match.search(/[=:]/) + 1).trim().replace(/^["']+|["']+$/g, '')
  const lower = value.toLowerCase()
  return !FAKE_VALUE_MARKERS.some(marker => lower.includes(marker))
}

/**
 * Built-in rules, all global-flagged, ordered by tier ascending and, within
 * a tier, from most specific to most general. Tiers 0–1 are
 * prefix-anchored (provider key prefixes, assignment shapes, URL authority
 * forms); tier 2 matches shapes (PII and high-entropy runs). The ordering
 * lets broad multi-line and provider-prefixed rules claim their spans
 * before the generic fallbacks (`generic-sk-key`, `generic-bearer`,
 * `high-entropy`) run.
 * `private-key` spans lines and runs first so nothing else claims pieces of
 * a PEM body; `id-cn` runs before `credit-card` so a Luhn-valid 17–19 digit
 * run categorizes as the more specific PII id; `generic-bearer` and
 * `high-entropy` are the per-tier fallbacks. JWTs ride the
 * `generic-bearer` category both as `Bearer <token>` header values and as
 * bare `eyJ…` tokens.
 */
export const BUILTIN_RULES: readonly SecretRule[] = [
  {
    category: 'private-key',
    tier: 0,
    // eslint-disable-next-line @stylistic/max-len -- one atomic PEM armor literal; splitting it invites drift.
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
  },
  {
    category: 'private-key-truncated',
    tier: 0,
    // Truncation remnants, claimed immediately after complete blocks: an
    // unclosed BEGIN redacts through the end of the text (tail truncation),
    // an orphaned END redacts from the start of the text through the marker
    // (head truncation). Both present yields placeholder + middle slice +
    // placeholder. A lone BEGIN quoted in documentation over-redacts the
    // rest of the text — accepted, privacy-first (kaya parity).
    // eslint-disable-next-line @stylistic/max-len -- the two armor alternatives must stay atomic.
    pattern: /^[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----|-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*$/g,
  },
  {
    category: 'api-key',
    tier: 0,
    // Generic `apikey` assignment (kaya parity): the fixed name `api` +
    // optional `_`/`-` + `key` in any case, `=` or `:` separator with
    // optional surrounding whitespace and quotes (JSON form `"api_key":
    // "…"`), value of 8+ token characters. No leading `\b`: the span inside
    // a longer name (`deepseek_api_key=…`) is claimed here at tier 0. The
    // whole name+separator+value span is replaced; the filter only rejects
    // obvious documentation placeholders. Runs before `generic-bearer` so
    // `api_key=<jwt>` is categorized here, not as a bare JWT.
    pattern: /[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]['"]?\s*[=:]\s*['"]?[A-Za-z0-9_+\-/]{8,}/g,
    validate: isRealApiKeyAssignment,
  },
  { category: 'aws-access-key', tier: 0, pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  {
    category: 'github-token',
    tier: 0,
    pattern: /(?:\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,})/g,
  },
  { category: 'google-api-key', tier: 0, pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  // `sk-` + exactly 32 lowercase hex (DeepSeek). OpenAI's legacy 48-char
  // form below can never collide: the fixed lengths keep one `\b` from
  // landing inside the other's run.
  { category: 'deepseek-key', tier: 0, pattern: /\bsk-[0-9a-f]{32}\b/g },
  {
    category: 'openai-key',
    tier: 0,
    pattern: /(?:\bsk-proj-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{48}\b)/g,
  },
  { category: 'anthropic-key', tier: 0, pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g },
  { category: 'gitlab-pat', tier: 0, pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  // Rollbar's exact-32 shape runs before stripe-key's looser
  // `[sr]k_(live|test)_…{16,}` so a real rollbar token keeps its own
  // category; a 32-char stripe restricted key would be labeled rollbar —
  // miscategorized but still redacted (kaya has the same collision).
  { category: 'rollbar-token', tier: 0, pattern: /\brk_(?:live|test)_[A-Za-z0-9]{32}\b/g },
  { category: 'stripe-key', tier: 0, pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  {
    category: 'slack-token',
    tier: 0,
    pattern: /(?:\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bxapp-[A-Za-z0-9-]{10,}\b)/g,
  },
  { category: 'slack-signing-secret', tier: 0, pattern: /\bwhsec_[A-Za-z0-9]{32,}\b/g },
  // No scheme requirement: a scheme-less paste is still a live credential.
  { category: 'slack-webhook-url', tier: 0, pattern: /hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9+/]{43,46}/g },
  { category: 'npm-token', tier: 0, pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  // The fixed macaroon prefix `AgEIcHlwaS5vcmc` (base64 of the PyPI token
  // header) keeps the rule from matching prose mentions of `pypi-`.
  { category: 'pypi-token', tier: 0, pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g },
  { category: 'sendgrid-key', tier: 0, pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { category: 'twilio-key', tier: 0, pattern: /\bSK[0-9a-f]{32}\b/g },
  { category: 'digitalocean-token', tier: 0, pattern: /\bdop_v1_[0-9a-f]{64}\b/g },
  { category: 'shopify-token', tier: 0, pattern: /\bshpat_[0-9a-f]{32}\b/g },
  { category: 'telegram-bot-token', tier: 0, pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g },
  { category: 'tavily-key', tier: 0, pattern: /\btvly-[A-Za-z0-9_-]{20,}\b/g },
  // Fixed prefix + exact 58-char bech32 charset is the guard; no `\b` (kaya parity).
  { category: 'age-secret-key', tier: 0, pattern: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g },
  { category: 'docker-pat', tier: 0, pattern: /\bdckr_pat_[A-Za-z0-9_-]{27}\b/g },
  { category: 'notion-token', tier: 0, pattern: /\bntn_[0-9]{11}[A-Za-z0-9]{32}\b/g },
  { category: 'supabase-token', tier: 0, pattern: /\bsbp_[a-f0-9]{40}\b/g },
  { category: 'linear-api-key', tier: 0, pattern: /\blin_api_[A-Za-z0-9]{40}\b/g },
  // Generic `sk-`/`sk_` fallback: runs after every provider-specific sk rule
  // above, so only shapes none of them claim (notably the underscore form
  // `sk_…`) land here.
  { category: 'generic-sk-key', tier: 0, pattern: /\bsk[-_][A-Za-z0-9_-]{20,}\b/g },
  // Connection-URL authority: the whole `scheme://user:password@` span is
  // replaced, leaving the host readable after the placeholder. The userinfo
  // classes exclude `[` and `]` so a `[REDACTED:<category>]` placeholder
  // emitted by an earlier rule is never re-consumed.
  {
    category: 'url-credentials',
    tier: 0,
    pattern: /(?:mysql|postgres|postgresql|mongodb|redis|amqp|rabbitmq|sftp|smtp):\/\/[^:\s[\]]*:[^@\s[\]]+@/gi,
  },
  // OAuth callback query token: the whole `?access_token=<value>` span is
  // replaced, including the parameter name.
  { category: 'url-access-token', tier: 0, pattern: /[?&][Aa]ccess_[Tt]oken=[A-Za-z0-9._~+/=-]{8,}/g },
  {
    category: 'generic-bearer',
    tier: 0,
    pattern: /(?:\bBearer [A-Za-z0-9._~+/=-]{16,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g,
  },
  {
    category: 'env-var-secret',
    tier: 1,
    // Assignment-shaped secrets: any uppercase `NAME=value` (with optional
    // `export`) matches, and the validate filter keeps only names carrying a
    // sensitive keyword as a whole `_`-delimited segment. Accepting every
    // uppercase name here keeps the pattern linear — a per-segment keyword
    // alternation backtracks quadratically on degenerate runs like
    // `KEY_KEY_KEY_…`. The whole assignment is replaced.
    // Horizontal whitespace only (`[^\S\n]`): a match never starts on an
    // earlier blank line and never spans a newline around `=`. The value is
    // one or more closed quoted spans and bare runs (`[^\s'"]` excludes the
    // newline), so a quote-concatenated tail (`"abc def"tail`,
    // `abc"def ghi"`) is consumed whole; an unmatched opening quote
    // consumes to end of line. `#` stays literal mid-word as the shell
    // treats it.
    pattern: /^[^\S\n]*(?:export[^\S\n]+)?[A-Z0-9_]+[^\S\n]*=[^\S\n]*(?:(?:[^\s'"]+|"[^"]*"|'[^']*')+|"[^"\n]*|'[^'\n]*)/gm,
    validate: isSecretEnvAssignment,
  },
  { category: 'azure-storage-key', tier: 1, pattern: /[Aa]ccount[Kk]ey=["']?[A-Za-z0-9+/=]{86,88}["']?/g },
  { category: 'alibaba-access-key', tier: 1, pattern: /\bLTAI[A-Za-z0-9]{16,}\b/g },
  {
    category: 'key-assignment',
    tier: 1,
    // Assignment-shaped secrets in ANY case: the lowercase and mixed-case
    // shapes `env-var-secret` cannot see (`deepseek_api_key=…`, `MY_Token=…`).
    // Like `env-var-secret`, the pattern accepts every `name=value` shape and
    // the validate filter owns the semantics. `=` must follow the name
    // immediately (no whitespace), so code like `token = 5` never matches;
    // the value is a closed quoted span or a bare run of at least 8 token
    // characters. Runs last in tier 1 so the uppercase-only rule keeps
    // claiming its own shape.
    pattern: /\b[A-Za-z0-9_]+=(?:"[^"\n]{8,}"|'[^'\n]{8,}'|[A-Za-z0-9_\-+/=.]{8,})/g,
    validate: isSensitiveKeyAssignment,
  },
  {
    // Bounded quantifiers keep mismatch on long `@`-less runs linear.
    category: 'email',
    tier: 2,
    pattern: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b/g,
  },
  { category: 'phone-cn', tier: 2, pattern: /(?<!\d)1[3-9]\d{9}(?!\d)/g },
  // E.164 with a leading `+`: the plus keeps it disjoint from `phone-cn`
  // and `id-cn`, and the trailing boundary rejects longer digit runs.
  { category: 'phone-intl', tier: 2, pattern: /\+[1-9]\d{7,14}\b/g },
  // Chinese resident id (GB 11643-1999): 17–19 digits plus the optional
  // X/x checksum letter; no checksum validation — a plausible shape is
  // redacted even when malformed. Runs before `credit-card`.
  { category: 'id-cn', tier: 2, pattern: /(?<!\d)\d{17,19}[Xx]?(?!\d)/g },
  {
    category: 'credit-card',
    tier: 2,
    // The final digit carries no separator, so a trailing space or dash is
    // never consumed.
    pattern: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    validate: luhnValid,
  },
  { category: 'ssn-us', tier: 2, pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  {
    category: 'high-entropy',
    tier: 2,
    pattern: /\b[A-Za-z0-9+=]{20,}\b/g,
    validate: isHighEntropyToken,
  },
]

/** Outcome of one scrub pass: the rewritten text plus per-category occurrence counts. */
export interface ScrubResult {
  readonly text: string
  readonly redactions: Readonly<Record<string, number>>
}

/**
 * Replace every rule hit in `text` with its category placeholder. A rule's
 * `validate` post-filter may reject a match: the original text is kept and
 * nothing is counted.
 * @param text - one text block's content.
 * @param rules - the active rule set (builtins minus disabled, plus extras).
 * @returns the rewritten text and the per-category hit counts (empty when untouched).
 */
export function scrubText(text: string, rules: readonly SecretRule[]): ScrubResult {
  const redactions: Record<string, number> = {}
  let out = text
  for (const rule of rules) {
    // String.replace with a global pattern scans from 0 each call, so the
    // shared RegExp's lastIndex never leaks across calls.
    out = out.replace(rule.pattern, (match: string) => {
      if (rule.validate && !rule.validate(match)) return match
      redactions[rule.category] = (redactions[rule.category] ?? 0) + 1
      return placeholder(rule.category)
    })
  }
  return { text: out, redactions }
}
