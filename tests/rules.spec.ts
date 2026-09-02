import { describe, expect, it } from 'vitest'
import { BUILTIN_RULES, maxTier, placeholder, scrubText } from '../src/rules.js'
import type { SecretRule } from '../src/rules.js'

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
// Classic GitHub PAT payload is exactly 36 chars.
const GITHUB_TOKEN = 'ghp_' + 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5'
const GITHUB_PAT = 'github_pat_' + '11ABCDEFG0' + 'ijklmnopqrstuvwxyz_0123456789ab'
const GOOGLE_KEY = 'AIza' + 'SyD4x8K2mN0pQ7rS9tU1vW3xY5zB6cD8eF0'
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c'
const PEM = '-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----'

const DEEPSEEK_KEY = 'sk-' + '0123456789abcdef'.repeat(2)
const OPENAI_PROJ_KEY = 'sk-proj-' + 'Ab1'.repeat(16)
const OPENAI_LEGACY_KEY = 'sk-' + 'Ab1'.repeat(16)
const ANTHROPIC_KEY = 'sk-ant-api03-' + 'aB1c'.repeat(8)
// Real glpat payload is exactly 20 chars.
const GITLAB_PAT = 'glpat-' + 'aB1cD2eF3gH4iJ5kL6mN'
// Split so secret scanners do not flag the documentation example key.
const STRIPE_LIVE_KEY = 'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc'
const STRIPE_TEST_RESTRICTED = 'rk_test_' + 'aB1c'.repeat(4)
const SLACK_BOT_TOKEN = 'xoxb-123456789012-abcdefghij'
const SLACK_APP_TOKEN = 'xapp-A0B1C2D3E4-a1b2c3d4e5'
const NPM_TOKEN = 'npm_' + 'aB1c'.repeat(9)
const PYPI_TOKEN = 'pypi-AgEIcHlwaS5vcmc' + 'aB1c'.repeat(13)
const SENDGRID_KEY = 'SG.' + 'aB1'.repeat(7) + 'c' + '.' + 'dE2'.repeat(14) + 'f'
const TWILIO_KEY = 'SK' + '0123456789abcdef'.repeat(2)
const DIGITALOCEAN_TOKEN = 'dop_v1_' + '0123456789abcdef'.repeat(4)
const SHOPIFY_TOKEN = 'shpat_' + '0123456789abcdef'.repeat(2)
const TELEGRAM_TOKEN = '123456789:' + 'aB1cD'.repeat(7)
const TAVILY_KEY = 'tvly-' + 'aB1c'.repeat(5)
const AWS_SECRET = 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY'
const AZURE_ACCOUNT_KEY = 'aB3d'.repeat(22)
const ALIBABA_KEY = 'LTAI4FvMrFDy5iHzKbEKeTXw'
const ENTROPY_TOKEN = '9fK2mQ7xR4vB8nL1pT6wZ3yH5cJ0aSdG'

describe('placeholder', () => {
  it('is the verbatim [REDACTED:<category>] form', () => {
    expect(placeholder('aws-access-key')).toBe('[REDACTED:aws-access-key]')
  })
})

describe('maxTier', () => {
  it('maps each level to its highest active tier', () => {
    expect(maxTier('minimal')).toBe(0)
    expect(maxTier('balanced')).toBe(1)
    expect(maxTier('aggressive')).toBe(2)
  })
})

describe('builtin rule table', () => {
  it('is ordered by tier ascending', () => {
    const tiers = BUILTIN_RULES.map(rule => rule.tier)
    expect([...tiers].sort((a, b) => a - b)).toEqual(tiers)
  })

  it('keeps the five legacy categories at tier 0', () => {
    const legacy = ['aws-access-key', 'github-token', 'google-api-key', 'generic-bearer', 'private-key']
    for (const category of legacy) {
      expect(BUILTIN_RULES.find(rule => rule.category === category)?.tier).toBe(0)
    }
  })
})

describe('tier 0: legacy categories', () => {
  it('redacts an AWS access key id', () => {
    const { text, redactions } = scrubText(`key: ${AWS_KEY}`, BUILTIN_RULES)
    expect(text).toBe('key: [REDACTED:aws-access-key]')
    expect(redactions).toEqual({ 'aws-access-key': 1 })
  })

  it('redacts GitHub tokens (classic and fine-grained PAT)', () => {
    expect(scrubText(GITHUB_TOKEN, BUILTIN_RULES).text).toBe('[REDACTED:github-token]')
    expect(scrubText(GITHUB_PAT, BUILTIN_RULES).text).toBe('[REDACTED:github-token]')
    // 35-char payload pins the lower bound of the classic-PAT shape.
    const short = 'ghp_' + 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY'
    expect(scrubText(short, BUILTIN_RULES).text).toBe(short)
  })

  it('redacts a Google API key', () => {
    expect(scrubText(`x=${GOOGLE_KEY}`, BUILTIN_RULES).text).toBe('x=[REDACTED:google-api-key]')
  })

  it('redacts a Bearer header value and a bare JWT as generic-bearer', () => {
    expect(scrubText(`Authorization: Bearer ${JWT}`, BUILTIN_RULES).text)
      .toBe('Authorization: [REDACTED:generic-bearer]')
    expect(scrubText(`token=${JWT}`, BUILTIN_RULES).text).toBe('token=[REDACTED:generic-bearer]')
  })

  it('redacts a multi-line PEM private key block as one occurrence', () => {
    const { text, redactions } = scrubText(`before\n${PEM}\nafter`, BUILTIN_RULES)
    expect(text).toBe('before\n[REDACTED:private-key]\nafter')
    expect(redactions).toEqual({ 'private-key': 1 })
  })

  it('redacts repeated occurrences of one category and counts each', () => {
    const { text, redactions } = scrubText(`${AWS_KEY} and ${AWS_KEY}`, BUILTIN_RULES)
    expect(text).toBe('[REDACTED:aws-access-key] and [REDACTED:aws-access-key]')
    expect(redactions).toEqual({ 'aws-access-key': 2 })
  })

  it('does not match conservative negatives', () => {
    const negatives = [
      'AKIA-too-short',                       // 前缀对但长度不够
      'the word bearer in prose',             // 小写 bearer 非凭证头
      'AIza-short',                           // Google 键长度不够
      'ghp_short',                            // GitHub 令牌长度不够
      '-----BEGIN PUBLIC KEY-----x-----END PUBLIC KEY-----', // 公钥不命中
      'ordinary prose without secrets',
    ]
    for (const prose of negatives) {
      expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    }
  })
})

describe('tier 0: provider keys', () => {
  const cases: { category: string; positive: string; negative: string }[] = [
    { category: 'deepseek-key', positive: DEEPSEEK_KEY, negative: 'sk-0123456789abcdef' },
    { category: 'openai-key', positive: OPENAI_PROJ_KEY, negative: 'sk-proj-short' },
    { category: 'openai-key', positive: OPENAI_LEGACY_KEY, negative: 'sk-Ab1' },
    { category: 'anthropic-key', positive: ANTHROPIC_KEY, negative: 'sk-ant-tooshort' },
    { category: 'gitlab-pat', positive: GITLAB_PAT, negative: 'glpat-short' },
    { category: 'stripe-key', positive: STRIPE_LIVE_KEY, negative: 'sk_live_short' },
    { category: 'stripe-key', positive: STRIPE_TEST_RESTRICTED, negative: 'pk_live_short' },
    { category: 'slack-token', positive: SLACK_BOT_TOKEN, negative: 'xoxo-123456789012' },
    { category: 'slack-token', positive: SLACK_APP_TOKEN, negative: 'xapp-short' },
    { category: 'npm-token', positive: NPM_TOKEN, negative: 'npm_short' },
    { category: 'pypi-token', positive: PYPI_TOKEN, negative: 'pypi-AgEIcHlwaS5vcmc-tooshort' },
    { category: 'sendgrid-key', positive: SENDGRID_KEY, negative: 'SG.aB1cD2.dE2fG3' },
    { category: 'twilio-key', positive: TWILIO_KEY, negative: 'SK0123456789abcdef' },
    { category: 'digitalocean-token', positive: DIGITALOCEAN_TOKEN, negative: 'dop_v1_0123456789abcdef' },
    { category: 'shopify-token', positive: SHOPIFY_TOKEN, negative: 'shpat_0123456789ABCDEF' },
    { category: 'telegram-bot-token', positive: TELEGRAM_TOKEN, negative: '1234567:aB1caB1caB1caB1c' },
    { category: 'tavily-key', positive: TAVILY_KEY, negative: 'tvly-short' },
  ]
  for (const { category, positive, negative } of cases) {
    it(`redacts ${category} and rejects its near-miss`, () => {
      const { text, redactions } = scrubText(`use ${positive} now`, BUILTIN_RULES)
      expect(text).toBe(`use [REDACTED:${category}] now`)
      expect(redactions).toEqual({ [category]: 1 })
      expect(scrubText(negative, BUILTIN_RULES).text).toBe(negative)
    })
  }

  it('redacts a 48-hex sk- key once as openai-key (deepseek-key cannot double-match)', () => {
    const legacy48 = 'sk-' + '0123456789abcdef'.repeat(3)
    const { text, redactions } = scrubText(legacy48, BUILTIN_RULES)
    expect(text).toBe('[REDACTED:openai-key]')
    expect(redactions).toEqual({ 'openai-key': 1 })
  })

  it('rejects a 19-char glpat payload (one below the real length)', () => {
    const short = 'glpat-' + 'aB1cD2eF3gH4iJ5kL6m'
    expect(scrubText(short, BUILTIN_RULES).text).toBe(short)
  })
})

describe('tier 0: URL forms', () => {
  it('redacts the whole scheme://user:password@ authority of a connection URL', () => {
    const { text, redactions } = scrubText('db postgres://admin:s3cret@db.internal/app', BUILTIN_RULES)
    expect(text).toBe('db [REDACTED:url-credentials]db.internal/app')
    expect(redactions).toEqual({ 'url-credentials': 1 })
  })

  it('redacts the empty-username redis form and other listed schemes', () => {
    expect(scrubText('redis://:s3cret@cache.internal/0', BUILTIN_RULES).text)
      .toBe('[REDACTED:url-credentials]cache.internal/0')
    expect(scrubText('smtp://user:pass@mail.internal', BUILTIN_RULES).text)
      .toBe('[REDACTED:url-credentials]mail.internal')
  })

  it('leaves non-listed schemes to the later tiers', () => {
    // https 不在连接串 scheme 清单里:不归 url-credentials。全表下
    // user:pass@host 的 pass@host 段会被 tier-2 的 email 规则兜底。
    expect(scrubText('https://example.com/path', BUILTIN_RULES).text).toBe('https://example.com/path')
    expect(scrubText('https://user:pass@example.com/path', BUILTIN_RULES).text)
      .toBe('https://user:[REDACTED:email]/path')
  })

  it('redacts a URL access_token query parameter including its name', () => {
    const { text, redactions } = scrubText('https://app.com/cb?access_token=a1b2c3d4e5f6g7h8&state=xyz', BUILTIN_RULES)
    expect(text).toBe('https://app.com/cb[REDACTED:url-access-token]&state=xyz')
    expect(redactions).toEqual({ 'url-access-token': 1 })
  })

  it('never re-consumes an earlier placeholder inside the userinfo', () => {
    // aws-access-key runs first and replaces the key; url-credentials must
    // leave the placeholder intact and count nothing.
    const { text, redactions } = scrubText(`postgres://user:${AWS_KEY}@host`, BUILTIN_RULES)
    expect(text).toBe('postgres://user:[REDACTED:aws-access-key]@host')
    expect(redactions).toEqual({ 'aws-access-key': 1 })
  })

  it('ignores a too-short access_token value', () => {
    const prose = 'https://app.com/cb?access_token=sh0rt&state=xyz'
    expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
  })
})

describe('tier 1: env-var and cloud keys', () => {
  it('redacts a whole export assignment as env-var-secret', () => {
    const { text, redactions } = scrubText(`export AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`, BUILTIN_RULES)
    expect(text).toBe('[REDACTED:env-var-secret]')
    expect(redactions).toEqual({ 'env-var-secret': 1 })
  })

  it('consumes a quoted value whole, including spaces inside the quotes', () => {
    expect(scrubText('export AWS_SECRET_ACCESS_KEY="wJal rXUtnFEMIK7 rest"', BUILTIN_RULES).text)
      .toBe('[REDACTED:env-var-secret]')
    expect(scrubText("API_TOKEN='abc def ghi'", BUILTIN_RULES).text)
      .toBe('[REDACTED:env-var-secret]')
  })

  it('matches only a keyword carried as a whole `_`-delimited name segment', () => {
    const { text, redactions } = scrubText('MY_API_KEY=x', BUILTIN_RULES)
    expect(text).toBe('[REDACTED:env-var-secret]')
    expect(redactions).toEqual({ 'env-var-secret': 1 })
    expect(scrubText('TOKEN=x', BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
    // `_` 边界上的名字仍按分段语义视为密钥名。
    expect(scrubText('_KEY=x', BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
    expect(scrubText('KEY_=x', BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
    const negatives = ['KEYBOARD=1', 'MONKEY=1', 'APIKEY=1', 'KEYS=1', 'api_key=x']
    for (const prose of negatives) {
      expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    }
  })

  it('consumes quote-concatenated tails and unmatched-quote values whole', () => {
    expect(scrubText('MY_KEY="abc def"tail', BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
    expect(scrubText('MY_KEY=abc"def ghi"', BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
    expect(scrubText('MY_SECRET="abc def', BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
    expect(scrubText("MY_SECRET='abc def", BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
  })

  it('keeps an empty value non-matching', () => {
    expect(scrubText('KEY=', BUILTIN_RULES).text).toBe('KEY=')
  })

  it('consumes a bare value whole — # is literal mid-word in the shell', () => {
    expect(scrubText('TOKEN=abc#def', BUILTIN_RULES).text).toBe('[REDACTED:env-var-secret]')
  })

  it('never spans a newline around = or starts on an earlier blank line', () => {
    const prose = 'SECRET_KEY\n=val'
    expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    const spaced = 'API_TOKEN\n  =val'
    expect(scrubText(spaced, BUILTIN_RULES).text).toBe(spaced)
  })

  it('redacts bare assignments on later lines of a dump', () => {
    const { text } = scrubText('FOO=1\nSECRET_KEY=abc123def456\nBAR=2', BUILTIN_RULES)
    expect(text).toBe('FOO=1\n[REDACTED:env-var-secret]\nBAR=2')
  })

  it('keeps safe and deny-listed variable names', () => {
    const negatives = [
      'PATH=/usr/bin',
      'HOME=/root',
      'PASSWORD_STORE_DIR=/home/u/.password-store',
      'TOKENIZERS_PARALLELISM=false',
    ]
    for (const prose of negatives) {
      expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    }
  })

  it('redacts an Azure storage AccountKey connection-string segment', () => {
    // DefaultEndpointsProtocol=https 段本身是一个 20+ 字符的混合类 run,
    // 全表下会被 high-entropy 兜底(与参考实现一致),这里从 AccountName 起。
    const { text, redactions } = scrubText(
      `AccountName=x;AccountKey=${AZURE_ACCOUNT_KEY};EndpointSuffix=core.windows.net`,
      BUILTIN_RULES,
    )
    expect(text).toBe('AccountName=x;[REDACTED:azure-storage-key];EndpointSuffix=core.windows.net')
    expect(redactions).toEqual({ 'azure-storage-key': 1 })
    expect(scrubText('AccountKey=tooshort', BUILTIN_RULES).text).toBe('AccountKey=tooshort')
  })

  it('redacts an Alibaba LTAI access key and rejects a short one', () => {
    expect(scrubText(`key ${ALIBABA_KEY}`, BUILTIN_RULES).text).toBe('key [REDACTED:alibaba-access-key]')
    expect(scrubText('LTAIshort', BUILTIN_RULES).text).toBe('LTAIshort')
  })
})

describe('tier 2: PII', () => {
  it('redacts an email address', () => {
    expect(scrubText('reach ada.lovelace@example.com today', BUILTIN_RULES).text)
      .toBe('reach [REDACTED:email] today')
    expect(scrubText('not-an-email@', BUILTIN_RULES).text).toBe('not-an-email@')
  })

  it('redacts a Chinese mobile number, also in a Chinese context', () => {
    expect(scrubText('call 13800138000 now', BUILTIN_RULES).text).toBe('call [REDACTED:phone-cn] now')
    expect(scrubText('手机13800138000', BUILTIN_RULES).text).toBe('手机[REDACTED:phone-cn]')
    expect(scrubText('12300138000', BUILTIN_RULES).text).toBe('12300138000')
  })

  it('redacts an E.164 international number without swallowing phone-cn', () => {
    expect(scrubText('intl +442071234567', BUILTIN_RULES).text).toBe('intl [REDACTED:phone-intl]')
    // +86 前缀的国内手机号整体归 phone-intl,不被 phone-cn 截断。
    expect(scrubText('+8613800138000', BUILTIN_RULES).text).toBe('[REDACTED:phone-intl]')
    // +1 号码的 11 位数字本身形似国内手机号:phone-cn 先匹配(与参考实现同序)。
    expect(scrubText('+14155552671', BUILTIN_RULES).text).toBe('+[REDACTED:phone-cn]')
    expect(scrubText('+012345678', BUILTIN_RULES).text).toBe('+012345678')
  })

  it('redacts 17–19 digit Chinese id shapes including the X checksum form', () => {
    expect(scrubText('id 110101199003070019', BUILTIN_RULES).text).toBe('id [REDACTED:id-cn]')
    expect(scrubText('id 11010119900307001X', BUILTIN_RULES).text).toBe('id [REDACTED:id-cn]')
  })

  it('categorizes a Luhn-valid 18-digit run as id-cn, not credit-card', () => {
    const { text, redactions } = scrubText('110101199003070013', BUILTIN_RULES)
    expect(text).toBe('[REDACTED:id-cn]')
    expect(redactions).toEqual({ 'id-cn': 1 })
  })

  it('leaves 16-digit and 20-plus-digit runs alone', () => {
    for (const prose of ['1234567890123456', '12345678901234567890']) {
      expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    }
  })

  it('redacts Luhn-valid card numbers with space or dash groups', () => {
    expect(scrubText('card 4111 1111 1111 1111', BUILTIN_RULES).text).toBe('card [REDACTED:credit-card]')
    expect(scrubText('card 5500-0055-5555-5559', BUILTIN_RULES).text).toBe('card [REDACTED:credit-card]')
  })

  it('never consumes a trailing space or dash after the final digit', () => {
    expect(scrubText('4111 1111 1111 1111 next', BUILTIN_RULES).text)
      .toBe('[REDACTED:credit-card] next')
    expect(scrubText('4111-1111-1111-1111 - more', BUILTIN_RULES).text)
      .toBe('[REDACTED:credit-card] - more')
  })

  it('keeps a Luhn-invalid candidate unchanged and uncounted', () => {
    const { text, redactions } = scrubText('serial 1234 5678 9012 3456', BUILTIN_RULES)
    expect(text).toBe('serial 1234 5678 9012 3456')
    expect(redactions).toEqual({})
  })

  it('redacts a US SSN and rejects the dash-less form', () => {
    expect(scrubText('ssn 078-05-1120', BUILTIN_RULES).text).toBe('ssn [REDACTED:ssn-us]')
    expect(scrubText('078051120', BUILTIN_RULES).text).toBe('078051120')
  })
})

describe('tier 2: high-entropy fallback', () => {
  it('redacts a random mixed-class token', () => {
    const { text, redactions } = scrubText(`tok ${ENTROPY_TOKEN}`, BUILTIN_RULES)
    expect(text).toBe('tok [REDACTED:high-entropy]')
    expect(redactions).toEqual({ 'high-entropy': 1 })
  })

  it('redacts a token carrying the symbol class', () => {
    expect(scrubText('aB1cD2eF3gH4iJ5kL6+7m', BUILTIN_RULES).text).toBe('[REDACTED:high-entropy]')
  })

  it('rejects single-class runs and low-diversity repeats', () => {
    for (const prose of ['aaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaa1']) {
      expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    }
  })

  it('rejects obvious fakes and placeholder fragments', () => {
    const negatives = [
      'yourapikeyhereabcd1234',
      'REDACTEDawsaccesskey1234',
      '[REDACTED:aws-access-key]',
    ]
    for (const prose of negatives) {
      expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    }
  })

  it('rejects natural-language-ish runs', () => {
    expect(scrubText('TheCatAndTheDog12345', BUILTIN_RULES).text).toBe('TheCatAndTheDog12345')
  })
})

describe('characterization: hash-like text at the full table', () => {
  // These pin the accepted aggressive-level tradeoff: hash-like text is
  // redacted by the high-entropy fallback even though it is not a secret.
  it('redacts a 40-hex git SHA as high-entropy', () => {
    const { text, redactions } = scrubText('commit 0123456789abcdef0123456789abcdef01234567', BUILTIN_RULES)
    expect(text).toBe('commit [REDACTED:high-entropy]')
    expect(redactions).toEqual({ 'high-entropy': 1 })
  })

  it('redacts a 64-hex SHA-256 as high-entropy', () => {
    const sha256 = '0123456789abcdef'.repeat(4)
    const { text, redactions } = scrubText(`digest ${sha256}`, BUILTIN_RULES)
    expect(text).toBe('digest [REDACTED:high-entropy]')
    expect(redactions).toEqual({ 'high-entropy': 1 })
  })

  it('redacts a mixed-class base64 blob as high-entropy', () => {
    const blob = 'aGVsbG8td29ybGQtdGhpcy1pcy1iYXNlNjQ'
    expect(scrubText(`data ${blob}`, BUILTIN_RULES).text).toBe('data [REDACTED:high-entropy]')
  })

  it('leaves a UUID and ordinary prose alone', () => {
    const negatives = [
      'id 3f8a2b1c-9d4e-4f50-8a6b-1c2d3e4f5a6b',
      'the quick brown fox jumps over the lazy dog',
    ]
    for (const prose of negatives) {
      expect(scrubText(prose, BUILTIN_RULES).text).toBe(prose)
    }
  })
})

describe('scrubText', () => {
  it('returns empty redactions and the identical text when nothing matches', () => {
    const { text, redactions } = scrubText('nothing here', BUILTIN_RULES)
    expect(text).toBe('nothing here')
    expect(redactions).toEqual({})
  })

  it('honors a caller-supplied rule subset and extra rules', () => {
    const only = BUILTIN_RULES.filter(rule => rule.category === 'aws-access-key')
    expect(scrubText(GOOGLE_KEY, only).text).toBe(GOOGLE_KEY)
    const extra: SecretRule[] = [{ category: 'internal-token', tier: 0, pattern: /internal-[0-9]{4}/g }]
    expect(scrubText('use internal-1234 now', extra).text).toBe('use [REDACTED:internal-token] now')
  })

  it('leaves the placeholder itself untouched on a second pass (idempotent)', () => {
    const once = scrubText(`key: ${AWS_KEY}`, BUILTIN_RULES).text
    expect(scrubText(once, BUILTIN_RULES).text).toBe(once)
  })

  it('is idempotent over the full table on a text with one hit per category', () => {
    const source = [
      `aws ${AWS_KEY}`,
      `gh ${GITHUB_TOKEN}`,
      `gcp ${GOOGLE_KEY}`,
      `jwt ${JWT}`,
      PEM,
      `ds ${DEEPSEEK_KEY}`,
      `oai ${OPENAI_PROJ_KEY}`,
      `ant ${ANTHROPIC_KEY}`,
      `gl ${GITLAB_PAT}`,
      `stripe ${STRIPE_LIVE_KEY}`,
      `slack ${SLACK_BOT_TOKEN}`,
      `npm ${NPM_TOKEN}`,
      `pypi ${PYPI_TOKEN}`,
      `sg ${SENDGRID_KEY}`,
      `tw ${TWILIO_KEY}`,
      `do ${DIGITALOCEAN_TOKEN}`,
      `shop ${SHOPIFY_TOKEN}`,
      `tg ${TELEGRAM_TOKEN}`,
      `tvly ${TAVILY_KEY}`,
      'url postgres://admin:s3cret@db.internal/app',
      'cb https://app.com/cb?access_token=a1b2c3d4e5f6g7h8&state=xyz',
      `export AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`,
      `azure AccountKey=${AZURE_ACCOUNT_KEY}`,
      `ali ${ALIBABA_KEY}`,
      'mail ada.lovelace@example.com',
      'phone 13800138000',
      'intl +442071234567',
      'id 110101199003070019',
      'card 4111 1111 1111 1111',
      'ssn 078-05-1120',
      `entropy ${ENTROPY_TOKEN}`,
    ].join('\n')
    const once = scrubText(source, BUILTIN_RULES)
    expect(once.text).not.toBe(source)
    expect(once.text).not.toContain(AWS_KEY)
    expect(once.text).not.toContain(AWS_SECRET)
    // One hit per category: a neutered `validate` on any rule turns this red.
    expect(Object.keys(once.redactions).sort()).toEqual(BUILTIN_RULES.map(rule => rule.category).sort())
    const twice = scrubText(once.text, BUILTIN_RULES)
    expect(twice.text).toBe(once.text)
    expect(twice.redactions).toEqual({})
  })
})
