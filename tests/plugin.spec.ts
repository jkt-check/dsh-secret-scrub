import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { UserMessage } from '@deepseek-ai/dsh-session'
import * as SecretScrub from '../src/index.js'
import type { Config } from '../src/index.js'

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
const AWS_SECRET = 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY'
const ENV_LINE = `export AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`
const EMAIL = 'ada@example.com'
const ENTROPY_TOKEN = '9fK2mQ7xR4vB8nL1pT6wZ3yH5cJ0aSdG'

function message(text: string): UserMessage {
  return {
    id: 'm1',
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'user' },
  } as unknown as UserMessage
}

/** Drive the `agent/pre-step` waterfall with a stub payload and one admitted message. */
function preStep(ctx: Context, text: string) {
  const msg = message(text)
  const payload = { agent: undefined, messages: [msg], turn: 1, step: 1, signal: new AbortController().signal }
  return ctx.waterfall('agent/pre-step', payload as never, async () => ({ kind: 'enter' as const, messages: [msg] }))
}

/** Drive the `tools/post-execute` waterfall with a stub execution and accepted text result. */
function postExecute(ctx: Context, content: ContentBlock[]) {
  const exec = { name: 'leaky' }
  const result = { content, isError: false }
  return ctx.waterfall('tools/post-execute', exec as never, result as never, async () => ({ kind: 'accept' as const }))
}

describe('config validation fails loud', () => {
  it('rejects an unknown disabled category', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(SecretScrub, { disabled: ['no-such-category'] })).rejects.toThrow(/unknown built-in category/)
  })

  it('rejects disabling a tier-0 category', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(SecretScrub, { disabled: ['aws-access-key'] })).rejects.toThrow(/tier-0/)
  })

  it('rejects an invalid extra pattern at load', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(SecretScrub, { extra: [{ category: 'mine', pattern: '([' }] })).rejects.toThrow(/invalid pattern/)
  })

  it('rejects an extra category that cannot appear in the placeholder', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(SecretScrub, { extra: [{ category: 'Bad Category', pattern: 'x' }] })).rejects.toThrow(/category/)
  })

  it('rejects an extra category colliding with a builtin or another extra', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(SecretScrub, { extra: [{ category: 'aws-access-key', pattern: 'x' }] })).rejects.toThrow(/duplicate/)
    const ctx2 = new Context()
    await expect(ctx2.plugin(SecretScrub, { extra: [{ category: 'mine', pattern: 'x' }, { category: 'mine', pattern: 'y' }] })).rejects.toThrow(/duplicate/)
  })

  it('rejects an unknown level string at schema validation', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(SecretScrub, { level: 'paranoid' } as unknown as Config)).rejects.toThrow(/expected|level/)
  })
})

describe('agent/pre-step arm', () => {
  it('scrubs an admitted user message, preserving identity and source', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const decision = await preStep(ctx, `my key is ${AWS_KEY}`)
    if (decision.kind !== 'enter') throw new Error('expected enter')
    expect(decision.messages[0]!.content).toEqual([{ type: 'text', text: 'my key is [REDACTED:aws-access-key]' }])
    expect(decision.messages[0]!.id).toBe('m1')
    expect(decision.messages[0]!.source).toEqual({ kind: 'user' })
  })

  it('passes a downstream reject decision through untouched', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const msg = message(`veto ${AWS_KEY}`)
    const payload = { agent: undefined, messages: [msg], turn: 1, step: 1, signal: new AbortController().signal }
    const decision = await ctx.waterfall('agent/pre-step', payload as never, async () => ({ kind: 'reject' as const }))
    expect(decision.kind).toBe('reject')
  })

  it('returns the original decision when nothing matched (no-op path)', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const inner = { kind: 'enter' as const, messages: [message('clean text')] }
    const payload = { agent: undefined, messages: inner.messages, turn: 1, step: 1, signal: new AbortController().signal }
    const decision = await ctx.waterfall('agent/pre-step', payload as never, async () => inner)
    expect(decision).toBe(inner)
  })
})

describe('tools/post-execute arm', () => {
  it('scrubs an accepted text result', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const decision = await postExecute(ctx, [{ type: 'text', text: `creds ${AWS_KEY}` }])
    expect(decision).toEqual({ kind: 'accept', content: [{ type: 'text', text: 'creds [REDACTED:aws-access-key]' }] })
  })

  it('passes a downstream block decision through untouched', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const exec = { name: 'leaky' }
    const result = { content: [{ type: 'text', text: `creds ${AWS_KEY}` }], isError: false }
    const decision = await ctx.waterfall('tools/post-execute', exec as never, result as never, async () => ({
      kind: 'block' as const,
      feedback: [{ type: 'text' as const, text: `denied ${AWS_KEY}` }],
    }))
    expect(JSON.stringify(decision)).toContain(`denied ${AWS_KEY}`)
  })

  it('passes a downstream value replacement through untouched', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const exec = { name: 'leaky' }
    const result = { content: [{ type: 'text', text: `creds ${AWS_KEY}` }], isError: false }
    const decision = await ctx.waterfall('tools/post-execute', exec as never, result as never, async () => ({
      kind: 'accept' as const,
      value: [{ type: 'text', text: 'replaced' }],
    }))
    expect(JSON.stringify(decision)).toContain('replaced')
    expect(JSON.stringify(decision)).not.toContain('[REDACTED:')
  })

  it('passes a clean result through unchanged (no-op path)', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const decision = await postExecute(ctx, [{ type: 'text', text: 'nothing sensitive' }])
    expect(decision).toEqual({ kind: 'accept' })
  })

  it('scrubs only text blocks in a mixed content list', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const reasoning = { type: 'reasoning', text: 'why' } as unknown as ContentBlock
    const decision = await postExecute(ctx, [{ type: 'text', text: `key ${AWS_KEY}` }, reasoning])
    if (decision.kind !== 'accept') throw new Error('expected accept')
    expect(decision.content![1]).toBe(reasoning)
    expect(JSON.stringify(decision.content)).toContain('[REDACTED:aws-access-key]')
  })
})

describe('tools/ptc-dispatch-log arm', () => {
  it('scrubs only the logged copy of a sub-dispatch', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const content: ContentBlock[] = [{ type: 'text', text: `creds ${AWS_KEY}` }]
    const logged = await ctx.waterfall('tools/ptc-dispatch-log', { name: 'leaky' } as never, async () => content)
    expect(logged).toEqual([{ type: 'text', text: 'creds [REDACTED:aws-access-key]' }])
    // The program-facing value is the original array, untouched.
    expect(content[0]).toEqual({ type: 'text', text: `creds ${AWS_KEY}` })
  })
})

describe('level gating', () => {
  const SAMPLE = `key ${AWS_KEY}\n${ENV_LINE}\nmail ${EMAIL}\ntok ${ENTROPY_TOKEN}`

  it('minimal scrubs tier 0 only', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, { level: 'minimal' })
    const decision = await preStep(ctx, SAMPLE)
    if (decision.kind !== 'enter') throw new Error('expected enter')
    expect(decision.messages[0]!.content).toEqual([{ type: 'text', text: `key [REDACTED:aws-access-key]\n${ENV_LINE}\nmail ${EMAIL}\ntok ${ENTROPY_TOKEN}` }])
  })

  it('omitted level defaults to balanced: tier 1 included, tier 2 excluded', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, {})
    const decision = await preStep(ctx, SAMPLE)
    if (decision.kind !== 'enter') throw new Error('expected enter')
    expect(decision.messages[0]!.content).toEqual([{ type: 'text', text: `key [REDACTED:aws-access-key]\n[REDACTED:env-var-secret]\nmail ${EMAIL}\ntok ${ENTROPY_TOKEN}` }])
  })

  it('aggressive scrubs every tier', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, { level: 'aggressive' })
    const decision = await preStep(ctx, SAMPLE)
    if (decision.kind !== 'enter') throw new Error('expected enter')
    expect(decision.messages[0]!.content).toEqual([{ type: 'text', text: 'key [REDACTED:aws-access-key]\n[REDACTED:env-var-secret]\nmail [REDACTED:email]\ntok [REDACTED:high-entropy]' }])
  })

  it('keeps extra rules active at minimal level', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, { level: 'minimal', extra: [{ category: 'internal-token', pattern: 'internal-[0-9]{4}' }] })
    const decision = await preStep(ctx, 'use internal-1234')
    if (decision.kind !== 'enter') throw new Error('expected enter')
    expect(decision.messages[0]!.content).toEqual([{ type: 'text', text: 'use [REDACTED:internal-token]' }])
  })

  it('a disabled tier-1 builtin stops scrubbing that category only', async () => {
    const ctx = new Context()
    await ctx.plugin(SecretScrub, { disabled: ['env-var-secret'] })
    const decision = await preStep(ctx, `key ${AWS_KEY}\n${ENV_LINE}`)
    if (decision.kind !== 'enter') throw new Error('expected enter')
    expect(decision.messages[0]!.content).toEqual([{ type: 'text', text: `key [REDACTED:aws-access-key]\n${ENV_LINE}` }])
  })
})

describe('disposal', () => {
  it('stops scrubbing after the plugin fiber is disposed', async () => {
    const ctx = new Context()
    const fiber = await ctx.plugin(SecretScrub, {})
    const before = await preStep(ctx, `key ${AWS_KEY}`)
    if (before.kind !== 'enter') throw new Error('expected enter')
    expect(JSON.stringify(before.messages[0]!.content)).toContain('[REDACTED:aws-access-key]')

    await fiber.dispose()
    const after = await preStep(ctx, `key ${AWS_KEY}`)
    if (after.kind !== 'enter') throw new Error('expected enter')
    expect(after.messages[0]!.content).toEqual([{ type: 'text', text: `key ${AWS_KEY}` }])
  })
})
