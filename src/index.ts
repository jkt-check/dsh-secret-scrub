/**
 * Irreversible regex secret scrubber. Three prepended waterfall listeners
 * rewrite text blocks on their way to the session log and the model —
 * `agent/pre-step` for admitted user messages (whose `user/message` events
 * are logged only after the decision), `tools/post-execute` for accepted
 * tool results, and `tools/ptc-dispatch-log` for the durable copy of a
 * `run_code` sub-dispatch. Redaction is one-way: the placeholder
 * `[REDACTED:<category>]` is all the log and the model ever see at those
 * points. The known gaps (the `agent/inbox/spliced` receipt copy, tool-call
 * arguments, assistant text) are documented in the package README.
 * @module dsh-secret-scrub
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type {} from '@deepseek-ai/dsh-agent'
import type { PreStepDecision } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import type { PostToolDecision } from '@deepseek-ai/dsh-tools'
import type { UserMessage } from '@deepseek-ai/dsh-session'
import { BUILTIN_RULES, maxTier, scrubText } from './rules.js'
import type { ScrubLevel, SecretRule } from './rules.js'

export const name = 'secret-scrub'

/**
 * Plugin config, validated by the same-named schemastery schema plus the
 * load-time checks in {@link apply} (misconfiguration fails loud: an unknown
 * or tier-0 `disabled` category, an invalid `extra` pattern, an unusable
 * category id, or a duplicate category throws at plugin load, never a
 * silent fall-back).
 */
export interface Config {
  /**
   * Scrub depth: `minimal` runs tier 0 only, `balanced` (the default) adds
   * tier 1, `aggressive` adds tier 2 — PII and the high-entropy fallback.
   * `extra` rules always run, after all built-ins.
   */
  level?: ScrubLevel
  /**
   * Built-in rule categories to turn off; every entry must name a built-in
   * rule and tier-0 (core secret) categories cannot be disabled.
   */
  disabled?: string[]
  /** Deployment-added rules, compiled with `new RegExp(pattern, 'g')` at load. */
  extra?: {
    /**
     * Category id carried verbatim inside the `[REDACTED:<category>]`
     * placeholder; must stay lowercase-dashed and unique across all rules.
     */
    category: string
    /** Regular expression source, compiled with the global flag at load; a pattern that fails to compile fails the plugin load. */
    pattern: string
  }[]
}

export const Config: z<Config> = z.object({
  level: z.union(['minimal', 'balanced', 'aggressive']).default('balanced'),
  disabled: z.array(z.string()).default([]),
  extra: z.array(z.object({ category: z.string(), pattern: z.string() })).default([]),
})

/** Category ids appear verbatim inside `[REDACTED:<category>]`, so they stay lowercase-dashed. */
const CATEGORY_ID = /^[a-z0-9][a-z0-9-]*$/

/**
 * Resolve the active rule set from validated config, failing loud on every
 * unknown or unusable entry.
 */
function resolveRules(config: Config): SecretRule[] {
  // schemastery's .default() guarantees the fields are set after validation.
  const disabled = new Set(config.disabled as string[])
  const known = new Map(BUILTIN_RULES.map(rule => [rule.category, rule]))
  for (const category of disabled) {
    const rule = known.get(category)
    if (!rule) {
      throw new Error(`secret-scrub: disabled names unknown built-in category "${category}" (known: ${[...known.keys()].join(', ')})`)
    }
    if (rule.tier === 0) {
      const core = BUILTIN_RULES.filter(builtin => builtin.tier === 0).map(builtin => builtin.category).join(', ')
      throw new Error(`secret-scrub: disabled names tier-0 category "${category}" — core secret rules are always active (tier-0: ${core})`)
    }
  }
  const extra: SecretRule[] = []
  for (const entry of config.extra as { category: string; pattern: string }[]) {
    if (!CATEGORY_ID.test(entry.category)) {
      throw new Error(`secret-scrub: extra category "${entry.category}" must match ${String(CATEGORY_ID)} — it appears verbatim inside the [REDACTED:<category>] placeholder`)
    }
    if (known.has(entry.category) || extra.some(rule => rule.category === entry.category)) {
      throw new Error(`secret-scrub: duplicate rule category "${entry.category}"`)
    }
    let pattern: RegExp
    try {
      pattern = new RegExp(entry.pattern, 'g')
    } catch (error: unknown) {
      throw new Error(`secret-scrub: extra rule "${entry.category}" has an invalid pattern: ${entry.pattern}`, { cause: error })
    }
    // Extra rules are always active — tier-0-equivalent, exempt from the level gate.
    extra.push({ category: entry.category, pattern, tier: 0 })
  }
  const active = BUILTIN_RULES.filter(rule => rule.tier <= maxTier(config.level as ScrubLevel) && !disabled.has(rule.category))
  return [...active, ...extra]
}

/** Per-category counts of one scrubbed content list (empty when untouched). */
interface ScrubbedBlocks {
  blocks: ContentBlock[]
  redactions: Record<string, number>
}

/**
 * Scrub the text blocks of one content list, preserving block order and
 * identity: the ORIGINAL array comes back when nothing matched, non-text
 * blocks always pass through by reference, and only rewritten text blocks
 * are new objects.
 */
function scrubBlocks(content: readonly ContentBlock[], rules: readonly SecretRule[]): ScrubbedBlocks {
  const redactions: Record<string, number> = {}
  const next: ContentBlock[] = []
  let changed = false
  for (const block of content) {
    if (block.type !== 'text') {
      next.push(block)
      continue
    }
    const result = scrubText(block.text, rules)
    if (result.text === block.text) {
      next.push(block)
      continue
    }
    changed = true
    for (const [category, count] of Object.entries(result.redactions)) {
      redactions[category] = (redactions[category] ?? 0) + count
    }
    next.push({ type: 'text', text: result.text })
  }
  return { blocks: changed ? next : content as ContentBlock[], redactions }
}

/**
 * Install the guard's three listeners.
 * @param ctx - plugin context; listeners are scoped to it and disposed with it.
 * @param config - validated {@link Config}; rule resolution re-checks it fail-loud here.
 */
export function apply(ctx: Context, config: Config): void {
  const rules = resolveRules(config)

  /**
   * Count one arm's redactions; v1 keeps this out of the session log. Every
   * caller invokes it only after an actual rewrite, so the total is positive.
   */
  function logRedactions(arm: string, redactions: Readonly<Record<string, number>>): void {
    const total = Object.values(redactions).reduce((sum, count) => sum + count, 0)
    const detail = Object.entries(redactions).map(([category, count]) => `${category}×${count}`).join(', ')
    ctx.logger.info(`secret-scrub: redacted ${total} occurrence(s) at ${arm} (${detail})`)
  }

  // Prepended so the rewrite applies to the FINAL downstream decision:
  // delegate first, then scrub whatever messages the chain admitted. A
  // reject passes through — nothing enters the step, so nothing needs
  // scrubbing. Message id/source/role survive; only text blocks change.
  ctx.on('agent/pre-step', async (_payload, next): Promise<PreStepDecision> => {
    const decision = await next()
    if (decision.kind !== 'enter') return decision
    const redactions: Record<string, number> = {}
    let changed = false
    const messages: UserMessage[] = []
    for (const message of decision.messages) {
      const scrubbed = scrubBlocks(message.content, rules)
      if (scrubbed.blocks === message.content) {
        messages.push(message)
        continue
      }
      changed = true
      for (const [category, count] of Object.entries(scrubbed.redactions)) {
        redactions[category] = (redactions[category] ?? 0) + count
      }
      messages.push({ ...message, content: scrubbed.blocks })
    }
    if (!changed) return decision
    logRedactions('agent/pre-step', redactions)
    return { ...decision, messages }
  }, { prepend: true })

  // Accepted plain content only: a block's feedback is another listener's
  // corrective text (not tool output), and a value replacement is the
  // registry's structured channel — both pass through untouched. `hasOwn`
  // would treat `{value: undefined}` as a replacement; only a defined value
  // counts.
  ctx.on('tools/post-execute', async (exec, result, next): Promise<PostToolDecision> => {
    const decision = await next()
    if (decision.kind !== 'accept' || decision.value !== undefined) return decision
    const content = decision.content ?? result.content
    const scrubbed = scrubBlocks(content, rules)
    if (scrubbed.blocks === content) return decision
    logRedactions(`tools/post-execute ${exec.name}`, scrubbed.redactions)
    return { ...decision, content: scrubbed.blocks }
  }, { prepend: true })

  // The durable-log arm: the program already received the complete value, so
  // only the tool/code-dispatch event's copy is scrubbed.
  ctx.on('tools/ptc-dispatch-log', async (dispatch, next): Promise<ContentBlock[]> => {
    const content = await next()
    const scrubbed = scrubBlocks(content, rules)
    if (scrubbed.blocks === content) return content
    logRedactions(`tools/ptc-dispatch-log ${dispatch.name}`, scrubbed.redactions)
    return scrubbed.blocks
  }, { prepend: true })
}
