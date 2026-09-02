/**
 * Package-owned invariant companion for `dsh-secret-scrub`.
 * @module dsh-secret-scrub/invariant
 */

import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = 'dsh-secret-scrub'

/** Cordis companion plugin name. */
export const name = 'secret-scrub-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: the plugin rewrites in-flight waterfall decisions and
 * owns no event stream or mutable snapshot of its own, and the one durable
 * relation it could suggest — "no session-log text matches an active rule" —
 * is false by design (the `agent/inbox/spliced` receipt copy retains the
 * original text before `agent/pre-step` can rewrite it) and unknowable to a
 * companion (the active rule set is deployment Config: `disabled`/`extra`
 * change it at load).
 */
const install: InvariantInstaller = () => {}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
