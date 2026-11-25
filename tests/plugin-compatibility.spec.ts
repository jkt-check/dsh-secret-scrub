import { describe, expect, it } from 'vitest'
import { evaluatePluginCompatibility } from '@deepseek-ai/dsh-app-boot'
import manifest from '../package.json' with { type: 'json' }

describe('DSH plugin compatibility of this manifest', () => {
  it('is accepted by the installed dsh runtime', () => {
    expect(evaluatePluginCompatibility(manifest)).toBeUndefined()
  })

  it('stays accepted by the previously supported dsh 0.1.2-alpha.4', () => {
    expect(evaluatePluginCompatibility(manifest, {}, '0.1.2-alpha.4')).toBeUndefined()
  })

  it('is accepted by a later 0.x dsh runtime (0.99.0)', () => {
    expect(evaluatePluginCompatibility(manifest, {}, '0.99.0')).toBeUndefined()
  })

  it('is rejected by dsh 1.0.0 on exactly the four interface peers', () => {
    const issue = evaluatePluginCompatibility(manifest, {}, '1.0.0')
    expect(Object.keys(issue?.requirements ?? {}).sort()).toEqual([
      '@deepseek-ai/dsh-agent',
      '@deepseek-ai/dsh-llm',
      '@deepseek-ai/dsh-session',
      '@deepseek-ai/dsh-tools',
    ])
  })

  it('keeps the four interface peers optional and dsh-invariants out of the manifest peers', () => {
    expect(manifest.peerDependencies).not.toHaveProperty('@deepseek-ai/dsh-invariants')
    expect(manifest.peerDependenciesMeta).not.toHaveProperty('@deepseek-ai/dsh-invariants')
    expect(manifest.peerDependenciesMeta).toEqual({
      '@deepseek-ai/dsh-agent': { optional: true },
      '@deepseek-ai/dsh-llm': { optional: true },
      '@deepseek-ai/dsh-session': { optional: true },
      '@deepseek-ai/dsh-tools': { optional: true },
    })
  })
})
