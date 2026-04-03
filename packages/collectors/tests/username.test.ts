import { describe, it, expect } from 'vitest'
import { generateUsernameVariants } from '../src/social/username.js'

describe('generateUsernameVariants', () => {
  const variants = generateUsernameVariants('Giuseppe', 'Giona')

  it('generates common patterns', () => {
    expect(variants).toContain('giuseppegiona')
    expect(variants).toContain('giuseppe.giona')
    expect(variants).toContain('giuseppe_giona')
    expect(variants).toContain('giuseppe-giona')
  })

  it('generates initial + lastname', () => {
    expect(variants).toContain('ggiona')
    expect(variants).toContain('g.giona')
    expect(variants).toContain('g_giona')
  })

  it('generates reversed patterns', () => {
    expect(variants).toContain('gionagiuseppe')
    expect(variants).toContain('giona.giuseppe')
  })

  it('generates numbered variants', () => {
    expect(variants).toContain('giuseppegiona1')
    expect(variants).toContain('giuseppegiona123')
    expect(variants).toContain('ggiona1')
  })

  it('all lowercase', () => {
    for (const v of variants) {
      expect(v).toBe(v.toLowerCase())
    }
  })

  it('all at least 3 characters', () => {
    for (const v of variants) {
      expect(v.length).toBeGreaterThanOrEqual(3)
    }
  })

  it('no duplicates', () => {
    expect(new Set(variants).size).toBe(variants.length)
  })

  it('generates reasonable count', () => {
    expect(variants.length).toBeGreaterThan(15)
    expect(variants.length).toBeLessThan(50)
  })
})
