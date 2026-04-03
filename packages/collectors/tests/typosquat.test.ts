import { describe, it, expect } from 'vitest'
import { generateCandidates } from '../src/brand/typosquat.js'

describe('generateCandidates', () => {
  const candidates = generateCandidates('resinaro.com')
  const domains = candidates.map(c => c.domain)

  it('generates candidates', () => {
    expect(candidates.length).toBeGreaterThan(50)
  })

  it('does not include the original domain', () => {
    expect(domains).not.toContain('resinaro.com')
  })

  it('generates omission variants', () => {
    const omissions = candidates.filter(c => c.technique === 'omission')
    expect(omissions.length).toBe(8) // 8 chars in "resinaro"
    expect(domains).toContain('esinaro.com')
    expect(domains).toContain('resinao.com')
    expect(domains).toContain('rsinaro.com')
  })

  it('generates duplication variants', () => {
    const dups = candidates.filter(c => c.technique === 'duplication')
    expect(dups.length).toBeGreaterThan(0)
    expect(domains).toContain('rresinaro.com')
    expect(domains).toContain('ressinaro.com')
  })

  it('generates transposition variants', () => {
    const swaps = candidates.filter(c => c.technique === 'transposition')
    expect(swaps.length).toBe(7) // 7 adjacent pairs in "resinaro"
    expect(domains).toContain('ersinaro.com')
    expect(domains).toContain('reisnaro.com')
  })

  it('generates adjacent-key variants', () => {
    const adjacent = candidates.filter(c => c.technique === 'adjacent-key')
    expect(adjacent.length).toBeGreaterThan(10)
  })

  it('generates TLD variations', () => {
    const tlds = candidates.filter(c => c.technique === 'tld-variation')
    expect(tlds.length).toBeGreaterThan(3)
    expect(domains).toContain('resinaro.net')
    expect(domains).toContain('resinaro.org')
    expect(domains).toContain('resinaro.io')
  })

  it('generates hyphenation variants', () => {
    const hyphens = candidates.filter(c => c.technique === 'hyphenation')
    expect(hyphens.length).toBeGreaterThan(0)
    expect(domains).toContain('res-inaro.com')
  })

  it('generates prefix variants', () => {
    const prefixes = candidates.filter(c => c.technique === 'prefix')
    expect(prefixes.length).toBeGreaterThan(0)
    expect(domains).toContain('myresinaro.com')
    expect(domains).toContain('getresinaro.com')
  })

  it('generates suffix variants', () => {
    const suffixes = candidates.filter(c => c.technique === 'suffix')
    expect(suffixes.length).toBeGreaterThan(0)
    expect(domains).toContain('resinarouk.com')
    expect(domains).toContain('resinaroapp.com')
  })

  it('generates homoglyph variants', () => {
    const glyphs = candidates.filter(c => c.technique === 'homoglyph')
    expect(glyphs.length).toBeGreaterThan(0)
    // i → 1 or l
    expect(domains.some(d => d.includes('res1naro') || d.includes('reslnaro'))).toBe(true)
  })

  it('all candidates are unique', () => {
    expect(new Set(domains).size).toBe(domains.length)
  })

  it('all candidates are lowercase', () => {
    for (const d of domains) {
      expect(d).toBe(d.toLowerCase())
    }
  })

  it('works with multi-part TLDs', () => {
    const ukCandidates = generateCandidates('resinaro.co.uk')
    const ukDomains = ukCandidates.map(c => c.domain)
    expect(ukDomains).toContain('rsinaro.co.uk')
    expect(ukCandidates.length).toBeGreaterThan(30)
  })

  it('works with short domains', () => {
    const shortCandidates = generateCandidates('abc.com')
    expect(shortCandidates.length).toBeGreaterThan(10)
  })
})
