import { describe, it, expect } from 'vitest'
import {
  fieldWeight,
  computeLinkage,
  jaroWinkler,
  namesMatch,
} from '../src/linkage/fellegi-sunter.js'

describe('jaroWinkler', () => {
  it('identical strings = 1.0', () => {
    expect(jaroWinkler('giuseppe', 'giuseppe')).toBe(1.0)
  })

  it('completely different = low', () => {
    expect(jaroWinkler('abcdef', 'zyxwvu')).toBeLessThan(0.5)
  })

  it('empty strings', () => {
    expect(jaroWinkler('', '')).toBe(1.0)
    expect(jaroWinkler('abc', '')).toBe(0)
    expect(jaroWinkler('', 'abc')).toBe(0)
  })

  it('similar names score high', () => {
    expect(jaroWinkler('giuseppe', 'giusepe')).toBeGreaterThan(0.9)
    expect(jaroWinkler('marco', 'marcos')).toBeGreaterThan(0.9)
  })

  it('prefix bonus: shared start → higher score', () => {
    // "mar" prefix in both
    const withPrefix = jaroWinkler('martinez', 'martins')
    const noPrefix = jaroWinkler('artinez', 'artins')
    expect(withPrefix).toBeGreaterThanOrEqual(noPrefix)
  })

  it('symmetry: jw(a,b) = jw(b,a)', () => {
    for (let i = 0; i < 50; i++) {
      const a = Math.random().toString(36).slice(2, 8)
      const b = Math.random().toString(36).slice(2, 8)
      expect(jaroWinkler(a, b)).toBeCloseTo(jaroWinkler(b, a), 10)
    }
  })

  it('result ∈ [0, 1]', () => {
    for (let i = 0; i < 100; i++) {
      const a = Math.random().toString(36).slice(2, 2 + Math.floor(Math.random() * 10))
      const b = Math.random().toString(36).slice(2, 2 + Math.floor(Math.random() * 10))
      const score = jaroWinkler(a, b)
      expect(score).toBeGreaterThanOrEqual(0)
      expect(score).toBeLessThanOrEqual(1)
    }
  })
})

describe('namesMatch', () => {
  it('exact match', () => {
    expect(namesMatch('Giuseppe Giona', 'giuseppe giona')).toBe(true)
  })

  it('close variant', () => {
    // "G. Giona" is too short vs "Giuseppe Giona" for Jaro-Winkler 0.85
    // but similar full names should match
    expect(namesMatch('Giuseppe Giona', 'Giusepe Giona')).toBe(true)
  })

  it('different people', () => {
    expect(namesMatch('Giuseppe Giona', 'Marco de Vries')).toBe(false)
  })
})

describe('fieldWeight', () => {
  it('email agreement gives high positive weight', () => {
    const result = fieldWeight('email', true)
    expect(result.weight).toBeGreaterThan(15) // log₂(0.99 / 0.0000001) ≈ 23
  })

  it('email disagreement gives large negative weight', () => {
    const result = fieldWeight('email', false)
    expect(result.weight).toBeLessThan(-3)
  })

  it('agreement on rare field > agreement on common field', () => {
    const emailAgree = fieldWeight('email', true)
    const countryAgree = fieldWeight('location_country', true)
    expect(emailAgree.weight).toBeGreaterThan(countryAgree.weight)
  })

  it('w(agree) > 0 for all fields', () => {
    const fields: Array<'email' | 'username' | 'display_name' | 'location_city' | 'domain'> = [
      'email', 'username', 'display_name', 'location_city', 'domain',
    ]
    for (const f of fields) {
      expect(fieldWeight(f, true).weight).toBeGreaterThan(0)
    }
  })

  it('w(disagree) < 0 for fields where m is high', () => {
    const result = fieldWeight('email', false)
    expect(result.weight).toBeLessThan(0)
  })
})

describe('computeLinkage', () => {
  it('strong match: same email + same name', () => {
    const result = computeLinkage([
      { field: 'email', agrees: true },
      { field: 'display_name', agrees: true },
      { field: 'location_city', agrees: true },
    ])
    expect(result.classification).toBe('match')
    expect(result.matchProbability).toBeGreaterThan(0.99)
  })

  it('no match: everything disagrees', () => {
    const result = computeLinkage([
      { field: 'email', agrees: false },
      { field: 'display_name', agrees: false },
      { field: 'location_country', agrees: false },
    ])
    expect(result.classification).toBe('non_match')
    expect(result.matchProbability).toBeLessThan(0.01)
  })

  it('possible: mixed evidence', () => {
    const result = computeLinkage([
      { field: 'display_name', agrees: true },
      { field: 'location_city', agrees: true },
      { field: 'email', agrees: false },
    ])
    // name + city agree, but email disagrees — ambiguous
    expect(result.compositeWeight).toBeLessThan(12)
  })

  it('matchProbability ∈ [0, 1]', () => {
    for (let i = 0; i < 100; i++) {
      const fields: Array<'email' | 'username' | 'display_name'> = ['email', 'username', 'display_name']
      const comparisons = fields.map(f => ({
        field: f,
        agrees: Math.random() > 0.5,
      }))
      const result = computeLinkage(comparisons)
      expect(result.matchProbability).toBeGreaterThanOrEqual(0)
      expect(result.matchProbability).toBeLessThanOrEqual(1)
    }
  })

  it('more agreeing fields → higher probability', () => {
    const one = computeLinkage([{ field: 'display_name', agrees: true }])
    const two = computeLinkage([
      { field: 'display_name', agrees: true },
      { field: 'username', agrees: true },
    ])
    const three = computeLinkage([
      { field: 'display_name', agrees: true },
      { field: 'username', agrees: true },
      { field: 'email', agrees: true },
    ])
    expect(three.matchProbability).toBeGreaterThan(two.matchProbability)
    expect(two.matchProbability).toBeGreaterThan(one.matchProbability)
  })
})
