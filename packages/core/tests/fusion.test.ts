import { describe, it, expect } from 'vitest'
import {
  createMass,
  combine,
  fuseEvidence,
  type MassFunction,
} from '../src/fusion/dempster-shafer.js'

describe('createMass', () => {
  it('sums to 1', () => {
    const m = createMass(0.8, 0.9, 'test')
    expect(m.attributed + m.not_attributed + m.uncertain).toBeCloseTo(1, 10)
  })

  it('reliability 0 = full uncertainty', () => {
    const m = createMass(0.99, 0, 'test')
    expect(m.uncertain).toBeCloseTo(1, 10)
    expect(m.attributed).toBeCloseTo(0, 10)
  })

  it('reliability 1 = no uncertainty', () => {
    const m = createMass(0.7, 1, 'test')
    expect(m.uncertain).toBeCloseTo(0, 10)
    expect(m.attributed).toBeCloseTo(0.7, 10)
    expect(m.not_attributed).toBeCloseTo(0.3, 10)
  })

  it('clamps score and reliability to [0, 1]', () => {
    const m = createMass(1.5, 2.0, 'test')
    expect(m.attributed + m.not_attributed + m.uncertain).toBeCloseTo(1, 10)
  })
})

describe('combine', () => {
  it('is commutative', () => {
    const m1 = createMass(0.8, 0.7, 'a')
    const m2 = createMass(0.6, 0.5, 'b')
    const ab = combine(m1, m2)
    const ba = combine(m2, m1)
    expect(ab.attributed).toBeCloseTo(ba.attributed, 10)
    expect(ab.not_attributed).toBeCloseTo(ba.not_attributed, 10)
    expect(ab.uncertain).toBeCloseTo(ba.uncertain, 10)
  })

  it('is associative', () => {
    const m1 = createMass(0.7, 0.6, 'a')
    const m2 = createMass(0.5, 0.8, 'b')
    const m3 = createMass(0.9, 0.4, 'c')
    const ab_c = combine(combine(m1, m2), m3)
    const a_bc = combine(m1, combine(m2, m3))
    expect(ab_c.attributed).toBeCloseTo(a_bc.attributed, 8)
    expect(ab_c.not_attributed).toBeCloseTo(a_bc.not_attributed, 8)
    expect(ab_c.uncertain).toBeCloseTo(a_bc.uncertain, 8)
  })

  it('vacuous mass is identity element', () => {
    const m = createMass(0.8, 0.9, 'real')
    const vacuous: MassFunction = { attributed: 0, not_attributed: 0, uncertain: 1, source: 'none' }
    const result = combine(m, vacuous)
    expect(result.attributed).toBeCloseTo(m.attributed, 10)
    expect(result.not_attributed).toBeCloseTo(m.not_attributed, 10)
    expect(result.uncertain).toBeCloseTo(m.uncertain, 10)
  })

  it('agreeing sources strengthen attribution', () => {
    const m1 = createMass(0.8, 0.7, 'a')
    const m2 = createMass(0.9, 0.6, 'b')
    const result = combine(m1, m2)
    expect(result.attributed).toBeGreaterThan(m1.attributed)
    expect(result.attributed).toBeGreaterThan(m2.attributed)
  })

  it('conflicting sources increase uncertainty', () => {
    const m1 = createMass(0.95, 0.9, 'pro')     // strongly attributed
    const m2 = createMass(0.05, 0.9, 'contra')   // strongly not attributed
    const result = combine(m1, m2)
    // conflict should reduce both beliefs
    expect(result.attributed).toBeLessThan(m1.attributed)
    expect(result.not_attributed).toBeLessThan(m2.not_attributed)
  })

  it('total conflict returns uncertainty', () => {
    const m1: MassFunction = { attributed: 1, not_attributed: 0, uncertain: 0, source: 'a' }
    const m2: MassFunction = { attributed: 0, not_attributed: 1, uncertain: 0, source: 'b' }
    const result = combine(m1, m2)
    expect(result.uncertain).toBe(1)
  })

  it('result always sums to 1', () => {
    for (let i = 0; i < 100; i++) {
      const m1 = createMass(Math.random(), Math.random(), 'a')
      const m2 = createMass(Math.random(), Math.random(), 'b')
      const result = combine(m1, m2)
      const sum = result.attributed + result.not_attributed + result.uncertain
      expect(sum).toBeCloseTo(1, 8)
    }
  })
})

describe('fuseEvidence', () => {
  it('empty input = inconclusive', () => {
    const result = fuseEvidence([])
    expect(result.level).toBe('inconclusive')
    expect(result.belief).toBe(0)
    expect(result.conflict).toBe(0)
  })

  it('single source passes through', () => {
    const m = createMass(0.8, 0.9, 'whois')
    const result = fuseEvidence([m])
    expect(result.belief).toBeCloseTo(m.attributed, 10)
    expect(result.sources).toEqual(['whois'])
  })

  it('multiple agreeing sources → high confidence', () => {
    const masses = [
      createMass(0.85, 0.90, 'whois'),
      createMass(0.80, 0.85, 'ct'),
      createMass(0.75, 0.70, 'dns'),
    ]
    const result = fuseEvidence(masses)
    expect(result.belief).toBeGreaterThan(0.85)
    expect(result.level).toBe('high')
    expect(result.conflict).toBeLessThan(0.5)
  })

  it('conflicting sources → high conflict, lower confidence', () => {
    const masses = [
      createMass(0.95, 0.90, 'whois'),       // strongly attributed
      createMass(0.05, 0.90, 'stylometry'),   // strongly not attributed
    ]
    const result = fuseEvidence(masses)
    expect(result.conflict).toBeGreaterThan(0.3)
    // with high conflict, belief should be less certain than agreeing sources
    expect(result.belief).toBeLessThan(0.95)
  })

  it('Bel ≤ Pl always holds', () => {
    for (let i = 0; i < 100; i++) {
      const n = Math.floor(Math.random() * 5) + 1
      const masses = Array.from({ length: n }, (_, j) =>
        createMass(Math.random(), Math.random(), `src${j}`),
      )
      const result = fuseEvidence(masses)
      expect(result.belief).toBeLessThanOrEqual(result.plausibility + 1e-10)
    }
  })

  it('belief ∈ [0, 1] and plausibility ∈ [0, 1]', () => {
    for (let i = 0; i < 100; i++) {
      const n = Math.floor(Math.random() * 6) + 1
      const masses = Array.from({ length: n }, (_, j) =>
        createMass(Math.random(), Math.random(), `s${j}`),
      )
      const result = fuseEvidence(masses)
      expect(result.belief).toBeGreaterThanOrEqual(-1e-10)
      expect(result.belief).toBeLessThanOrEqual(1 + 1e-10)
      expect(result.plausibility).toBeGreaterThanOrEqual(-1e-10)
      expect(result.plausibility).toBeLessThanOrEqual(1 + 1e-10)
    }
  })
})
