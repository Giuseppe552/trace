import { describe, it, expect } from 'vitest'
import {
  shannonEntropy,
  selfInfo,
  anonymitySetSize,
  priorAnonymity,
  computeAnonymity,
  narrowingGain,
  POPULATION,
} from '../src/entropy/anonymity.js'

describe('shannonEntropy', () => {
  it('returns 0 for a certain outcome', () => {
    expect(shannonEntropy([1])).toBe(0)
    expect(shannonEntropy([1, 0, 0])).toBe(0)
  })

  it('returns 1 bit for a fair coin', () => {
    expect(shannonEntropy([0.5, 0.5])).toBeCloseTo(1.0, 10)
  })

  it('returns log₂(n) for uniform distribution over n', () => {
    const n = 16
    const uniform = new Array(n).fill(1 / n)
    expect(shannonEntropy(uniform)).toBeCloseTo(Math.log2(n), 10)
  })

  it('H ≥ 0 for any distribution', () => {
    for (let i = 0; i < 100; i++) {
      const n = Math.floor(Math.random() * 10) + 2
      const raw = Array.from({ length: n }, () => Math.random())
      const sum = raw.reduce((a, b) => a + b, 0)
      const probs = raw.map(r => r / sum)
      expect(shannonEntropy(probs)).toBeGreaterThanOrEqual(0)
    }
  })

  it('H ≤ log₂(n) for any distribution over n', () => {
    for (let i = 0; i < 100; i++) {
      const n = Math.floor(Math.random() * 10) + 2
      const raw = Array.from({ length: n }, () => Math.random())
      const sum = raw.reduce((a, b) => a + b, 0)
      const probs = raw.map(r => r / sum)
      expect(shannonEntropy(probs)).toBeLessThanOrEqual(Math.log2(n) + 1e-10)
    }
  })

  it('handles empty input', () => {
    expect(shannonEntropy([])).toBe(0)
  })
})

describe('selfInfo', () => {
  it('rare event gives more bits', () => {
    expect(selfInfo(0.001)).toBeGreaterThan(selfInfo(0.1))
  })

  it('I(1/2) = 1 bit', () => {
    expect(selfInfo(0.5)).toBeCloseTo(1.0, 10)
  })

  it('I(1/1024) = 10 bits', () => {
    expect(selfInfo(1 / 1024)).toBeCloseTo(10.0, 10)
  })

  it('returns 0 for edge cases', () => {
    expect(selfInfo(0)).toBe(0)
    expect(selfInfo(1)).toBe(0)
    expect(selfInfo(-0.5)).toBe(0)
  })
})

describe('anonymitySetSize', () => {
  it('2^10 = 1024', () => {
    expect(anonymitySetSize(10)).toBe(1024)
  })

  it('2^0 = 1 (identified)', () => {
    expect(anonymitySetSize(0)).toBe(1)
  })

  it('negative entropy clamped to 0', () => {
    expect(anonymitySetSize(-5)).toBe(1)
  })
})

describe('priorAnonymity', () => {
  it('UK population ≈ 26.0 bits', () => {
    expect(priorAnonymity(POPULATION.uk)).toBeCloseTo(26.0, 0)
  })

  it('global internet ≈ 32.3 bits', () => {
    expect(priorAnonymity(POPULATION.global_internet)).toBeCloseTo(32.3, 0)
  })

  it('single person = 0 bits', () => {
    expect(priorAnonymity(1)).toBe(0)
  })
})

describe('narrowingGain', () => {
  it('UK to Bradford ≈ 6.95 bits', () => {
    // 67M → 540K
    const gain = narrowingGain(67_000_000, 540_000)
    expect(gain).toBeCloseTo(6.95, 1)
  })

  it('no narrowing = 0 bits', () => {
    expect(narrowingGain(1000, 1000)).toBe(0)
    expect(narrowingGain(1000, 2000)).toBe(0)
  })

  it('narrowing to 1 = full prior', () => {
    const pop = 67_000_000
    expect(narrowingGain(pop, 1)).toBeCloseTo(priorAnonymity(pop), 5)
  })
})

describe('computeAnonymity', () => {
  it('no evidence = full anonymity', () => {
    const result = computeAnonymity(POPULATION.uk, [])
    expect(result.remainingBits).toBeCloseTo(priorAnonymity(POPULATION.uk), 5)
    expect(result.identified).toBe(false)
    expect(result.complete).toBe(true)
    expect(result.failedCollectors.length).toBe(0)
  })

  it('enough evidence = identified', () => {
    const result = computeAnonymity(POPULATION.uk, [
      { source: 'whois', observation: 'registrant email match', informationGain: 20, confidence: 0.95 },
      { source: 'stylometry', observation: 'writing style match', informationGain: 8, confidence: 0.80 },
    ])
    // 20*0.95 + 8*0.80 = 19 + 6.4 = 25.4 bits out of ~26
    expect(result.remainingBits).toBeLessThan(2)
    expect(result.identified).toBe(result.remainingBits < 1)
  })

  it('remaining never goes below 0', () => {
    const result = computeAnonymity(100, [
      { source: 'test', observation: 'overwhelming', informationGain: 1000, confidence: 1 },
    ])
    expect(result.remainingBits).toBe(0)
    expect(result.anonymitySet).toBe(1)
  })

  it('confidence scales information gain', () => {
    const full = computeAnonymity(POPULATION.uk, [
      { source: 'a', observation: 'x', informationGain: 10, confidence: 1.0 },
    ])
    const half = computeAnonymity(POPULATION.uk, [
      { source: 'a', observation: 'x', informationGain: 10, confidence: 0.5 },
    ])
    expect(full.totalGainBits).toBeCloseTo(10, 5)
    expect(half.totalGainBits).toBeCloseTo(5, 5)
  })

  it('breakdown sorted by contribution', () => {
    const result = computeAnonymity(POPULATION.uk, [
      { source: 'small', observation: 'x', informationGain: 2, confidence: 1 },
      { source: 'big', observation: 'y', informationGain: 15, confidence: 1 },
      { source: 'medium', observation: 'z', informationGain: 7, confidence: 1 },
    ])
    expect(result.breakdown[0].source).toBe('big')
    expect(result.breakdown[1].source).toBe('medium')
    expect(result.breakdown[2].source).toBe('small')
  })

  it('failed collectors tracked separately', () => {
    const result = computeAnonymity(POPULATION.uk, [
      { source: 'whois', observation: 'email match', informationGain: 20, confidence: 0.9 },
    ], [
      { source: 'dns', reason: 'timeout', maxPotentialBits: 8.0 },
      { source: 'ct', reason: 'crt.sh unavailable', maxPotentialBits: 6.0 },
    ])
    expect(result.failedCollectors.length).toBe(2)
    expect(result.complete).toBe(false)
    expect(result.failedCollectors[0].source).toBe('dns')
  })

  it('failed collectors do not contribute to information gain', () => {
    const withFailed = computeAnonymity(POPULATION.uk, [
      { source: 'whois', observation: 'match', informationGain: 10, confidence: 1 },
    ], [
      { source: 'dns', reason: 'failed', maxPotentialBits: 8.0 },
    ])
    const withoutFailed = computeAnonymity(POPULATION.uk, [
      { source: 'whois', observation: 'match', informationGain: 10, confidence: 1 },
    ])
    // remaining bits should be the same — failed collectors add zero
    expect(withFailed.remainingBits).toBe(withoutFailed.remainingBits)
    // but completeness differs
    expect(withFailed.complete).toBe(false)
    expect(withoutFailed.complete).toBe(true)
  })

  it('remainingUpper equals remainingBits', () => {
    const result = computeAnonymity(POPULATION.uk, [
      { source: 'a', observation: 'x', informationGain: 5, confidence: 1 },
    ], [
      { source: 'b', reason: 'failed', maxPotentialBits: 10 },
    ])
    // upper bound is the conservative estimate (without failed collector data)
    expect(result.remainingUpper).toBe(result.remainingBits)
  })

  it('no failed collectors = complete assessment', () => {
    const result = computeAnonymity(1000, [
      { source: 'a', observation: 'x', informationGain: 5, confidence: 1 },
    ])
    expect(result.complete).toBe(true)
    expect(result.failedCollectors.length).toBe(0)
  })
})
