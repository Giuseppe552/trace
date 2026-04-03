import { describe, it, expect } from 'vitest'
import {
  ksTest,
  exponentialCdf,
  interArrivalTimes,
  coefficientOfVariation,
  detectCoordination,
} from '../src/timing/coordination.js'

describe('interArrivalTimes', () => {
  it('computes intervals between sorted timestamps', () => {
    expect(interArrivalTimes([10, 20, 35, 50])).toEqual([10, 15, 15])
  })

  it('sorts unsorted input', () => {
    expect(interArrivalTimes([50, 10, 35, 20])).toEqual([10, 15, 15])
  })

  it('returns empty for < 2 timestamps', () => {
    expect(interArrivalTimes([100])).toEqual([])
    expect(interArrivalTimes([])).toEqual([])
  })
})

describe('coefficientOfVariation', () => {
  it('constant values → CV = 0', () => {
    expect(coefficientOfVariation([5, 5, 5, 5])).toBe(0)
  })

  it('exponential distribution → CV ≈ 1', () => {
    // generate exponential samples
    const n = 10000
    const samples: number[] = []
    for (let i = 0; i < n; i++) {
      samples.push(-Math.log(Math.random()) * 1000)
    }
    const cv = coefficientOfVariation(samples)
    expect(cv).toBeGreaterThan(0.9)
    expect(cv).toBeLessThan(1.1)
  })

  it('CV > 0 for non-constant data', () => {
    expect(coefficientOfVariation([1, 2, 3, 4, 5])).toBeGreaterThan(0)
  })
})

describe('exponentialCdf', () => {
  it('F(0) = 0', () => {
    expect(exponentialCdf(100)(0)).toBe(0)
  })

  it('F(∞) → 1', () => {
    expect(exponentialCdf(100)(100000)).toBeCloseTo(1, 5)
  })

  it('F(mean) = 1 - 1/e ≈ 0.632', () => {
    expect(exponentialCdf(100)(100)).toBeCloseTo(1 - 1 / Math.E, 5)
  })

  it('negative values → 0', () => {
    expect(exponentialCdf(100)(-50)).toBe(0)
  })

  it('monotonically increasing', () => {
    const cdf = exponentialCdf(100)
    let prev = 0
    for (let x = 0; x <= 1000; x += 10) {
      const current = cdf(x)
      expect(current).toBeGreaterThanOrEqual(prev)
      prev = current
    }
  })
})

describe('ksTest', () => {
  it('samples from the reference distribution → high p-value', () => {
    const mean = 500
    const n = 200
    const samples: number[] = []
    for (let i = 0; i < n; i++) {
      samples.push(-Math.log(Math.random()) * mean)
    }
    const result = ksTest(samples, exponentialCdf(mean))
    expect(result.pValue).toBeGreaterThan(0.05)
  })

  it('uniform samples vs exponential → low p-value', () => {
    const n = 200
    const samples = Array.from({ length: n }, () => Math.random() * 1000)
    const result = ksTest(samples, exponentialCdf(500))
    expect(result.pValue).toBeLessThan(0.05)
  })

  it('constant intervals → low p-value (too regular)', () => {
    // perfectly spaced inter-arrival times (not the cumulative timestamps)
    const intervals = Array.from({ length: 50 }, () => 100)
    const mean = 100
    const result = ksTest(intervals, exponentialCdf(mean))
    // constant values cluster at one point — CDF jumps from 0 to 1
    expect(result.D).toBeGreaterThan(0.2)
  })

  it('D ∈ [0, 1]', () => {
    const samples = Array.from({ length: 30 }, () => Math.random() * 1000)
    const result = ksTest(samples, exponentialCdf(500))
    expect(result.D).toBeGreaterThanOrEqual(0)
    expect(result.D).toBeLessThanOrEqual(1)
  })

  it('empty input → D = 0, p = 1', () => {
    const result = ksTest([], exponentialCdf(100))
    expect(result.D).toBe(0)
    expect(result.pValue).toBe(1)
  })
})

describe('detectCoordination', () => {
  it('natural timing → not coordinated', () => {
    // exponential inter-arrival times (natural human pattern)
    const timestamps: number[] = [0]
    for (let i = 1; i < 50; i++) {
      timestamps.push(timestamps[i - 1] + (-Math.log(Math.random()) * 86400000))
    }
    const result = detectCoordination(timestamps)
    expect(result.likelyCoordinated).toBe(false)
  })

  it('regular intervals → coordinated', () => {
    // review every 3600 seconds exactly (scheduled bot)
    const timestamps = Array.from({ length: 20 }, (_, i) => i * 3600000)
    const result = detectCoordination(timestamps)
    expect(result.likelyCoordinated).toBe(true)
    expect(result.cv).toBeLessThan(0.3)
  })

  it('burst of reviews → may detect coordination', () => {
    // 10 reviews within 5 minutes, then nothing
    const base = Date.now()
    const timestamps = Array.from({ length: 10 }, (_, i) => base + i * 30000)
    const result = detectCoordination(timestamps)
    // very regular → should flag
    expect(result.cv).toBeLessThan(0.3)
  })

  it('insufficient data → not coordinated, 0 confidence', () => {
    const result = detectCoordination([1000, 2000])
    expect(result.likelyCoordinated).toBe(false)
    expect(result.confidence).toBe(0)
  })

  it('eventCount matches input', () => {
    const result = detectCoordination([1, 2, 3, 4, 5, 6, 7, 8])
    expect(result.eventCount).toBe(8)
  })
})
