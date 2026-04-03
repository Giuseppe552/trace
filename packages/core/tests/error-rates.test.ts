import { describe, it, expect } from 'vitest'
import {
  computeMetrics,
  benchmark,
  ksCriticalValue,
  ksTestPower,
  ksPowerTable,
  defaultErrorRates,
  formatErrorRates,
} from '../src/benchmark/error-rates.js'

describe('computeMetrics', () => {
  it('perfect classifier', () => {
    const m = computeMetrics(50, 0, 50, 0)
    expect(m.precision).toBe(1)
    expect(m.recall).toBe(1)
    expect(m.f1).toBe(1)
    expect(m.accuracy).toBe(1)
    expect(m.falsePositiveRate).toBe(0)
    expect(m.falseNegativeRate).toBe(0)
  })

  it('all false positives', () => {
    const m = computeMetrics(0, 50, 50, 0)
    expect(m.precision).toBe(0)
    expect(m.falsePositiveRate).toBe(0.5)
  })

  it('all false negatives', () => {
    const m = computeMetrics(0, 0, 50, 50)
    expect(m.recall).toBe(0)
    expect(m.falseNegativeRate).toBe(1)
  })

  it('realistic classifier: 80% precision, 70% recall', () => {
    // TP=70, FP=18, TN=82, FN=30
    const m = computeMetrics(70, 18, 82, 30)
    expect(m.precision).toBeCloseTo(0.795, 2) // 70/88
    expect(m.recall).toBeCloseTo(0.70, 2) // 70/100
    expect(m.f1).toBeGreaterThan(0.7)
    expect(m.f1).toBeLessThan(0.8)
  })

  it('F1 is harmonic mean of precision and recall', () => {
    const m = computeMetrics(40, 10, 40, 10)
    const expected = 2 * m.precision * m.recall / (m.precision + m.recall)
    expect(m.f1).toBeCloseTo(expected, 10)
  })

  it('all metrics ∈ [0, 1]', () => {
    for (let i = 0; i < 50; i++) {
      const tp = Math.floor(Math.random() * 100)
      const fp = Math.floor(Math.random() * 100)
      const tn = Math.floor(Math.random() * 100)
      const fn = Math.floor(Math.random() * 100)
      const m = computeMetrics(tp, fp, tn, fn)
      expect(m.precision).toBeGreaterThanOrEqual(0)
      expect(m.precision).toBeLessThanOrEqual(1)
      expect(m.recall).toBeGreaterThanOrEqual(0)
      expect(m.recall).toBeLessThanOrEqual(1)
      expect(m.f1).toBeGreaterThanOrEqual(0)
      expect(m.f1).toBeLessThanOrEqual(1)
    }
  })

  it('handles all-zero input', () => {
    const m = computeMetrics(0, 0, 0, 0)
    expect(m.precision).toBe(0)
    expect(m.recall).toBe(0)
    expect(m.f1).toBe(0)
  })
})

describe('benchmark', () => {
  it('measures perfect classifier', () => {
    const data = [
      { input: 'positive', expected: true },
      { input: 'negative', expected: false },
      { input: 'positive2', expected: true },
      { input: 'negative2', expected: false },
    ]
    const result = benchmark(data, (x) => x.startsWith('positive'))
    expect(result.confusion.tp).toBe(2)
    expect(result.confusion.tn).toBe(2)
    expect(result.confusion.fp).toBe(0)
    expect(result.confusion.fn).toBe(0)
    expect(result.precision).toBe(1)
    expect(result.recall).toBe(1)
  })

  it('measures 50% classifier', () => {
    const data = [
      { input: 1, expected: true },
      { input: 2, expected: true },
      { input: 3, expected: false },
      { input: 4, expected: false },
    ]
    // always predicts true
    const result = benchmark(data, () => true)
    expect(result.confusion.tp).toBe(2)
    expect(result.confusion.fp).toBe(2)
    expect(result.precision).toBe(0.5)
    expect(result.recall).toBe(1)
  })

  it('reports sample size', () => {
    const data = Array.from({ length: 100 }, (_, i) => ({
      input: i,
      expected: i < 50,
    }))
    const result = benchmark(data, (x) => x < 50)
    expect(result.sampleSize).toBe(100)
  })
})

describe('ksCriticalValue', () => {
  it('decreases with larger n', () => {
    expect(ksCriticalValue(10, 0.05)).toBeGreaterThan(ksCriticalValue(100, 0.05))
  })

  it('decreases with larger alpha', () => {
    expect(ksCriticalValue(20, 0.01)).toBeGreaterThan(ksCriticalValue(20, 0.10))
  })

  it('matches known values: n=20, alpha=0.05 → D_crit ≈ 0.304', () => {
    // c(0.05) = 1.358, D = 1.358/sqrt(20) = 0.3036
    expect(ksCriticalValue(20, 0.05)).toBeCloseTo(0.304, 2)
  })
})

describe('ksTestPower', () => {
  it('power increases with n', () => {
    expect(ksTestPower(50, 0.3)).toBeGreaterThan(ksTestPower(10, 0.3))
  })

  it('power increases with effect size', () => {
    expect(ksTestPower(20, 0.5)).toBeGreaterThan(ksTestPower(20, 0.2))
  })

  it('power ∈ [alpha, 1]', () => {
    for (const n of [5, 10, 20, 50, 100]) {
      for (const d of [0.1, 0.2, 0.3, 0.5, 0.8]) {
        const power = ksTestPower(n, d)
        expect(power).toBeGreaterThanOrEqual(0.04)
        expect(power).toBeLessThanOrEqual(1.0)
      }
    }
  })

  it('n=5 with moderate effect has low power', () => {
    expect(ksTestPower(5, 0.3)).toBeLessThan(0.5)
  })

  it('n=100 with moderate effect has high power', () => {
    expect(ksTestPower(100, 0.3)).toBeGreaterThan(0.8)
  })
})

describe('ksPowerTable', () => {
  it('returns entries for standard sample sizes', () => {
    const table = ksPowerTable()
    expect(table.length).toBe(8) // [5, 8, 10, 15, 20, 30, 50, 100]
    expect(table[0].n).toBe(5)
    expect(table[table.length - 1].n).toBe(100)
  })

  it('power increases across the table', () => {
    const table = ksPowerTable()
    for (let i = 1; i < table.length; i++) {
      expect(table[i].power).toBeGreaterThanOrEqual(table[i - 1].power)
    }
  })

  it('typeIIError + power ≈ 1', () => {
    const table = ksPowerTable()
    for (const row of table) {
      expect(row.power + row.typeIIError).toBeCloseTo(1, 2)
    }
  })

  it('critical D decreases with n', () => {
    const table = ksPowerTable()
    for (let i = 1; i < table.length; i++) {
      expect(table[i].criticalD).toBeLessThan(table[i - 1].criticalD)
    }
  })
})

describe('defaultErrorRates', () => {
  it('covers all modules', () => {
    const rates = defaultErrorRates()
    expect(rates.length).toBeGreaterThanOrEqual(8)

    const modules = rates.map(r => r.module)
    expect(modules).toContain('ai_text_detection')
    expect(modules).toContain('stylometry_comparison')
    expect(modules).toContain('timing_coordination')
    expect(modules).toContain('evidence_chain')
    expect(modules).toContain('entropy_computation')
    expect(modules).toContain('dempster_shafer_fusion')
  })

  it('analytical modules have citations', () => {
    const rates = defaultErrorRates()
    const analytical = rates.filter(r => r.method === 'analytical')
    for (const rate of analytical) {
      expect(rate.citation.length).toBeGreaterThan(10)
    }
  })

  it('unmeasured modules are honest', () => {
    const rates = defaultErrorRates()
    const unmeasured = rates.filter(r => r.method === 'not_measured')
    for (const rate of unmeasured) {
      expect(rate.precision).toBeNull()
      expect(rate.recall).toBeNull()
      expect(rate.summary).toContain('Not')
    }
  })

  it('SHA-256 has zero error rate', () => {
    const chain = defaultErrorRates().find(r => r.module === 'evidence_chain')
    expect(chain).toBeDefined()
    expect(chain!.falsePositiveRate).toBe(0)
    expect(chain!.falseNegativeRate).toBe(0)
  })
})

describe('formatErrorRates', () => {
  it('produces markdown with table', () => {
    const md = formatErrorRates(defaultErrorRates())
    expect(md).toContain('## Error Rates')
    expect(md).toContain('Criminal Practice Direction 19A')
    expect(md).toContain('| Module |')
  })

  it('includes KS power table', () => {
    const md = formatErrorRates(defaultErrorRates())
    expect(md).toContain('KS Test Power Analysis')
    expect(md).toContain('Sample size')
    expect(md).toContain('| 20 |')
  })

  it('includes all modules', () => {
    const md = formatErrorRates(defaultErrorRates())
    expect(md).toContain('ai_text_detection')
    expect(md).toContain('timing_coordination')
    expect(md).toContain('evidence_chain')
  })
})
