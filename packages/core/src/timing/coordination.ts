/**
 * Coordinated behavior detection via timing analysis.
 *
 * Real human activity follows natural patterns — reviews spread over
 * days/weeks with irregular intervals. Coordinated campaigns (fake
 * review bursts, astroturfing) have statistical signatures:
 *
 * 1. Inter-arrival times that are too uniform (low variance)
 * 2. Burst patterns that fail the Poisson test
 * 3. Periodicity that humans don't produce naturally
 *
 * Uses the same KS test from threadr — if threadr uses it to avoid
 * detection, trace uses it to detect.
 *
 * Reference: Kolmogorov, A.N. (1933). "Sulla determinazione empirica
 *   di una legge di distribuzione."
 * Reference: Biryukov et al. (2014). Deanonymisation of clients in
 *   Bitcoin P2P network. (timing analysis framework)
 */

/**
 * Kolmogorov-Smirnov test: does a sample come from a given distribution?
 *
 * Computes the KS statistic D = max|F_n(x) - F(x)| where F_n is the
 * empirical CDF and F is the reference CDF.
 *
 * Returns D and approximate p-value using the Kolmogorov distribution.
 *
 * @param sample - Observed values (e.g. inter-arrival times in ms)
 * @param referenceCdf - CDF of the reference distribution
 */
export function ksTest(
  sample: number[],
  referenceCdf: (x: number) => number,
): { D: number; pValue: number; n: number } {
  const n = sample.length
  if (n === 0) return { D: 0, pValue: 1, n: 0 }

  const sorted = [...sample].sort((a, b) => a - b)

  let D = 0
  for (let i = 0; i < n; i++) {
    const empiricalBelow = (i + 1) / n
    const empiricalAbove = i / n
    const theoretical = referenceCdf(sorted[i])

    D = Math.max(D, Math.abs(empiricalBelow - theoretical))
    D = Math.max(D, Math.abs(empiricalAbove - theoretical))
  }

  // approximate p-value using Kolmogorov distribution
  // P(D > d) ≈ 2·Σ (-1)^(k-1) exp(-2k²n·d²)
  const lambda = (Math.sqrt(n) + 0.12 + 0.11 / Math.sqrt(n)) * D
  let pValue = 0
  for (let k = 1; k <= 100; k++) {
    const term = 2 * Math.pow(-1, k - 1) * Math.exp(-2 * k * k * lambda * lambda)
    pValue += term
    if (Math.abs(term) < 1e-10) break
  }
  pValue = Math.max(0, Math.min(1, pValue))

  return { D, pValue, n }
}

/**
 * Exponential CDF — F(x) = 1 - e^(-x/μ)
 *
 * Natural human inter-arrival times approximate an exponential
 * distribution (Poisson process). If the KS test rejects exponential,
 * the timing pattern is likely artificial.
 */
export function exponentialCdf(mean: number): (x: number) => number {
  return (x: number) => {
    if (x < 0) return 0
    return 1 - Math.exp(-x / mean)
  }
}

/**
 * Compute inter-arrival times from a series of timestamps.
 */
export function interArrivalTimes(timestamps: number[]): number[] {
  if (timestamps.length < 2) return []
  const sorted = [...timestamps].sort((a, b) => a - b)
  const intervals: number[] = []
  for (let i = 1; i < sorted.length; i++) {
    intervals.push(sorted[i] - sorted[i - 1])
  }
  return intervals
}

/**
 * Coefficient of variation: CV = σ/μ
 *
 * For an exponential distribution (natural Poisson process), CV = 1.
 * CV << 1 → too regular (coordinated scheduling)
 * CV >> 1 → too bursty (but could be natural heavy-tailed behavior)
 */
export function coefficientOfVariation(values: number[]): number {
  if (values.length < 2) return 0
  const mean = values.reduce((a, b) => a + b, 0) / values.length
  if (mean === 0) return 0
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (values.length - 1)
  return Math.sqrt(variance) / mean
}

/** Result of coordination analysis */
export interface CoordinationResult {
  /** number of events analyzed */
  eventCount: number
  /** KS test against exponential distribution */
  ksExponential: { D: number; pValue: number }
  /** coefficient of variation of inter-arrival times */
  cv: number
  /** mean inter-arrival time in the input unit (ms, seconds, etc.) */
  meanInterval: number
  /** is this likely coordinated? */
  likelyCoordinated: boolean
  /** confidence in the coordination assessment (0-1) */
  confidence: number
  /** human-readable explanation */
  reason: string
}

/**
 * Analyze a series of timestamps for signs of coordination.
 *
 * @param timestamps - Event timestamps (Unix ms or any consistent unit)
 * @param options - Thresholds for detection
 */
export function detectCoordination(
  timestamps: number[],
  options: {
    /** p-value threshold for KS test (default 0.05) */
    significanceLevel?: number
    /** CV threshold below which timing is "too regular" (default 0.3) */
    cvRegularThreshold?: number
  } = {},
): CoordinationResult {
  const { significanceLevel = 0.05, cvRegularThreshold = 0.3 } = options

  const intervals = interArrivalTimes(timestamps)

  if (intervals.length < 3) {
    return {
      eventCount: timestamps.length,
      ksExponential: { D: 0, pValue: 1 },
      cv: 0,
      meanInterval: 0,
      likelyCoordinated: false,
      confidence: 0,
      reason: 'insufficient data (need ≥4 events)',
    }
  }

  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length
  const cv = coefficientOfVariation(intervals)
  const ks = ksTest(intervals, exponentialCdf(mean))

  // coordination signals
  const ksRejects = ks.pValue < significanceLevel
  const tooRegular = cv < cvRegularThreshold

  let likelyCoordinated = false
  let confidence = 0
  let reason = ''

  if (ksRejects && tooRegular) {
    likelyCoordinated = true
    confidence = Math.min(0.95, 1 - ks.pValue)
    reason = `timing rejects exponential (p=${ks.pValue.toFixed(4)}) and is unusually regular (CV=${cv.toFixed(3)}, expected ~1.0 for natural behavior)`
  } else if (ksRejects) {
    likelyCoordinated = true
    confidence = Math.min(0.80, 1 - ks.pValue)
    reason = `timing rejects exponential distribution (p=${ks.pValue.toFixed(4)}, KS D=${ks.D.toFixed(4)})`
  } else if (tooRegular) {
    likelyCoordinated = true
    confidence = 0.60
    reason = `inter-arrival times are unusually regular (CV=${cv.toFixed(3)}, expected ~1.0 for natural behavior)`
  } else {
    reason = `timing is consistent with natural human behavior (KS p=${ks.pValue.toFixed(4)}, CV=${cv.toFixed(3)})`
  }

  return {
    eventCount: timestamps.length,
    ksExponential: ks,
    cv,
    meanInterval: mean,
    likelyCoordinated,
    confidence,
    reason,
  }
}
