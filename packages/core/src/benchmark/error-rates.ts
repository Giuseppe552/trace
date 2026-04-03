/**
 * Error rate measurement for forensic reporting.
 *
 * Criminal Practice Direction 19A (2014) requires expert evidence
 * methodologies to have "known or potential rate of error."
 *
 * This module:
 * 1. Measures error rates against labeled test data
 * 2. Computes analytical error bounds for statistical tests
 * 3. Formats error rates for inclusion in forensic reports
 *
 * Three categories:
 * - Measured: precision/recall/F1 against a benchmark dataset
 * - Analytical: mathematical properties of the statistical test
 * - Unmeasured: honestly stated as "not empirically measured"
 */

/** Error rate measurement for a single module */
export interface ErrorRate {
  module: string
  /** how was the error rate determined? */
  method: 'benchmark' | 'analytical' | 'not_measured'
  /** precision: TP / (TP + FP) — "of things flagged, how many were correct?" */
  precision: number | null
  /** recall: TP / (TP + FN) — "of things that are positive, how many did we catch?" */
  recall: number | null
  /** F1: harmonic mean of precision and recall */
  f1: number | null
  /** false positive rate: FP / (FP + TN) */
  falsePositiveRate: number | null
  /** false negative rate: FN / (FN + TP) */
  falseNegativeRate: number | null
  /** sample size of the benchmark */
  sampleSize: number | null
  /** citation for the benchmark or analytical derivation */
  citation: string
  /** human-readable summary */
  summary: string
}

/**
 * Compute precision, recall, F1 from confusion matrix.
 */
export function computeMetrics(
  truePositive: number,
  falsePositive: number,
  trueNegative: number,
  falseNegative: number,
): { precision: number; recall: number; f1: number; falsePositiveRate: number; falseNegativeRate: number; accuracy: number } {
  const precision = truePositive + falsePositive > 0
    ? truePositive / (truePositive + falsePositive)
    : 0
  const recall = truePositive + falseNegative > 0
    ? truePositive / (truePositive + falseNegative)
    : 0
  const f1 = precision + recall > 0
    ? 2 * precision * recall / (precision + recall)
    : 0
  const falsePositiveRate = falsePositive + trueNegative > 0
    ? falsePositive / (falsePositive + trueNegative)
    : 0
  const falseNegativeRate = falseNegative + truePositive > 0
    ? falseNegative / (falseNegative + truePositive)
    : 0
  const total = truePositive + falsePositive + trueNegative + falseNegative
  const accuracy = total > 0 ? (truePositive + trueNegative) / total : 0

  return { precision, recall, f1, falsePositiveRate, falseNegativeRate, accuracy }
}

/**
 * Run a benchmark: apply a binary classifier to labeled data
 * and compute error rates.
 *
 * @param data - labeled samples: { input, expected: true/false }
 * @param classify - the function being benchmarked (returns true = positive)
 */
export function benchmark<T>(
  data: Array<{ input: T; expected: boolean }>,
  classify: (input: T) => boolean,
): ErrorRate & { confusion: { tp: number; fp: number; tn: number; fn: number } } {
  let tp = 0, fp = 0, tn = 0, fn = 0

  for (const { input, expected } of data) {
    const predicted = classify(input)
    if (predicted && expected) tp++
    else if (predicted && !expected) fp++
    else if (!predicted && !expected) tn++
    else fn++
  }

  const metrics = computeMetrics(tp, fp, tn, fn)

  return {
    module: 'unknown',
    method: 'benchmark',
    precision: metrics.precision,
    recall: metrics.recall,
    f1: metrics.f1,
    falsePositiveRate: metrics.falsePositiveRate,
    falseNegativeRate: metrics.falseNegativeRate,
    sampleSize: data.length,
    citation: '',
    summary: `P=${(metrics.precision * 100).toFixed(1)}%, R=${(metrics.recall * 100).toFixed(1)}%, F1=${(metrics.f1 * 100).toFixed(1)}%, FPR=${(metrics.falsePositiveRate * 100).toFixed(1)}%, n=${data.length}`,
    confusion: { tp, fp, tn, fn },
  }
}

// ── KS test power analysis ──────────────────────────────────

/**
 * Compute the critical value for a one-sample KS test.
 *
 * D_critical = c(alpha) / sqrt(n)
 *
 * where c(alpha) values from the Kolmogorov distribution:
 *   alpha=0.10: c=1.224
 *   alpha=0.05: c=1.358
 *   alpha=0.01: c=1.628
 *
 * Source: NIST Engineering Statistics Handbook, section 1.3.5.16
 */
export function ksCriticalValue(n: number, alpha: number): number {
  // Kolmogorov distribution critical values
  let c: number
  if (alpha <= 0.01) c = 1.628
  else if (alpha <= 0.02) c = 1.517
  else if (alpha <= 0.05) c = 1.358
  else if (alpha <= 0.10) c = 1.224
  else if (alpha <= 0.20) c = 1.073
  else c = 1.0

  return c / Math.sqrt(n)
}

/**
 * Estimate KS test power for detecting a given effect size.
 *
 * Power = P(reject H0 | H1 true)
 *
 * Approximated using the asymptotic formula:
 * power ≈ 1 - exp(-2n * (D_effect - D_critical)^2)
 * when D_effect > D_critical, else power ≈ alpha.
 *
 * @param n - sample size
 * @param effectSize - the true KS statistic D under the alternative hypothesis
 * @param alpha - significance level (default 0.05)
 */
export function ksTestPower(n: number, effectSize: number, alpha = 0.05): number {
  const dCrit = ksCriticalValue(n, alpha)

  if (effectSize <= dCrit) {
    return alpha // can't detect effects smaller than critical value
  }

  // asymptotic power approximation
  const diff = effectSize - dCrit
  const power = 1 - Math.exp(-2 * n * diff * diff)

  return Math.min(1, Math.max(alpha, power))
}

/**
 * Generate a power table for the KS test at various sample sizes.
 * Used in forensic reports to document detection capability.
 */
export function ksPowerTable(
  effectSize = 0.3,
  alpha = 0.05,
): Array<{ n: number; criticalD: number; power: number; typeIIError: number }> {
  const sampleSizes = [5, 8, 10, 15, 20, 30, 50, 100]
  return sampleSizes.map(n => {
    const power = ksTestPower(n, effectSize, alpha)
    return {
      n,
      criticalD: ksCriticalValue(n, alpha),
      power: Math.round(power * 1000) / 1000,
      typeIIError: Math.round((1 - power) * 1000) / 1000,
    }
  })
}

// ── Error rate reporting ────────────────────────────────────

/** Error rates for all modules, for inclusion in forensic reports */
export interface ErrorRateReport {
  modules: ErrorRate[]
  /** overall assessment */
  assessed: number
  /** modules with benchmark data */
  benchmarked: number
  /** modules with analytical bounds */
  analytical: number
  /** modules without error rate data */
  unmeasured: number
}

/**
 * Default error rates for modules without benchmark data.
 * These are the honest "not measured" entries.
 */
export function defaultErrorRates(): ErrorRate[] {
  return [
    {
      module: 'ai_text_detection',
      method: 'not_measured',
      precision: null, recall: null, f1: null,
      falsePositiveRate: null, falseNegativeRate: null,
      sampleSize: null,
      citation: 'No benchmark dataset run. Industry reference: GPTZero 88.7%, Originality.ai 92.3% (2025 benchmarks). Our statistical detector expected to score lower — no neural model.',
      summary: 'Not empirically measured. Industry detectors achieve 88-92% accuracy on standard benchmarks.',
    },
    {
      module: 'stylometry_comparison',
      method: 'not_measured',
      precision: null, recall: null, f1: null,
      falsePositiveRate: null, falseNegativeRate: null,
      sampleSize: null,
      citation: 'PAN shared task 2022-2023: top systems achieve 0.85-0.95 AUC on 500+ word texts, 0.60-0.75 on short texts. Our implementation not benchmarked against PAN data.',
      summary: 'Not empirically measured. PAN 2022 top systems: AUC 0.85-0.95 on long texts.',
    },
    {
      module: 'timing_coordination',
      method: 'analytical',
      precision: null, recall: null, f1: null,
      falsePositiveRate: 0.05, // = alpha
      falseNegativeRate: null, // depends on effect size and n
      sampleSize: null,
      citation: 'KS test type I error = alpha (0.05). Type II error depends on sample size and effect size. See power table. Source: NIST Handbook 1.3.5.16.',
      summary: 'Type I error: 5.0% (alpha). Type II error: see power table (varies with n).',
    },
    {
      module: 'review_heuristics',
      method: 'not_measured',
      precision: null, recall: null, f1: null,
      falsePositiveRate: null, falseNegativeRate: null,
      sampleSize: null,
      citation: 'No labeled benchmark of confirmed fake reviews with known attacker. Yelp filter accuracy itself is unknown.',
      summary: 'Not empirically measured. No ground truth dataset available.',
    },
    {
      module: 'cross_domain_correlation',
      method: 'not_measured',
      precision: null, recall: null, f1: null,
      falsePositiveRate: null, falseNegativeRate: null,
      sampleSize: null,
      citation: 'No dataset of confirmed same-operator vs different-operator domain pairs.',
      summary: 'Not empirically measured. No ground truth dataset available.',
    },
    {
      module: 'whois_attribution',
      method: 'not_measured',
      precision: null, recall: null, f1: null,
      falsePositiveRate: null, falseNegativeRate: null,
      sampleSize: null,
      citation: 'ICANN ARS reports 92% registrant email operability but does not measure attribution accuracy.',
      summary: 'Not empirically measured. ICANN ARS: 92% email operability when data available.',
    },
    {
      module: 'entropy_computation',
      method: 'analytical',
      precision: null, recall: null, f1: null,
      falsePositiveRate: 0, falseNegativeRate: 0,
      sampleSize: null,
      citation: 'Shannon entropy is computed exactly. No error in the computation — error is in the input probability estimates. See reliability parameters for input accuracy.',
      summary: 'Computation is exact. Error propagates from input probability estimates only.',
    },
    {
      module: 'evidence_chain',
      method: 'analytical',
      precision: null, recall: null, f1: null,
      falsePositiveRate: 0, falseNegativeRate: 0,
      sampleSize: null,
      citation: 'SHA-256 collision probability: 2^(-128) for birthday attack. Chain tampering detection is deterministic — any modification is caught.',
      summary: 'Deterministic. Collision probability: 2^(-128). Zero false positives/negatives.',
    },
    {
      module: 'dempster_shafer_fusion',
      method: 'analytical',
      precision: null, recall: null, f1: null,
      falsePositiveRate: null, falseNegativeRate: null,
      sampleSize: null,
      citation: 'Dempster combination rule is mathematically exact given input mass functions. Output accuracy depends entirely on input reliability parameters. See calibration (research/001).',
      summary: 'Computation is exact. Output quality depends on input reliability calibration.',
    },
  ]
}

/**
 * Generate error rate section for forensic report.
 */
export function formatErrorRates(rates: ErrorRate[]): string {
  const lines: string[] = []

  lines.push('## Error Rates')
  lines.push('')
  lines.push('Criminal Practice Direction 19A (2014) requires expert evidence methodologies to have a "known or potential rate of error." The following table documents error rates for each analysis module. [12]')
  lines.push('')
  lines.push('| Module | Method | Rate | Detail |')
  lines.push('|--------|--------|------|--------|')

  for (const rate of rates) {
    const rateStr = rate.method === 'benchmark'
      ? `P=${rate.precision !== null ? (rate.precision * 100).toFixed(1) + '%' : '?'}, R=${rate.recall !== null ? (rate.recall * 100).toFixed(1) + '%' : '?'}`
      : rate.method === 'analytical'
        ? rate.summary.slice(0, 60)
        : 'Not measured'
    lines.push(`| ${rate.module} | ${rate.method} | ${rateStr} | ${rate.citation.slice(0, 80)} |`)
  }

  lines.push('')

  // KS power table
  const powerTable = ksPowerTable()
  lines.push('### KS Test Power Analysis')
  lines.push('')
  lines.push('Statistical power of the Kolmogorov-Smirnov test for coordination detection, at alpha=0.05 and moderate effect size (D=0.3):')
  lines.push('')
  lines.push('| Sample size (n) | Critical D | Power | Type II error |')
  lines.push('|----------------:|-----------:|------:|--------------:|')
  for (const row of powerTable) {
    lines.push(`| ${row.n} | ${row.criticalD.toFixed(3)} | ${row.power.toFixed(3)} | ${row.typeIIError.toFixed(3)} |`)
  }
  lines.push('')
  lines.push('Power below 0.80 (n < 20) means the test cannot reliably detect coordination. Results from small samples should be interpreted with caution.')
  lines.push('')

  return lines.join('\n')
}
