/**
 * Anonymity quantification for attribution investigations.
 *
 * Inverts the degauss framework: instead of "how exposed is this person?"
 * we ask "how anonymous is this attacker?" Each piece of evidence reduces
 * the attacker's anonymity set.
 *
 * Core metric: remaining anonymity in bits.
 *   H_remaining = H_prior - I_observed
 *
 * where H_prior is the entropy of the initial suspect population
 * and I_observed is the total information gained from evidence.
 *
 * UK population: log₂(67,000,000) ≈ 26.0 bits
 * Global internet: log₂(5,400,000,000) ≈ 32.3 bits
 * Unique identification: H_remaining ≈ 0
 *
 * Reference: Shannon, C.E. (1948). A Mathematical Theory of Communication.
 * Reference: Sweeney, L. (2000). Simple Demographics Often Identify People Uniquely.
 */

const LN2 = Math.LN2

/** Population baselines for anonymity set priors */
export const POPULATION = {
  uk: 67_000_000,
  us: 334_000_000,
  global_internet: 5_400_000_000,
  uk_businesses: 5_500_000,        // UK registered companies
  uk_immigration_agencies: 2_000,  // estimate: solicitors + agencies doing citizenship
} as const

/**
 * Shannon entropy of a probability distribution.
 * H(X) = -Σ p(x) log₂ p(x)
 *
 * Returns 0 for empty or degenerate distributions.
 */
export function shannonEntropy(probs: number[]): number {
  let H = 0
  for (const p of probs) {
    if (p > 0 && p <= 1) H -= p * Math.log(p) / LN2
  }
  return H
}

/**
 * Self-information (surprisal) of a specific observation.
 * I(x) = -log₂ p(x)
 *
 * An observation with probability 1/1000 gives ~10 bits.
 * An observation with probability 1/10 gives ~3.3 bits.
 */
export function selfInfo(probability: number): number {
  if (probability <= 0 || probability >= 1) return 0
  return -Math.log(probability) / LN2
}

/**
 * Effective anonymity set size from entropy.
 * |A_eff| = 2^H
 *
 * H = 10 bits → anonymity set of 1024
 * H = 0 bits → anonymity set of 1 (identified)
 */
export function anonymitySetSize(entropyBits: number): number {
  return Math.pow(2, Math.max(0, entropyBits))
}

/**
 * Prior anonymity in bits for a population.
 * H_prior = log₂(N)
 *
 * Assumes uniform prior (no information about the attacker).
 */
export function priorAnonymity(populationSize: number): number {
  if (populationSize <= 1) return 0
  return Math.log(populationSize) / LN2
}

/** A single piece of attribution evidence */
export interface EvidenceItem {
  /** which layer produced this (whois, ct, stylometry, etc.) */
  source: string
  /** what was observed */
  observation: string
  /** how much anonymity this removes, in bits */
  informationGain: number
  /** confidence in this measurement (0-1) */
  confidence: number
}

/** Result of anonymity computation */
export interface AnonymityAssessment {
  /** starting anonymity in bits (from population prior) */
  priorBits: number
  /** total information gained from all evidence */
  totalGainBits: number
  /** remaining anonymity in bits */
  remainingBits: number
  /** effective anonymity set size */
  anonymitySet: number
  /** population used as baseline */
  population: number
  /** per-source breakdown, sorted by contribution */
  breakdown: EvidenceItem[]
  /** is the subject effectively identified? (remaining < 1 bit) */
  identified: boolean
}

/**
 * Compute remaining anonymity given a set of evidence items.
 *
 * Each evidence item contributes information bits weighted by confidence.
 * Effective gain = Σ (bits_i × confidence_i)
 *
 * The confidence weighting is conservative — it represents how much
 * we trust this particular measurement. A WHOIS record with confidence
 * 0.95 contributes 95% of its theoretical information gain.
 *
 * Correlation between evidence sources is NOT modelled here — that's
 * handled by Dempster-Shafer fusion in the fusion module. This function
 * assumes independent evidence (which overestimates information gain,
 * i.e. underestimates remaining anonymity — conservative for the
 * defender, which is the right direction).
 */
export function computeAnonymity(
  population: number,
  evidence: EvidenceItem[],
): AnonymityAssessment {
  const priorBits = priorAnonymity(population)

  const totalGainBits = evidence.reduce(
    (sum, e) => sum + e.informationGain * e.confidence,
    0,
  )

  // remaining can't go below 0
  const remainingBits = Math.max(0, priorBits - totalGainBits)
  const anonymitySet = anonymitySetSize(remainingBits)

  const breakdown = [...evidence].sort(
    (a, b) => b.informationGain * b.confidence - a.informationGain * a.confidence,
  )

  return {
    priorBits,
    totalGainBits,
    remainingBits,
    anonymitySet,
    population,
    breakdown,
    identified: remainingBits < 1,
  }
}

/**
 * Compute information gain from narrowing a categorical variable.
 *
 * If we know the attacker is in the UK (67M) and then learn they're
 * in Bradford (540K), the gain is:
 *   I = log₂(67M / 540K) ≈ 6.95 bits
 *
 * More generally: I = log₂(|prior set| / |posterior set|)
 */
export function narrowingGain(priorSetSize: number, posteriorSetSize: number): number {
  if (posteriorSetSize <= 0 || priorSetSize <= 0) return 0
  if (posteriorSetSize >= priorSetSize) return 0
  return Math.log(priorSetSize / posteriorSetSize) / LN2
}
