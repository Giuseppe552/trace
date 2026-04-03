/**
 * Dempster-Shafer evidence fusion for attribution investigations.
 *
 * Each attribution layer (WHOIS, CT, stylometry, reviews, etc.) produces
 * a mass function over Θ = {ATTRIBUTED, NOT_ATTRIBUTED}. Dempster's
 * combination rule fuses them, handling conflicting evidence properly.
 *
 * This is the same framework as epsilon-tx's privacy scoring, inverted:
 * epsilon-tx fuses evidence of EXPOSURE vs PRIVACY.
 * trace fuses evidence of ATTRIBUTION vs NON-ATTRIBUTION.
 *
 * Why not just average? If WHOIS says "definitely Company X" and
 * stylometry says "definitely not Company X", an average gives 0.5 —
 * misleadingly confident. Dempster-Shafer detects the conflict (high K)
 * and reports high uncertainty instead.
 *
 * Reference: Dempster, A.P. (1967). "Upper and lower probabilities
 *   induced by a multivalued mapping." Ann. Math. Stat. 38(2).
 * Reference: Shafer, G. (1976). "A Mathematical Theory of Evidence."
 *   Princeton University Press.
 */

/**
 * Mass function over Θ = {ATTRIBUTED, NOT_ATTRIBUTED}.
 *
 * attributed:     m({ATTRIBUTED}) — evidence pointing to this suspect
 * not_attributed: m({NOT_ATTRIBUTED}) — evidence against this suspect
 * uncertain:      m(Θ) — can't tell from this source
 *
 * Constraint: attributed + not_attributed + uncertain = 1
 */
export interface MassFunction {
  attributed: number
  not_attributed: number
  uncertain: number
  source: string
}

/**
 * Result of fusing multiple evidence sources.
 */
export interface FusedAttribution {
  /** Bel(ATTRIBUTED) — lower bound on attribution confidence */
  belief: number
  /** Pl(ATTRIBUTED) = 1 - m({NOT_ATTRIBUTED}) — upper bound */
  plausibility: number
  /** Pl - Bel — width of the uncertainty interval */
  uncertaintyWidth: number
  /** K — total conflicting mass across all combinations */
  conflict: number
  /** contributing sources */
  sources: string[]
  /** human-readable confidence level */
  level: 'high' | 'medium' | 'low' | 'inconclusive'
}

/**
 * Create a mass function from an attribution score.
 *
 * @param score - How strongly this evidence points to the suspect (0-1)
 * @param reliability - How much we trust this source (0-1)
 * @param source - Name of the attribution layer
 */
export function createMass(
  score: number,
  reliability: number,
  source: string,
): MassFunction {
  // reliability gates how much of the mass is informative vs uncertain
  const informative = Math.min(Math.max(reliability, 0), 1)
  const s = Math.min(Math.max(score, 0), 1)

  return {
    attributed: informative * s,
    not_attributed: informative * (1 - s),
    uncertain: 1 - informative,
    source,
  }
}

/**
 * Dempster's combination rule for two mass functions.
 *
 * Focal elements: {ATTRIBUTED}, {NOT_ATTRIBUTED}, Θ
 *
 * Intersections:
 *   {A} ∩ {A} = {A}
 *   {N} ∩ {N} = {N}
 *   {A} ∩ {N} = ∅  (conflict)
 *   Any ∩ Θ = Any
 *   Θ ∩ Θ = Θ
 *
 * Normalisation: divide by (1 - K) where K = conflicting mass.
 * If K = 1 (total conflict), return maximum uncertainty.
 */
export function combine(m1: MassFunction, m2: MassFunction): MassFunction {
  // agreement masses
  const aa = m1.attributed * m2.attributed
  const au = m1.attributed * m2.uncertain
  const ua = m1.uncertain * m2.attributed
  const nn = m1.not_attributed * m2.not_attributed
  const nu = m1.not_attributed * m2.uncertain
  const un = m1.uncertain * m2.not_attributed
  const uu = m1.uncertain * m2.uncertain

  // conflict mass
  const K = m1.attributed * m2.not_attributed + m1.not_attributed * m2.attributed
  const norm = 1 - K

  if (norm <= 0) {
    // total conflict — sources completely disagree
    return {
      attributed: 0,
      not_attributed: 0,
      uncertain: 1,
      source: `${m1.source}+${m2.source}`,
    }
  }

  return {
    attributed: (aa + au + ua) / norm,
    not_attributed: (nn + nu + un) / norm,
    uncertain: uu / norm,
    source: `${m1.source}+${m2.source}`,
  }
}

/**
 * Fuse all evidence sources using iterated Dempster combination.
 *
 * Order doesn't matter — Dempster's rule is commutative and associative.
 * (Verified in tests.)
 */
export function fuseEvidence(masses: MassFunction[]): FusedAttribution {
  if (masses.length === 0) {
    return {
      belief: 0,
      plausibility: 1,
      uncertaintyWidth: 1,
      conflict: 0,
      sources: [],
      level: 'inconclusive',
    }
  }

  if (masses.length === 1) {
    const m = masses[0]
    const belief = m.attributed
    const plausibility = 1 - m.not_attributed
    return {
      belief,
      plausibility,
      uncertaintyWidth: plausibility - belief,
      conflict: 0,
      sources: [m.source],
      level: classifyConfidence(belief, plausibility - belief),
    }
  }

  let fused = masses[0]
  let totalConflict = 0

  for (let i = 1; i < masses.length; i++) {
    const K = fused.attributed * masses[i].not_attributed
      + fused.not_attributed * masses[i].attributed
    // accumulate conflict: 1 - Π(1 - K_i)
    totalConflict = 1 - (1 - totalConflict) * (1 - K)
    fused = combine(fused, masses[i])
  }

  const belief = fused.attributed
  const plausibility = 1 - fused.not_attributed
  const uncertaintyWidth = plausibility - belief

  return {
    belief,
    plausibility,
    uncertaintyWidth,
    conflict: totalConflict,
    sources: masses.map(m => m.source),
    level: classifyConfidence(belief, uncertaintyWidth),
  }
}

function classifyConfidence(
  belief: number,
  uncertaintyWidth: number,
): FusedAttribution['level'] {
  if (belief >= 0.85 && uncertaintyWidth < 0.15) return 'high'
  if (belief >= 0.60 && uncertaintyWidth < 0.30) return 'medium'
  if (belief >= 0.30) return 'low'
  return 'inconclusive'
}

/**
 * Reliability parameters for each attribution layer.
 *
 * Based on published accuracy data and practical experience.
 * Higher = more weight in the fusion.
 */
export const LAYER_RELIABILITY: Record<string, number> = {
  whois: 0.90,          // WHOIS records are authoritative when not privacy-proxied
  whois_historical: 0.80, // older records may be stale
  ct: 0.85,             // certificate transparency logs are append-only, reliable
  email_headers: 0.70,  // headers can be spoofed, but rarely perfectly
  stylometry: 0.55,     // 94% on long texts (Abbasi & Chen), lower on short reviews
  review_profile: 0.60, // profile patterns are suggestive but not definitive
  reverse_image: 0.80,  // exact match is strong, similar match is weaker
  infrastructure: 0.75, // shared hosting complicates attribution
  timing: 0.50,         // coordinated timing is suggestive, not conclusive
  dns: 0.85,            // DNS records are factual
}
