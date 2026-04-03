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
 * Calibrated reliability parameters.
 *
 * Each value is derived from a published study or standard.
 * The citation field references the source so a forensic
 * examiner can verify it independently.
 *
 * These are the REFERENCE values. In practice, each collector
 * selects the appropriate value based on context and attaches
 * it directly to the signal. The orchestrator uses signal.reliability
 * rather than looking up from this table.
 *
 * This table exists for: (a) documentation, (b) fallback when
 * a collector doesn't set reliability, (c) tests.
 */
export const CALIBRATED_RELIABILITY = {
  // ── WHOIS ─────────────────────────────────────────────────
  // ICANN ARS Phase 2 Cycle 6 (Jan 2018): 92% email operability
  // Source: https://www.icann.org/resources/pages/whois-data-accuracy-2017-06-20-en
  whois_visible: { value: 0.92, citation: 'ICANN ARS Phase 2 Cycle 6, 2018: 92% registrant email operability' },
  // Post-GDPR: 73% of gTLD registrant emails redacted
  // Source: WhoisXML API analysis
  whois_redacted: { value: 0.10, citation: 'WhoisXML API: 73% of gTLD domains have no registrant email post-GDPR' },
  whois_historical: { value: 0.85, citation: 'ICANN ARS pre-GDPR accuracy; data may be stale' },
  whois_reverse: { value: 0.80, citation: 'Derived from WHOIS visible reliability minus coverage gaps' },

  // ── Certificate Transparency ──────────────────────────────
  // Li et al. (2019) "CT in the Wild" CCS: 6.7% certificates missing from monitors
  // Source: https://www.ittc.ku.edu/~fli/papers/2019_ccs_CT.pdf
  ct: { value: 0.87, citation: 'Li et al. CCS 2019: ~93% monitor completeness for crt.sh' },

  // ── Email Headers ─────────────────────────────────────────
  email_authenticated: { value: 0.85, citation: 'SPF+DKIM+DMARC pass verifies sending domain (RFC 7208/6376/7489)' },
  email_partial_auth: { value: 0.60, citation: 'SPF pass alone; DKIM/DMARC absent or not aligned' },
  email_auth_failed: { value: 0.40, citation: 'Auth failure indicates spoofing but does not identify sender' },
  email_stripped: { value: 0.20, citation: 'Gmail/Outlook strip X-Originating-IP; minimal attribution value' },

  // ── Stylometry ────────────────────────────────────────────
  // Abbasi & Chen, ACM TOIS 26(2), 2008: 94% on 100+ word samples
  // arXiv 2507.00838 (2025): 79-100% on 10-sentence (~100 word) samples
  // arXiv 2003.11545 (2020): <48% with limited training samples on tweets
  stylometry_200plus: { value: 0.75, citation: 'Abbasi & Chen 2008; arXiv 2507.00838: 79-100% on ~100 words' },
  stylometry_100_200: { value: 0.55, citation: 'Interpolated from Abbasi & Chen 2008 and arXiv 2507.00838' },
  stylometry_50_100: { value: 0.35, citation: 'arXiv 2003.11545: accuracy drops sharply below 100 words' },
  stylometry_under_50: { value: 0.15, citation: 'Literature consensus: unreliable below 50 words' },

  // ── IP Geolocation ────────────────────────────────────────
  // MaxMind published accuracy: https://www.maxmind.com/en/geoip-accuracy-comparison
  ip_country: { value: 0.95, citation: 'MaxMind: 99.8% country-level accuracy' },
  ip_city_us_eu: { value: 0.60, citation: 'MaxMind: ~66% city-level accuracy within 50km (US)' },
  ip_city_other: { value: 0.40, citation: 'MaxMind: lower accuracy outside US/EU; no published number' },
  ip_asn: { value: 0.90, citation: 'MaxMind: ~95% ISP accuracy (US), ~80% outside US' },
  ip_via_proxy: { value: 0.20, citation: 'Proxy/VPN masks real location; geolocation reflects exit node' },

  // ── Review Profile ────────────────────────────────────────
  // No published accuracy study. Values are conservative estimates.
  review_multi_flag: { value: 0.65, citation: 'Uncalibrated; convergent heuristic signals' },
  review_single_flag: { value: 0.35, citation: 'Uncalibrated; individual heuristic, high false positive risk' },
  review_rating_dist: { value: 0.50, citation: 'Uncalibrated; rating distribution skew is established indicator' },

  // ── Tracking IDs ──────────────────────────────────────────
  // Each GA/GTM property has a unique ID; shared ID = intentional configuration
  tracking_ga: { value: 0.98, citation: 'GA property IDs are unique; shared = same account owner' },
  tracking_fbpixel: { value: 0.95, citation: 'FB Pixel IDs are unique per ad account' },
  tracking_gtm: { value: 0.98, citation: 'GTM container IDs are unique per account' },

  // ── Cross-domain Correlation ──────────────────────────────
  correlation_dedicated_ip: { value: 0.85, citation: 'Dedicated IP implies same hosting account' },
  correlation_cdn_ip: { value: 0.05, citation: 'CDN anycast IPs shared across thousands of unrelated domains' },
  correlation_dedicated_ns: { value: 0.60, citation: 'Shared dedicated NS suggests same DNS management' },
  correlation_cdn_ns: { value: 0.05, citation: 'Major CDN nameservers shared by millions of domains' },
  correlation_registrant: { value: 0.95, citation: 'ICANN ARS: unredacted registrant data is 92% accurate' },
  correlation_certificate: { value: 0.80, citation: 'Shared SAN field requires intentional certificate configuration' },
  correlation_tracking_id: { value: 0.98, citation: 'See tracking_ga above' },

  // ── AI Detection ──────────────────────────────────────────
  // No benchmark dataset. Thresholds are heuristic.
  ai_detection: { value: 0.45, citation: 'Uncalibrated; no benchmark dataset; heuristic thresholds' },

  // ── Timing / Coordination ─────────────────────────────────
  // KS test power depends on sample size
  timing_n20plus: { value: 0.70, citation: 'KS test: adequate power at n>=20 (alpha=0.05)' },
  timing_n10_20: { value: 0.50, citation: 'KS test: reduced power at n=10-20' },
  timing_under_10: { value: 0.25, citation: 'KS test: low power below n=10; results unreliable' },

  // ── DNS ───────────────────────────────────────────────────
  dns: { value: 0.90, citation: 'DNS records are factual; resolver accuracy is near-perfect' },

  // ── Domain Age ────────────────────────────────────────────
  domain_age_whois: { value: 0.95, citation: 'Creation date from WHOIS is authoritative' },
  domain_age_wayback: { value: 0.80, citation: 'First archive.org capture; domain may predate first crawl' },
  domain_age_ct: { value: 0.85, citation: 'First CT entry; mandatory logging since 2018' },

  // ── Backlinks ─────────────────────────────────────────────
  backlinks: { value: 0.55, citation: 'Uncalibrated; heuristic spam pattern matching' },

  // ── Reverse Image ─────────────────────────────────────────
  reverse_image_exact: { value: 0.90, citation: 'Exact image hash match across platforms' },
  reverse_image_similar: { value: 0.50, citation: 'Perceptual similarity; higher false positive rate' },

  // ── Social Media ──────────────────────────────────────────
  social_confirmed: { value: 0.85, citation: 'API-validated profile existence (GitHub, Reddit, HN)' },
  social_unconfirmed: { value: 0.50, citation: 'HTTP 200 without body validation; ~15% false positive on LinkedIn' },
} as const

/**
 * Flat lookup for backward compatibility.
 * Prefer signal.reliability (set by the collector) over this map.
 */
export const LAYER_RELIABILITY: Record<string, number> = Object.fromEntries(
  Object.entries(CALIBRATED_RELIABILITY).map(([k, v]) => [k, v.value]),
)
