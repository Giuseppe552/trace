/**
 * Probabilistic record linkage for cross-platform identity correlation.
 *
 * Given two online identities (e.g. a Google reviewer and a LinkedIn profile),
 * computes the probability they're the same person using the Fellegi-Sunter
 * model.
 *
 * Adapted from degauss — same mathematical framework, different field types.
 * degauss links data broker profiles. trace links online identities across
 * platforms for attribution.
 *
 * The log-likelihood ratio for each field:
 *   w(agree) = log₂(m / u)
 *   w(disagree) = log₂((1 - m) / (1 - u))
 *
 * where:
 *   m = P(agree | true match)
 *   u = P(agree | coincidence) — the field's base rate
 *
 * Composite weight W = Σ w_i → match probability via sigmoid.
 *
 * References:
 *   Fellegi & Sunter, "A Theory for Record Linkage" (1969, JASA 64(328))
 *   Jaro, "Advances in Record-Linkage Methodology" (1989, JASA 84(406))
 */

/** Fields relevant to online identity correlation */
export type IdentityField =
  | 'display_name'
  | 'email'
  | 'username'
  | 'profile_photo'
  | 'location_city'
  | 'location_country'
  | 'company'
  | 'domain'
  | 'ip_address'
  | 'phone'
  | 'writing_style'
  | 'review_timing'
  | 'account_age'

/**
 * Match probabilities (m-values) by field.
 * P(fields agree | identities are the same person).
 */
const M_PROB: Record<IdentityField, number> = {
  display_name: 0.88,    // people use variants across platforms
  email: 0.99,           // near-unique when it matches
  username: 0.92,        // often reused but with variations
  profile_photo: 0.80,   // different crops/ages of same photo
  location_city: 0.85,   // people move, list different granularity
  location_country: 0.95,
  company: 0.80,         // different titles for same employer
  domain: 0.95,          // domain ownership is stable
  ip_address: 0.40,      // dynamic IPs, VPNs, shared networks
  phone: 0.95,
  writing_style: 0.70,   // stylometric similarity is probabilistic
  review_timing: 0.60,   // correlated timing is suggestive
  account_age: 0.75,     // similar creation dates
}

/**
 * Base rates (u-values) by field.
 * P(fields agree | different people, by coincidence).
 */
const U_PROB: Record<IdentityField, number> = {
  display_name: 0.005,    // ~1/200 share a common name
  email: 0.0000001,       // essentially unique
  username: 0.001,        // rare coincidence
  profile_photo: 0.0001,  // reverse image match is strong
  location_city: 0.01,    // ~1% chance same city
  location_country: 0.05, // ~1/20 same country
  company: 0.005,         // ~1/200 same employer
  domain: 0.0001,         // domain ownership is rare
  ip_address: 0.02,       // NAT, shared hosting, VPN exit nodes
  phone: 0.000001,        // essentially unique
  writing_style: 0.10,    // stylometric false positive rate ~10%
  review_timing: 0.15,    // coincidental timing correlation
  account_age: 0.10,      // many accounts created in similar periods
}

export interface FieldComparison {
  field: IdentityField
  agrees: boolean
  weight: number
  mProb: number
  uProb: number
}

export interface LinkageResult {
  compositeWeight: number
  matchProbability: number
  fields: FieldComparison[]
  classification: 'match' | 'possible' | 'non_match'
}

const MATCH_THRESHOLD = 12
const POSSIBLE_THRESHOLD = 4

/**
 * Compute the Fellegi-Sunter weight for a single field comparison.
 */
export function fieldWeight(
  field: IdentityField,
  agrees: boolean,
): FieldComparison {
  const m = M_PROB[field]
  const u = U_PROB[field]

  let weight: number
  if (agrees) {
    weight = Math.log2(m / Math.max(u, 1e-15))
  } else {
    weight = Math.log2((1 - m) / Math.max(1 - u, 1e-15))
  }

  return { field, agrees, weight, mProb: m, uProb: u }
}

/**
 * Compute linkage between two identity records.
 */
export function computeLinkage(
  comparisons: Array<{ field: IdentityField; agrees: boolean }>,
): LinkageResult {
  const fields = comparisons.map(c => fieldWeight(c.field, c.agrees))
  const compositeWeight = fields.reduce((sum, f) => sum + f.weight, 0)

  // P(match | W) = 1 / (1 + 2^(-W))
  const matchProbability = 1 / (1 + Math.pow(2, -compositeWeight))

  let classification: LinkageResult['classification']
  if (compositeWeight >= MATCH_THRESHOLD) classification = 'match'
  else if (compositeWeight >= POSSIBLE_THRESHOLD) classification = 'possible'
  else classification = 'non_match'

  return { compositeWeight, matchProbability, fields, classification }
}

/**
 * Jaro-Winkler similarity for approximate string matching.
 *
 * Jaro, "Advances in Record-Linkage Methodology" (1989, JASA 84(406))
 * Winkler prefix bonus rewards strings that match from the start.
 */
export function jaroWinkler(a: string, b: string): number {
  if (a === b) return 1
  if (a.length === 0 || b.length === 0) return 0

  const matchWindow = Math.max(0, Math.floor(Math.max(a.length, b.length) / 2) - 1)
  const aMatches = new Array(a.length).fill(false)
  const bMatches = new Array(b.length).fill(false)

  let matches = 0
  let transpositions = 0

  for (let i = 0; i < a.length; i++) {
    const start = Math.max(0, i - matchWindow)
    const end = Math.min(i + matchWindow + 1, b.length)
    for (let j = start; j < end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue
      aMatches[i] = true
      bMatches[j] = true
      matches++
      break
    }
  }

  if (matches === 0) return 0

  let k = 0
  for (let i = 0; i < a.length; i++) {
    if (!aMatches[i]) continue
    while (!bMatches[k]) k++
    if (a[i] !== b[k]) transpositions++
    k++
  }

  const jaro = (
    matches / a.length
    + matches / b.length
    + (matches - transpositions / 2) / matches
  ) / 3

  let prefix = 0
  for (let i = 0; i < Math.min(4, a.length, b.length); i++) {
    if (a[i] === b[i]) prefix++
    else break
  }

  return jaro + prefix * 0.1 * (1 - jaro)
}

/**
 * Compare two display names with Jaro-Winkler.
 * Returns true if similarity ≥ 0.85 (the standard threshold).
 */
export function namesMatch(a: string, b: string): boolean {
  return jaroWinkler(a.trim().toLowerCase(), b.trim().toLowerCase()) >= 0.85
}
