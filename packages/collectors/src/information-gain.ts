/**
 * Information gain computation from population base rates.
 *
 * I(x) = -log2 p(x)
 *
 * Where p(x) is the probability of observing this specific value
 * by coincidence in the suspect population. Computed from empirical
 * base rate data, not hardcoded constants.
 *
 * Reference: Shannon, C.E. (1948). "A Mathematical Theory of Communication."
 */

const LN2 = Math.LN2

/**
 * Self-information in bits.
 * I(x) = -log2(p)
 */
export function selfInfo(probability: number): number {
  if (probability <= 0 || probability >= 1) return 0
  return -Math.log(probability) / LN2
}

// ── Registrar market share ──────────────────────────────────
// Source: domainnamewire.com, Dec 2025; DNIB Q3 2025 (378.5M total domains)

const REGISTRAR_SHARE: Record<string, number> = {
  'godaddy': 0.139,
  'namecheap': 0.032,
  'tucows': 0.028,
  'cloudflare': 0.005,
  'google': 0.012,
  'name.com': 0.008,
  'enom': 0.015,
  'gandi': 0.006,
  'ionos': 0.020,
  'ovh': 0.010,
  'register.com': 0.005,
  'network solutions': 0.018,
  'hover': 0.003,
  'porkbun': 0.004,
  'dynadot': 0.003,
}

/**
 * Information gain from knowing the registrar.
 *
 * Large registrars (GoDaddy 14%) give ~2.8 bits.
 * Small registrars (<0.1%) give ~10 bits.
 */
export function registrarInfoGain(registrar: string): number {
  const key = registrar.toLowerCase()
  for (const [name, share] of Object.entries(REGISTRAR_SHARE)) {
    if (key.includes(name)) return selfInfo(share)
  }
  // unknown registrar — assume small, ~0.1% share
  return selfInfo(0.001)
}

// ── Nameserver provider share ───────────────────────────────
// Source: 6sense.com, 2024; w3techs.com

const NS_PROVIDER_PATTERNS: Array<{ pattern: RegExp; share: number }> = [
  { pattern: /cloudflare/i, share: 0.20 },
  { pattern: /godaddy|domaincontrol/i, share: 0.33 },
  { pattern: /awsdns|amazonaws/i, share: 0.05 },
  { pattern: /google|googledomains/i, share: 0.05 },
  { pattern: /digitalocean/i, share: 0.02 },
  { pattern: /hetzner/i, share: 0.01 },
  { pattern: /ionos|ui-dns/i, share: 0.03 },
  { pattern: /ovh/i, share: 0.02 },
  { pattern: /namecheap|registrar-servers/i, share: 0.03 },
  { pattern: /name\.com/i, share: 0.01 },
  { pattern: /dnsimple/i, share: 0.005 },
  { pattern: /netlify/i, share: 0.01 },
  { pattern: /vercel/i, share: 0.005 },
]

/**
 * Information gain from shared nameservers.
 *
 * Cloudflare NS (20% share): 2.3 bits — nearly meaningless.
 * Custom/dedicated NS (<0.1%): 10+ bits — strong signal.
 */
export function nameserverInfoGain(nameservers: string[]): number {
  const nsStr = nameservers.join(' ').toLowerCase()
  for (const { pattern, share } of NS_PROVIDER_PATTERNS) {
    if (pattern.test(nsStr)) return selfInfo(share)
  }
  // unknown/dedicated NS — rare, strong signal
  return selfInfo(0.001)
}

// ── CDN/hosting detection ───────────────────────────────────

const CDN_ASNS = new Set([
  13335,  // Cloudflare
  20940,  // Akamai
  54113,  // Fastly
  16509,  // AWS
  15169,  // Google
  8075,   // Microsoft
  14618,  // Amazon
])

/**
 * Information gain from a shared IP address.
 *
 * CDN/anycast IP (shared by thousands): ~1-2 bits.
 * Shared hosting IP (500 domains): ~10 bits.
 * Dedicated IP (1 domain): ~25 bits.
 */
export function ipInfoGain(ip: string, asn: number | null, isHosting: boolean | null): number {
  if (asn && CDN_ASNS.has(asn)) {
    // CDN — millions share these IPs
    return 1.5
  }
  if (isHosting) {
    // shared hosting — average 500 domains per IP
    // p = 500 / 378M ≈ 1.3e-6
    return selfInfo(500 / 378_500_000)
  }
  // residential or dedicated
  // very few domains per IP — high info gain
  return selfInfo(5 / 378_500_000)
}

// ── City population ─────────────────────────────────────────

const CITY_POP: Record<string, number> = {
  // UK
  'london': 9_000_000,
  'birmingham': 1_150_000,
  'manchester': 550_000,
  'leeds': 800_000,
  'glasgow': 635_000,
  'liverpool': 500_000,
  'bristol': 470_000,
  'edinburgh': 525_000,
  'sheffield': 585_000,
  'cardiff': 365_000,
  'belfast': 345_000,
  'bradford': 540_000,
  'nottingham': 330_000,
  'newcastle': 300_000,
  // US major
  'new york': 8_300_000,
  'los angeles': 3_900_000,
  'chicago': 2_700_000,
  'houston': 2_300_000,
  'phoenix': 1_600_000,
  'san francisco': 870_000,
  'seattle': 740_000,
  'boston': 685_000,
  'miami': 450_000,
  'atlanta': 500_000,
  // EU major
  'paris': 2_200_000,
  'berlin': 3_700_000,
  'rome': 2_800_000,
  'madrid': 3_300_000,
  'amsterdam': 900_000,
  'dublin': 1_400_000,
  'toronto': 2_800_000,
  'sydney': 5_300_000,
  'tokyo': 14_000_000,
}

const COUNTRY_POP: Record<string, number> = {
  GB: 67_000_000, US: 334_000_000, DE: 84_000_000, FR: 68_000_000,
  IT: 59_000_000, ES: 47_000_000, NL: 17_500_000, PL: 38_000_000,
  CA: 38_000_000, AU: 26_000_000, IN: 1_400_000_000, BR: 215_000_000,
  JP: 125_000_000, RU: 144_000_000, CN: 1_400_000_000, IE: 5_100_000,
  SE: 10_500_000, NO: 5_500_000, DK: 5_900_000, FI: 5_600_000,
  BE: 11_600_000, AT: 9_100_000, CH: 8_800_000, PT: 10_300_000,
  CZ: 10_800_000, GR: 10_400_000,
}

/**
 * Information gain from knowing the city.
 * I = log2(country_pop / city_pop)
 *
 * London (9M in 67M UK): 2.9 bits — weak.
 * Bradford (540K in 67M UK): 6.95 bits — moderate.
 * Small town (5K in 67M UK): 13.7 bits — strong.
 */
export function cityInfoGain(
  city: string,
  countryCode: string | null,
): number {
  const cityLower = city.toLowerCase().trim()
  const countryPop = COUNTRY_POP[countryCode ?? ''] ?? 50_000_000
  const cityPop = CITY_POP[cityLower]

  if (cityPop) {
    return Math.log(countryPop / cityPop) / LN2
  }

  // unknown city — estimate as medium-sized (100K)
  return Math.log(countryPop / 100_000) / LN2
}

/**
 * Information gain from country identification.
 * I = log2(world_pop / country_pop)
 */
export function countryInfoGain(countryCode: string): number {
  const pop = COUNTRY_POP[countryCode] ?? 50_000_000
  return Math.log(8_000_000_000 / pop) / LN2
}

/**
 * Information gain from an email address.
 * Email is unique by definition — matching one is near-definitive.
 * Returns the full prior entropy (identifies the person in the population).
 */
export function emailInfoGain(populationSize: number): number {
  return Math.log(populationSize) / LN2
}

/**
 * Information gain from a tracking ID (GA, GTM, FB Pixel).
 * Near-unique — shared only by intentional cross-domain configuration.
 * Returns near-definitive identification value.
 */
export function trackingIdInfoGain(populationSize: number): number {
  // slightly less than email — could be shared across a company's domains
  return Math.max(0, Math.log(populationSize) / LN2 - 2)
}

/**
 * Information gain from an ASN.
 * Major CDN ASN: low gain. Small ISP: moderate gain.
 */
export function asnInfoGain(asn: number): number {
  if (CDN_ASNS.has(asn)) {
    // large CDN — millions of customers
    return 2.0
  }
  // smaller ISP — assume ~10K customers
  return selfInfo(10_000 / 8_000_000_000)
}
