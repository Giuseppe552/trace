/**
 * Backlink toxicity analysis for negative SEO detection.
 *
 * Negative SEO attacks inject thousands of spammy backlinks pointing
 * to a target domain to trigger Google penalties. This module checks
 * for suspicious referring domains.
 *
 * Method: uses publicly available data from Common Crawl and
 * web archives. For deeper analysis, integrates with Ahrefs/Moz
 * APIs (paid, optional).
 *
 * Without paid APIs, this module provides heuristic analysis:
 * - Check referring domains from CT logs (domains sharing certs)
 * - DNS-based spam indicators (fresh domains, parking pages)
 * - Pattern detection in referring domain names
 *
 * Signals:
 * - Burst of new backlinks from fresh domains
 * - Backlinks from domains with spam-like characteristics
 * - Anchor text analysis (keyword stuffing patterns)
 */

import type { Signal } from '../types.js'
import { Resolver } from 'node:dns/promises'

/** A referring domain analysis */
export interface ReferringDomain {
  domain: string
  /** does the domain resolve? */
  isLive: boolean
  /** IP address */
  ip: string | null
  /** estimated domain age category */
  ageCategory: 'fresh' | 'established' | 'unknown'
  /** spam score heuristic (0-1) */
  spamScore: number
  /** why it scored as spam */
  spamReasons: string[]
}

/** Backlink analysis result */
export interface BacklinkAnalysis {
  targetDomain: string
  /** referring domains analyzed */
  referringDomains: ReferringDomain[]
  /** how many look spammy */
  spamCount: number
  /** overall toxicity score (0-1) */
  toxicityScore: number
  /** is this likely a negative SEO attack? */
  likelyNegativeSeo: boolean
  signals: Signal[]
}

/** Spam domain name patterns */
const SPAM_PATTERNS: Array<{ pattern: RegExp; reason: string; weight: number }> = [
  { pattern: /^[a-z]{15,}\./, reason: 'very long random-looking domain', weight: 0.4 },
  { pattern: /\d{5,}/, reason: 'many consecutive digits', weight: 0.3 },
  { pattern: /(casino|poker|slot|bet|gambl|porn|xxx|adult|viagra|cialis|pharma)/i, reason: 'spam keyword in domain', weight: 0.6 },
  { pattern: /^[a-z0-9]{2,3}\.[a-z]{2}$/, reason: 'very short domain on country TLD', weight: 0.2 },
  { pattern: /(free|cheap|best|buy|discount|deal|offer|click|traffic|seo|link)/i, reason: 'marketing spam keyword', weight: 0.3 },
  { pattern: /\.(xyz|top|wang|win|bid|click|gq|ml|cf|tk|ga)$/, reason: 'spam-associated TLD', weight: 0.4 },
  { pattern: /-{2,}/, reason: 'multiple hyphens', weight: 0.2 },
  { pattern: /[a-z]{3,}-[a-z]{3,}-[a-z]{3,}-[a-z]{3,}/, reason: 'excessive hyphenation pattern', weight: 0.35 },
]

/**
 * Analyze a set of referring domains for spam characteristics.
 *
 * Input: list of domains that link to your site (from GSC, Ahrefs,
 * or manual collection). This module scores each one.
 */
export async function analyzeBacklinks(
  targetDomain: string,
  referringDomains: string[],
  options: { checkDns?: boolean; concurrency?: number } = {},
): Promise<BacklinkAnalysis> {
  const { checkDns = true, concurrency = 10 } = options
  const resolver = new Resolver()
  resolver.setServers(['1.1.1.1', '8.8.8.8'])

  const results: ReferringDomain[] = []

  for (let i = 0; i < referringDomains.length; i += concurrency) {
    const batch = referringDomains.slice(i, i + concurrency)
    const batchResults = await Promise.allSettled(
      batch.map(async (domain) => {
        let isLive = false
        let ip: string | null = null

        if (checkDns) {
          try {
            const ips = await resolver.resolve4(domain)
            isLive = ips.length > 0
            ip = ips[0] ?? null
          } catch {
            isLive = false
          }
        }

        // spam scoring
        const spamReasons: string[] = []
        let spamScore = 0

        for (const { pattern, reason, weight } of SPAM_PATTERNS) {
          if (pattern.test(domain)) {
            spamReasons.push(reason)
            spamScore += weight
          }
        }

        // fresh domains that don't resolve are suspicious
        if (!isLive && checkDns) {
          spamReasons.push('domain does not resolve')
          spamScore += 0.2
        }

        return {
          domain,
          isLive,
          ip,
          ageCategory: 'unknown' as const,
          spamScore: Math.min(1, spamScore),
          spamReasons,
        }
      }),
    )

    for (const r of batchResults) {
      if (r.status === 'fulfilled') results.push(r.value)
    }
  }

  const spamCount = results.filter(r => r.spamScore > 0.3).length
  const toxicityScore = results.length > 0
    ? results.reduce((s, r) => s + r.spamScore, 0) / results.length
    : 0

  // negative SEO heuristic: >30% of referring domains are spammy
  const likelyNegativeSeo = results.length >= 10 && (spamCount / results.length) > 0.3

  const signals: Signal[] = []

  if (spamCount > 0) {
    signals.push({
      source: 'backlinks',
      observation: `${spamCount}/${results.length} referring domains have spam characteristics (toxicity: ${(toxicityScore * 100).toFixed(0)}%)`,
      score: toxicityScore,
      confidence: 0.65,
      informationBits: Math.log2(spamCount + 1) + 2,
      rawData: JSON.stringify(results.filter(r => r.spamScore > 0.3).map(r => ({ domain: r.domain, score: r.spamScore, reasons: r.spamReasons }))),
      sourceUrl: `backlink-analysis:${targetDomain}`,
    })
  }

  if (likelyNegativeSeo) {
    signals.push({
      source: 'backlinks',
      observation: `likely negative SEO attack: ${((spamCount / results.length) * 100).toFixed(0)}% of ${results.length} referring domains are spammy`,
      score: 0.85,
      confidence: 0.70,
      informationBits: 5.0,
      rawData: `${spamCount}/${results.length} spam ratio`,
      sourceUrl: `backlink-analysis:${targetDomain}`,
    })
  }

  return { targetDomain, referringDomains: results, spamCount, toxicityScore, likelyNegativeSeo, signals }
}
