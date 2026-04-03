/**
 * Typosquatting and brand impersonation detection.
 *
 * Given a brand domain, generates likely typosquat variants and
 * checks which ones are registered. A registered typosquat targeting
 * your brand is either: parked for resale, phishing, or a competitor
 * trying to intercept your traffic.
 *
 * Techniques:
 * 1. Character substitution (resinaro → reslnaro, res1naro)
 * 2. Adjacent key typos (resinaro → resinaeo, resinarp)
 * 3. Character omission (resinaro → rsinaro, resinao)
 * 4. Character duplication (resinaro → ressinaro, resinarro)
 * 5. Character transposition (resinaro → reisnaro, resinrao)
 * 6. Homoglyph substitution (resinaro → rеsinaro using Cyrillic е)
 * 7. TLD variations (.com, .co.uk, .net, .org, .io)
 * 8. Hyphenation (resinaro → resin-aro, res-inaro)
 * 9. Common prefixes/suffixes (myresinaro, resinarouk, resinaro-app)
 *
 * Reference: Szurdi et al. (2014). "The Long 'Taile' of Typosquatting
 *   Domain Names." USENIX Security.
 */

import { Resolver } from 'node:dns/promises'
import type { Signal } from '../types.js'

/** A generated typosquat candidate */
export interface TyposquatCandidate {
  domain: string
  technique: string
  /** does this domain resolve to an IP? */
  isRegistered: boolean
  /** IP addresses if registered */
  ips: string[]
}

/** Result of typosquat scan */
export interface TyposquatResult {
  /** the brand domain being protected */
  brandDomain: string
  /** total candidates generated */
  totalCandidates: number
  /** candidates that are actually registered */
  registeredCount: number
  /** registered domains with details */
  registered: TyposquatCandidate[]
  /** attribution signals */
  signals: Signal[]
}

/** QWERTY keyboard adjacency map */
const ADJACENT_KEYS: Record<string, string[]> = {
  q: ['w', 'a'], w: ['q', 'e', 's', 'a'], e: ['w', 'r', 'd', 's'],
  r: ['e', 't', 'f', 'd'], t: ['r', 'y', 'g', 'f'], y: ['t', 'u', 'h', 'g'],
  u: ['y', 'i', 'j', 'h'], i: ['u', 'o', 'k', 'j'], o: ['i', 'p', 'l', 'k'],
  p: ['o', 'l'], a: ['q', 'w', 's', 'z'], s: ['a', 'w', 'e', 'd', 'z', 'x'],
  d: ['s', 'e', 'r', 'f', 'x', 'c'], f: ['d', 'r', 't', 'g', 'c', 'v'],
  g: ['f', 't', 'y', 'h', 'v', 'b'], h: ['g', 'y', 'u', 'j', 'b', 'n'],
  j: ['h', 'u', 'i', 'k', 'n', 'm'], k: ['j', 'i', 'o', 'l', 'm'],
  l: ['k', 'o', 'p'], z: ['a', 's', 'x'], x: ['z', 's', 'd', 'c'],
  c: ['x', 'd', 'f', 'v'], v: ['c', 'f', 'g', 'b'], b: ['v', 'g', 'h', 'n'],
  n: ['b', 'h', 'j', 'm'], m: ['n', 'j', 'k'],
}

/** Common homoglyphs (visually similar characters) */
const HOMOGLYPHS: Record<string, string[]> = {
  a: ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а'],  // last is Cyrillic
  e: ['è', 'é', 'ê', 'ë', 'ē', 'е'],
  i: ['ì', 'í', 'î', 'ï', 'ı', '1', 'l'],
  o: ['ò', 'ó', 'ô', 'õ', 'ö', 'ø', '0', 'о'],
  l: ['1', 'i', 'ı', 'ℓ'],
  s: ['5', '$'],
  n: ['ñ', 'η'],
  r: ['г'],
  u: ['ù', 'ú', 'û', 'ü', 'µ'],
  c: ['ç', 'с'],
}

const COMMON_TLDS = ['.com', '.co.uk', '.net', '.org', '.io', '.uk', '.us', '.ca', '.co']
const COMMON_PREFIXES = ['my', 'the', 'get', 'go', 'try']
const COMMON_SUFFIXES = ['uk', 'us', 'app', 'online', 'site', 'web', 'official', 'hq']

/**
 * Generate typosquat candidates for a domain.
 *
 * Returns unique candidate domains (deduplicated).
 */
export function generateCandidates(brandDomain: string): Array<{ domain: string; technique: string }> {
  // extract the name part (before the TLD)
  const parts = brandDomain.split('.')
  const name = parts[0]
  const tld = '.' + parts.slice(1).join('.')
  const candidates = new Map<string, string>()

  const add = (domain: string, technique: string) => {
    const clean = domain.toLowerCase()
    if (clean !== brandDomain.toLowerCase() && clean.length > 3) {
      candidates.set(clean, technique)
    }
  }

  // 1. character omission
  for (let i = 0; i < name.length; i++) {
    add(name.slice(0, i) + name.slice(i + 1) + tld, 'omission')
  }

  // 2. character duplication
  for (let i = 0; i < name.length; i++) {
    add(name.slice(0, i + 1) + name[i] + name.slice(i + 1) + tld, 'duplication')
  }

  // 3. character transposition
  for (let i = 0; i < name.length - 1; i++) {
    const swapped = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2)
    add(swapped + tld, 'transposition')
  }

  // 4. adjacent key substitution
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase()
    const adjacent = ADJACENT_KEYS[ch] ?? []
    for (const adj of adjacent) {
      add(name.slice(0, i) + adj + name.slice(i + 1) + tld, 'adjacent-key')
    }
  }

  // 5. homoglyph substitution (ASCII-safe only for DNS)
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase()
    const glyphs = HOMOGLYPHS[ch] ?? []
    for (const g of glyphs) {
      // only use ASCII-safe homoglyphs for DNS
      if (/^[a-z0-9]$/.test(g)) {
        add(name.slice(0, i) + g + name.slice(i + 1) + tld, 'homoglyph')
      }
    }
  }

  // 6. TLD variations
  for (const altTld of COMMON_TLDS) {
    if (altTld !== tld) {
      add(name + altTld, 'tld-variation')
    }
  }

  // 7. hyphenation
  for (let i = 1; i < name.length; i++) {
    add(name.slice(0, i) + '-' + name.slice(i) + tld, 'hyphenation')
  }

  // 8. common prefixes/suffixes
  for (const prefix of COMMON_PREFIXES) {
    add(prefix + name + tld, 'prefix')
  }
  for (const suffix of COMMON_SUFFIXES) {
    add(name + suffix + tld, 'suffix')
  }

  return [...candidates.entries()].map(([domain, technique]) => ({ domain, technique }))
}

/**
 * Check which typosquat candidates are actually registered.
 *
 * Uses DNS resolution — if a domain resolves to an IP, it's registered
 * (or at least has DNS records). Fast: pure DNS, no WHOIS needed.
 */
export async function checkTyposquats(
  brandDomain: string,
  options: { concurrency?: number; timeout?: number } = {},
): Promise<TyposquatResult> {
  const { concurrency = 10, timeout = 3000 } = options
  const candidates = generateCandidates(brandDomain)
  const registered: TyposquatCandidate[] = []
  const resolver = new Resolver()
  resolver.setServers(['1.1.1.1', '8.8.8.8'])

  // batch DNS lookups with concurrency limit
  for (let i = 0; i < candidates.length; i += concurrency) {
    const batch = candidates.slice(i, i + concurrency)
    const results = await Promise.allSettled(
      batch.map(async (c) => {
        const timer = setTimeout(() => {}, timeout)
        try {
          const ips = await resolver.resolve4(c.domain)
          clearTimeout(timer)
          return { ...c, isRegistered: true, ips }
        } catch {
          clearTimeout(timer)
          return { ...c, isRegistered: false, ips: [] as string[] }
        }
      }),
    )

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.isRegistered) {
        registered.push(result.value)
      }
    }
  }

  const signals: Signal[] = []

  if (registered.length > 0) {
    signals.push({
      source: 'typosquat',
      observation: `${registered.length} typosquat domain(s) registered for ${brandDomain}`,
      score: Math.min(0.9, registered.length * 0.15),
      confidence: 0.85,
      informationBits: Math.log2(registered.length + 1) + 3,
      rawData: registered.map(r => `${r.domain} (${r.technique}, ${r.ips.join(',')})`).join('; '),
      sourceUrl: `typosquat-scan:${brandDomain}`,
    })
  }

  return {
    brandDomain,
    totalCandidates: candidates.length,
    registeredCount: registered.length,
    registered,
    signals,
  }
}
