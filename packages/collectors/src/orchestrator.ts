/**
 * Investigation orchestrator.
 *
 * Two modes:
 * 1. Single domain investigation (basic)
 * 2. Deep investigation (chains through reverse WHOIS, correlates all domains)
 *
 * Deep investigation flow:
 *   target domain
 *   → DNS + CT + headers + WHOIS
 *   → extract registrant email/name
 *   → reverse WHOIS → find all domains by this registrant
 *   → DNS + CT + headers on each related domain
 *   → cross-domain correlation
 *   → IP geolocation on all IPs
 *   → build attribution graph
 *   → fuse all evidence
 *   → generate report
 */

import {
  computeAnonymity,
  fuseEvidence,
  createMass,
  LAYER_RELIABILITY,
  POPULATION,
  createChain,
  appendEvidence,
  verifyChain,
  exportReport,
  buildGraphFromSignals,
  toDot,
  toD3Json,
  type EvidenceItem,
  type AnonymityAssessment,
  type FusedAttribution,
  type EvidenceChain,
  type AttributionGraph,
} from '@trace/core'

import type { Signal, CollectorResult } from './types.js'
import { collectDns } from './dns/resolver.js'
import { collectCT } from './ct/crtsh.js'
import { collectHeaders } from './headers/fingerprint.js'
import { collectWhois } from './whois/lookup.js'
import { reverseWhoisFreaks, reverseWhoisViewDns } from './whois/reverse.js'
import { whoisHistory } from './whois/history.js'
import { parseEmailHeaders, collectEmailSignals } from './email/headers.js'
import { lookupIp, correlateIps } from './ip/geolocation.js'
import { correlateDomains, type DomainSignals } from './correlation/cross-domain.js'

/** Investigation target specification */
export interface InvestigationTarget {
  /** primary domain to investigate */
  domain?: string
  /** additional domains to cross-reference */
  relatedDomains?: string[]
  /** email headers to analyze (raw text) */
  emailHeaders?: string
  /** suspect population for anonymity computation */
  population?: number
  /** investigation label */
  label: string
  /** run deep investigation (reverse WHOIS, correlate, IP geo) */
  deep?: boolean
  /** WhoisFreaks API key for reverse/history lookups */
  whoisApiKey?: string
}

/** Full investigation result */
export interface InvestigationResult {
  label: string
  startedAt: string
  completedAt: string
  signals: Signal[]
  anonymity: AnonymityAssessment
  attribution: FusedAttribution
  chain: EvidenceChain
  chainIntegrity: { intact: boolean; brokenAt: number; totalEntries: number }
  graph: AttributionGraph
  graphDot: string
  collectors: {
    dns?: { recordCount: number; warnings: string[] }
    ct?: { certCount: number; subdomains: number; relatedDomains: number; warnings: string[] }
    headers?: { platform: string | null; trackingIds: number; warnings: string[] }
    whois?: { registrant: string | null; privacyProtected: boolean; warnings: string[] }
    email?: { originatingIp: string | null; anomalies: number; warnings: string[] }
    reverseWhois?: { domainsFound: number; warnings: string[] }
    whoisHistory?: { snapshots: number; hasUnredacted: boolean; warnings: string[] }
    ipGeo?: { ipsLookedUp: number; warnings: string[] }
    correlation?: { correlationsFound: number; clusters: number }
  }
  /** domains discovered during deep investigation */
  discoveredDomains: string[]
}

/**
 * Run a full investigation against a target.
 */
export async function investigate(target: InvestigationTarget): Promise<InvestigationResult> {
  const startedAt = new Date().toISOString()
  const chain = createChain(target.label, 'trace-cli')
  const allSignals: Signal[] = []
  const collectors: InvestigationResult['collectors'] = {}
  const discoveredDomains: string[] = []

  // ── Phase 1: primary domain collection ──────────────────────

  if (target.domain) {
    const [dnsResult, ctResult, headersResult, whoisResult] = await Promise.allSettled([
      collectDns(target.domain),
      collectCT(target.domain),
      collectHeaders(target.domain),
      collectWhois(target.domain),
    ])

    if (dnsResult.status === 'fulfilled') {
      const r = dnsResult.value
      allSignals.push(...r.signals)
      collectors.dns = {
        recordCount: r.data.a.length + r.data.mx.length + r.data.txt.length + r.data.ns.length,
        warnings: r.warnings,
      }
      await appendEvidence(chain, {
        content: r.raw,
        type: 'dns_record',
        source: r.url,
        description: `DNS records for ${target.domain}`,
        layer: 'dns',
      })
    }

    if (ctResult.status === 'fulfilled') {
      const r = ctResult.value
      allSignals.push(...r.signals)
      collectors.ct = {
        certCount: r.data.certificates.length,
        subdomains: r.data.subdomains.length,
        relatedDomains: r.data.relatedDomains.length,
        warnings: r.warnings,
      }
      await appendEvidence(chain, {
        content: r.raw,
        type: 'certificate',
        source: r.url,
        description: `CT logs for ${target.domain}: ${r.data.certificates.length} certs, ${r.data.subdomains.length} subdomains`,
        layer: 'ct',
      })
      // add related domains from CT to discovered list
      discoveredDomains.push(...r.data.relatedDomains)
    }

    if (headersResult.status === 'fulfilled') {
      const r = headersResult.value
      allSignals.push(...r.signals)
      collectors.headers = {
        platform: r.data.platform,
        trackingIds: r.data.trackingIds.length,
        warnings: r.warnings,
      }
      await appendEvidence(chain, {
        content: r.raw,
        type: 'http_headers',
        source: r.url,
        description: `HTTP headers for ${target.domain}: platform=${r.data.platform}`,
        layer: 'headers',
      })
    }

    if (whoisResult.status === 'fulfilled') {
      const r = whoisResult.value
      allSignals.push(...r.signals)
      collectors.whois = {
        registrant: r.data.registrantName ?? r.data.registrantOrg ?? null,
        privacyProtected: r.data.isPrivacyProtected,
        warnings: r.warnings,
      }
      await appendEvidence(chain, {
        content: r.raw,
        type: 'whois_record',
        source: r.url,
        description: `WHOIS for ${target.domain}: registrant=${r.data.registrantName ?? 'redacted'}`,
        layer: 'whois',
      })

      // ── Phase 2: deep investigation ──────────────────────────
      if (target.deep) {
        // reverse WHOIS if we found a registrant email
        if (r.data.registrantEmail && !r.data.isPrivacyProtected) {
          const reverseResult = await reverseWhoisFreaks(
            r.data.registrantEmail,
            'email',
            { apiKey: target.whoisApiKey },
          )

          if (reverseResult.data.domains.length === 0 && reverseResult.warnings.some(w => w.includes('API_KEY'))) {
            // fallback to ViewDNS
            const fallback = await reverseWhoisViewDns(r.data.registrantEmail)
            reverseResult.data.domains = fallback.data.domains
            reverseResult.data.totalCount = fallback.data.totalCount
          }

          allSignals.push(...reverseResult.signals)
          collectors.reverseWhois = {
            domainsFound: reverseResult.data.totalCount,
            warnings: reverseResult.warnings,
          }

          if (reverseResult.data.domains.length > 0) {
            await appendEvidence(chain, {
              content: JSON.stringify(reverseResult.data),
              type: 'api_response',
              source: reverseResult.url,
              description: `Reverse WHOIS for ${r.data.registrantEmail}: ${reverseResult.data.totalCount} domains`,
              layer: 'whois_reverse',
            })
            discoveredDomains.push(...reverseResult.data.domains.map(d => d.domain))
          }
        }

        // WHOIS history
        const historyResult = await whoisHistory(target.domain, { apiKey: target.whoisApiKey })
        allSignals.push(...historyResult.signals)
        collectors.whoisHistory = {
          snapshots: historyResult.data.snapshots.length,
          hasUnredacted: historyResult.data.hasUnredactedRecords,
          warnings: historyResult.warnings,
        }
        if (historyResult.data.snapshots.length > 0) {
          await appendEvidence(chain, {
            content: JSON.stringify(historyResult.data),
            type: 'whois_record',
            source: historyResult.url,
            description: `WHOIS history for ${target.domain}: ${historyResult.data.snapshots.length} snapshots, unredacted=${historyResult.data.hasUnredactedRecords}`,
            layer: 'whois_historical',
          })

          // if history reveals a registrant email we didn't have, reverse that too
          if (historyResult.data.hasUnredactedRecords && r.data.isPrivacyProtected) {
            const histEmail = historyResult.data.distinctRegistrants[0]?.email
            if (histEmail) {
              const reverseHist = await reverseWhoisFreaks(histEmail, 'email', { apiKey: target.whoisApiKey })
              allSignals.push(...reverseHist.signals)
              discoveredDomains.push(...reverseHist.data.domains.map(d => d.domain))
              if (reverseHist.data.domains.length > 0) {
                await appendEvidence(chain, {
                  content: JSON.stringify(reverseHist.data),
                  type: 'api_response',
                  source: reverseHist.url,
                  description: `Reverse WHOIS for historical registrant ${histEmail}: ${reverseHist.data.totalCount} domains`,
                  layer: 'whois_reverse',
                })
              }
            }
          }
        }

        // IP geolocation on all A record IPs
        if (dnsResult.status === 'fulfilled' && dnsResult.value.data.a.length > 0) {
          const ipResults = await correlateIps(dnsResult.value.data.a)
          const allIpSignals = ipResults.results.flatMap(r => r.signals)
          allSignals.push(...allIpSignals)
          collectors.ipGeo = {
            ipsLookedUp: ipResults.results.length,
            warnings: ipResults.results.flatMap(r => r.warnings),
          }

          for (const ipResult of ipResults.results) {
            await appendEvidence(chain, {
              content: ipResult.raw,
              type: 'api_response',
              source: ipResult.url,
              description: `IP geolocation for ${ipResult.data.ip}: ${ipResult.data.city}, ${ipResult.data.country} (AS${ipResult.data.asn})`,
              layer: 'ip_geo',
            })
          }

          // add correlation signals
          for (const corr of ipResults.correlations) {
            allSignals.push({
              source: 'ip_correlation',
              observation: `IPs ${corr.ips.join(', ')} share ${corr.sharedAttribute}: ${corr.value}`,
              score: 0.5,
              confidence: 0.8,
              informationBits: 2.0,
              rawData: JSON.stringify(corr),
              sourceUrl: 'ip-correlation',
            })
          }
        }
      }
    }
  }

  // ── Phase 3: related domain collection + correlation ─────────

  const allDomains = [...new Set([
    ...(target.relatedDomains ?? []),
    ...discoveredDomains,
  ])].filter(d => d && d !== target.domain)

  if (allDomains.length > 0 && target.deep) {
    // collect signals from related domains (limit to 10 to avoid rate limits)
    const domainsToCheck = allDomains.slice(0, 10)
    const domainSignalSets: DomainSignals[] = []

    // add primary domain signals
    if (target.domain) {
      const primaryDns = await collectDns(target.domain).catch(() => null)
      const primaryHeaders = await collectHeaders(target.domain).catch(() => null)
      domainSignalSets.push({
        domain: target.domain,
        ips: primaryDns?.data.a ?? [],
        nameservers: primaryDns?.data.ns ?? [],
        mxRecords: primaryDns?.data.mx.map(m => m.exchange) ?? [],
        registrant: collectors.whois?.registrant ?? null,
        registrar: null,
        trackingIds: primaryHeaders?.data.trackingIds ?? [],
        platform: primaryHeaders?.data.platform ?? null,
        subdomains: [],
        relatedDomains: [],
        verificationTokens: primaryDns?.data.verificationTokens ?? [],
      })
    }

    for (const rd of domainsToCheck) {
      try {
        const [rdDns, rdHeaders] = await Promise.allSettled([
          collectDns(rd),
          collectHeaders(rd),
        ])

        const ds: DomainSignals = {
          domain: rd,
          ips: rdDns.status === 'fulfilled' ? rdDns.value.data.a : [],
          nameservers: rdDns.status === 'fulfilled' ? rdDns.value.data.ns : [],
          mxRecords: rdDns.status === 'fulfilled' ? rdDns.value.data.mx.map(m => m.exchange) : [],
          registrant: null,
          registrar: null,
          trackingIds: rdHeaders.status === 'fulfilled' ? rdHeaders.value.data.trackingIds : [],
          platform: rdHeaders.status === 'fulfilled' ? rdHeaders.value.data.platform : null,
          subdomains: [],
          relatedDomains: [],
          verificationTokens: rdDns.status === 'fulfilled' ? rdDns.value.data.verificationTokens : [],
        }
        domainSignalSets.push(ds)

        if (rdDns.status === 'fulfilled') {
          await appendEvidence(chain, {
            content: rdDns.value.raw,
            type: 'dns_record',
            source: rdDns.value.url,
            description: `DNS records for related domain ${rd}`,
            layer: 'dns',
          })
        }
      } catch { /* non-fatal */ }
    }

    // cross-domain correlation
    if (domainSignalSets.length >= 2) {
      const corrResult = correlateDomains(domainSignalSets)
      allSignals.push(...corrResult.signals)
      collectors.correlation = {
        correlationsFound: corrResult.correlations.length,
        clusters: corrResult.clusterSizes.length,
      }

      if (corrResult.correlations.length > 0) {
        await appendEvidence(chain, {
          content: JSON.stringify(corrResult),
          type: 'api_response',
          source: 'cross-domain-correlation',
          description: `Cross-domain correlation: ${corrResult.correlations.length} shared attributes across ${domainSignalSets.length} domains`,
          layer: 'correlation',
        })
      }
    }
  }

  // ── Phase 4: email header analysis ───────────────────────────

  if (target.emailHeaders) {
    const parsed = parseEmailHeaders(target.emailHeaders)
    const r = collectEmailSignals(parsed)
    allSignals.push(...r.signals)
    collectors.email = {
      originatingIp: parsed.originatingIp,
      anomalies: parsed.timestampAnomalies.length,
      warnings: r.warnings,
    }
    await appendEvidence(chain, {
      content: target.emailHeaders,
      type: 'email_headers',
      source: 'email-header-analysis',
      description: `Email header analysis: originating IP=${parsed.originatingIp ?? 'unknown'}`,
      layer: 'email',
    })

    // if we got an IP from the email, geolocate it
    if (parsed.originatingIp && target.deep) {
      const ipResult = await lookupIp(parsed.originatingIp)
      allSignals.push(...ipResult.signals)
      await appendEvidence(chain, {
        content: ipResult.raw,
        type: 'api_response',
        source: ipResult.url,
        description: `IP geo for email origin ${parsed.originatingIp}: ${ipResult.data.city}, ${ipResult.data.country}`,
        layer: 'ip_geo',
      })
    }
  }

  // ── Phase 5: compute results ─────────────────────────────────

  const population = target.population ?? POPULATION.uk
  const evidenceItems: EvidenceItem[] = allSignals.map(s => ({
    source: s.source,
    observation: s.observation,
    informationGain: s.informationBits,
    confidence: s.confidence,
  }))
  const anonymity = computeAnonymity(population, evidenceItems)

  const masses = allSignals.map(s =>
    createMass(s.score, LAYER_RELIABILITY[s.source] ?? 0.5, s.source),
  )
  const attribution = fuseEvidence(masses)

  const chainIntegrity = await verifyChain(chain)

  // build graph
  const graph = buildGraphFromSignals(
    target.domain ?? target.label,
    allSignals.map(s => ({ source: s.source, observation: s.observation, rawData: s.rawData })),
  )
  const graphDot = toDot(graph, { title: `trace: ${target.label}` })

  return {
    label: target.label,
    startedAt,
    completedAt: new Date().toISOString(),
    signals: allSignals,
    anonymity,
    attribution,
    chain,
    chainIntegrity,
    graph,
    graphDot,
    collectors,
    discoveredDomains: [...new Set(discoveredDomains)],
  }
}

/**
 * Export investigation as a forensic report (JSON).
 */
export function exportInvestigation(result: InvestigationResult): string {
  return JSON.stringify({
    _format: 'trace-investigation-v1',
    label: result.label,
    period: { started: result.startedAt, completed: result.completedAt },
    summary: {
      signalCount: result.signals.length,
      attribution: {
        belief: result.attribution.belief,
        plausibility: result.attribution.plausibility,
        conflict: result.attribution.conflict,
        level: result.attribution.level,
      },
      anonymity: {
        priorBits: result.anonymity.priorBits,
        remainingBits: result.anonymity.remainingBits,
        anonymitySet: Math.round(result.anonymity.anonymitySet),
        identified: result.anonymity.identified,
      },
      evidenceChain: {
        entries: result.chainIntegrity.totalEntries,
        intact: result.chainIntegrity.intact,
      },
      discoveredDomains: result.discoveredDomains.length,
    },
    signals: result.signals,
    collectors: result.collectors,
    discoveredDomains: result.discoveredDomains,
    graph: {
      nodes: result.graph.nodes.length,
      edges: result.graph.edges.length,
    },
    evidenceChain: exportReport(result.chain),
  }, null, 2)
}
