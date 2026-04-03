#!/usr/bin/env tsx
/**
 * trace CLI — attribution investigation tool
 *
 * Usage:
 *   trace domain <domain> [--related <domain2,domain3>] [--population <n>]
 *   trace email <path-to-headers.txt>
 *   trace compare <file1.txt> <file2.txt>    (stylometry comparison)
 *   trace timing <timestamps.json>            (coordination detection)
 *   trace ip <address>                        (geolocation + ASN lookup)
 *   trace correlate <domain1> <domain2> ...   (cross-domain correlation)
 *
 * All output goes to stdout as structured JSON.
 * Evidence chain is saved to ./trace-evidence-<label>.json
 */

import { writeFile } from 'node:fs/promises'
import { readFile } from 'node:fs/promises'

import {
  investigate,
  exportInvestigation,
  parseEmailHeaders,
  collectEmailSignals,
  generateReport,
  lookupIp,
  collectDns,
  collectCT,
  collectHeaders,
  collectWhois,
  correlateDomains,
  reverseWhoisFreaks,
  reverseWhoisViewDns,
  whoisHistory,
  analyzeReviews,
  type DomainSignals,
  type GoogleReview,
} from '@trace/collectors'

import {
  compareWriteprints,
  detectCoordination,
  POPULATION,
  toDot,
  toD3Json,
  buildGraphFromSignals,
} from '@trace/core'

const args = process.argv.slice(2)
const command = args[0]

function usage() {
  console.error(`
trace — attribution investigation tool

Commands:
  trace domain <domain>              Investigate a domain (DNS, CT, WHOIS, headers)
    --related <d1,d2>                Cross-reference related domains
    --population <n>                 Suspect population size (default: UK 67M)
    --label <name>                   Investigation label

  trace email <headers.txt>          Analyze email headers from file

  trace compare <file1> <file2>      Compare writing styles (stylometry)

  trace timing <timestamps.json>     Detect coordinated behavior from timestamps
                                     (JSON array of Unix ms timestamps)

  trace help                         Show this message
`)
  process.exit(1)
}

async function main() {
  if (!command || command === 'help' || command === '--help') {
    usage()
  }

  if (command === 'domain') {
    const domain = args[1]
    if (!domain) { console.error('error: domain required'); process.exit(1) }

    const relatedIdx = args.indexOf('--related')
    const related = relatedIdx >= 0 ? args[relatedIdx + 1]?.split(',') : undefined

    const popIdx = args.indexOf('--population')
    const population = popIdx >= 0 ? parseInt(args[popIdx + 1], 10) : POPULATION.uk

    const labelIdx = args.indexOf('--label')
    const label = labelIdx >= 0 ? args[labelIdx + 1] : `investigation-${domain}`

    const deep = args.includes('--deep')

    console.error(`[trace] investigating ${domain}${deep ? ' (deep mode)' : ''}...`)

    const result = await investigate({
      domain,
      relatedDomains: related,
      population,
      label,
      deep,
    })

    // summary to stderr
    console.error(`[trace] ${result.signals.length} signals collected`)
    console.error(`[trace] anonymity: ${result.anonymity.remainingBits.toFixed(1)} bits remaining (set size: ${Math.round(result.anonymity.anonymitySet)})`)
    console.error(`[trace] attribution: belief=${result.attribution.belief.toFixed(3)}, level=${result.attribution.level}, conflict=${result.attribution.conflict.toFixed(3)}`)
    console.error(`[trace] evidence chain: ${result.chainIntegrity.totalEntries} entries, integrity=${result.chainIntegrity.intact ? 'INTACT' : 'BROKEN'}`)

    // collectors summary
    if (result.collectors.dns) {
      console.error(`[trace]   dns: ${result.collectors.dns.recordCount} records`)
    }
    if (result.collectors.ct) {
      console.error(`[trace]   ct: ${result.collectors.ct.certCount} certs, ${result.collectors.ct.subdomains} subdomains, ${result.collectors.ct.relatedDomains} related domains`)
    }
    if (result.collectors.headers) {
      console.error(`[trace]   headers: platform=${result.collectors.headers.platform}, ${result.collectors.headers.trackingIds} tracking IDs`)
    }
    if (result.collectors.whois) {
      console.error(`[trace]   whois: registrant=${result.collectors.whois.registrant ?? 'redacted'}, privacy=${result.collectors.whois.privacyProtected}`)
    }
    if (result.collectors.reverseWhois) {
      console.error(`[trace]   reverse whois: ${result.collectors.reverseWhois.domainsFound} domains by same registrant`)
    }
    if (result.collectors.whoisHistory) {
      console.error(`[trace]   whois history: ${result.collectors.whoisHistory.snapshots} snapshots, unredacted=${result.collectors.whoisHistory.hasUnredacted}`)
    }
    if (result.collectors.ipGeo) {
      console.error(`[trace]   ip geo: ${result.collectors.ipGeo.ipsLookedUp} IPs geolocated`)
    }
    if (result.collectors.correlation) {
      console.error(`[trace]   correlation: ${result.collectors.correlation.correlationsFound} shared attributes, ${result.collectors.correlation.clusters} clusters`)
    }
    if (result.discoveredDomains.length > 0) {
      console.error(`[trace]   discovered: ${result.discoveredDomains.length} related domains`)
    }
    console.error(`[trace] graph: ${result.graph.nodes.length} nodes, ${result.graph.edges.length} edges`)

    // save JSON report
    const jsonReport = exportInvestigation(result)
    const jsonFile = `trace-evidence-${label}.json`
    await writeFile(jsonFile, jsonReport)
    console.error(`[trace] evidence saved to ${jsonFile}`)

    // generate and save human-readable report
    const narrative = generateReport(result)
    const mdFile = `trace-report-${label}.md`
    await writeFile(mdFile, narrative)
    console.error(`[trace] report saved to ${mdFile}`)

    // save graph
    const dotFile = `trace-graph-${label}.dot`
    await writeFile(dotFile, result.graphDot)
    console.error(`[trace] graph saved to ${dotFile}`)

    // output JSON to stdout
    console.log(jsonReport)
  }

  else if (command === 'email') {
    const file = args[1]
    if (!file) { console.error('error: headers file path required'); process.exit(1) }

    const raw = await readFile(file, 'utf-8')
    const analysis = parseEmailHeaders(raw)
    const result = collectEmailSignals(analysis)

    console.log(JSON.stringify({
      originatingIp: analysis.originatingIp,
      from: analysis.from,
      returnPath: analysis.returnPath,
      messageIdDomain: analysis.messageIdDomain,
      spf: analysis.spf,
      dkim: analysis.dkim,
      dmarc: analysis.dmarc,
      mailer: analysis.mailer,
      hops: analysis.receivedChain.length,
      timestampAnomalies: analysis.timestampAnomalies,
      signals: result.signals,
    }, null, 2))
  }

  else if (command === 'compare') {
    const fileA = args[1]
    const fileB = args[2]
    if (!fileA || !fileB) { console.error('error: two file paths required'); process.exit(1) }

    const textA = await readFile(fileA, 'utf-8')
    const textB = await readFile(fileB, 'utf-8')

    const result = compareWriteprints(textA, textB)

    console.log(JSON.stringify({
      similarity: result.similarity,
      scalarSimilarity: result.scalarSimilarity,
      bigramSimilarity: result.bigramSimilarity,
      wordCountA: result.featuresA.wordCount,
      wordCountB: result.featuresB.wordCount,
      avgWordLengthA: result.featuresA.avgWordLength.toFixed(2),
      avgWordLengthB: result.featuresB.avgWordLength.toFixed(2),
      vocabularyRichnessA: result.featuresA.vocabularyRichness.toFixed(3),
      vocabularyRichnessB: result.featuresB.vocabularyRichness.toFixed(3),
      yulesKA: result.featuresA.yulesK.toFixed(1),
      yulesKB: result.featuresB.yulesK.toFixed(1),
    }, null, 2))
  }

  else if (command === 'timing') {
    const file = args[1]
    if (!file) { console.error('error: timestamps JSON file required'); process.exit(1) }

    const raw = await readFile(file, 'utf-8')
    const timestamps: number[] = JSON.parse(raw)

    const result = detectCoordination(timestamps)

    console.log(JSON.stringify({
      eventCount: result.eventCount,
      likelyCoordinated: result.likelyCoordinated,
      confidence: result.confidence,
      reason: result.reason,
      meanIntervalMs: Math.round(result.meanInterval),
      coefficientOfVariation: result.cv.toFixed(3),
      ksTest: {
        D: result.ksExponential.D.toFixed(4),
        pValue: result.ksExponential.pValue.toFixed(6),
      },
    }, null, 2))
  }

  else if (command === 'reviews') {
    const file = args[1]
    if (!file) {
      console.error('error: reviews JSON file required')
      console.error('format: { "business": "Name", "reviews": [{ "authorName": "...", "rating": 5, "text": "...", "timestamp": 1234567890000 }] }')
      process.exit(1)
    }

    const raw = await readFile(file, 'utf-8')
    const input = JSON.parse(raw) as { business: string; reviews: GoogleReview[]; placeId?: string }

    console.error(`[trace] analyzing ${input.reviews.length} reviews for "${input.business}"...`)

    const result = analyzeReviews(input.business, input.reviews, input.placeId)

    console.error(`[trace] ${result.data.suspiciousReviews.length} suspicious reviews flagged`)
    console.error(`[trace] ${result.data.timingAnalysis.burstGroups.length} burst group(s) detected`)

    for (const sr of result.data.suspiciousReviews) {
      console.error(`[trace]   [${sr.suspicionScore.toFixed(2)}] "${sr.review.authorName}": ${sr.flags.join(', ')}`)
    }

    // compare suspicious reviews against each other for stylometry
    if (result.data.suspiciousReviews.length >= 2) {
      console.error('[trace] comparing suspicious review writing styles...')
      const suspicious = result.data.suspiciousReviews.filter(r => r.review.text.length > 50)
      for (let i = 0; i < suspicious.length; i++) {
        for (let j = i + 1; j < suspicious.length; j++) {
          const cmp = compareWriteprints(suspicious[i].review.text, suspicious[j].review.text)
          if (cmp.similarity > 0.7) {
            console.error(`[trace]   MATCH: "${suspicious[i].review.authorName}" ↔ "${suspicious[j].review.authorName}" similarity=${cmp.similarity.toFixed(3)}`)
          }
        }
      }
    }

    console.log(JSON.stringify({
      business: result.data.businessName,
      totalReviews: result.data.reviews.length,
      suspiciousCount: result.data.suspiciousReviews.length,
      suspiciousReviews: result.data.suspiciousReviews.map(sr => ({
        author: sr.review.authorName,
        rating: sr.review.rating,
        text: sr.review.text.slice(0, 200),
        flags: sr.flags,
        score: sr.suspicionScore,
      })),
      burstGroups: result.data.timingAnalysis.burstGroups.map(bg => ({
        count: bg.reviews.length,
        authors: bg.reviews.map(r => r.authorName),
        windowHours: bg.windowHours,
      })),
      signals: result.signals,
    }, null, 2))
  }

  else if (command === 'correlate') {
    const domains = args.slice(1).filter(a => !a.startsWith('--'))
    if (domains.length < 2) { console.error('error: need at least 2 domains'); process.exit(1) }

    console.error(`[trace] correlating ${domains.length} domains...`)

    const allSignals: DomainSignals[] = []
    for (const domain of domains) {
      console.error(`[trace]   collecting ${domain}...`)
      const [dns, ct, headers, whois] = await Promise.allSettled([
        collectDns(domain),
        collectCT(domain),
        collectHeaders(domain),
        collectWhois(domain),
      ])

      const ds: DomainSignals = {
        domain,
        ips: dns.status === 'fulfilled' ? dns.value.data.a : [],
        nameservers: dns.status === 'fulfilled' ? dns.value.data.ns : [],
        mxRecords: dns.status === 'fulfilled' ? dns.value.data.mx.map(m => m.exchange) : [],
        registrant: whois.status === 'fulfilled' ? (whois.value.data.registrantName ?? whois.value.data.registrantOrg ?? null) : null,
        registrar: whois.status === 'fulfilled' ? whois.value.data.registrar : null,
        trackingIds: headers.status === 'fulfilled' ? headers.value.data.trackingIds : [],
        platform: headers.status === 'fulfilled' ? headers.value.data.platform : null,
        subdomains: ct.status === 'fulfilled' ? ct.value.data.subdomains : [],
        relatedDomains: ct.status === 'fulfilled' ? ct.value.data.relatedDomains : [],
        verificationTokens: dns.status === 'fulfilled' ? dns.value.data.verificationTokens : [],
      }
      allSignals.push(ds)
    }

    const result = correlateDomains(allSignals)

    console.error(`[trace] ${result.correlations.length} correlations found`)
    for (const cluster of result.clusterSizes) {
      console.error(`[trace]   cluster: ${cluster.domains.join(', ')} (shared: ${cluster.sharedAttributes.join(', ')})`)
    }

    console.log(JSON.stringify(result, null, 2))
  }

  else if (command === 'graph') {
    // build graph from a previous investigation JSON
    const file = args[1]
    if (!file) { console.error('error: investigation JSON file required'); process.exit(1) }

    const raw = await readFile(file, 'utf-8')
    const investigation = JSON.parse(raw)
    const signals = investigation.signals ?? []
    const label = investigation.label ?? 'unknown'

    // extract target domain from label or first signal
    const targetDomain = label.replace('investigation-', '')

    const graph = buildGraphFromSignals(targetDomain, signals)

    const format = args.includes('--json') ? 'json' : 'dot'
    if (format === 'json') {
      console.log(toD3Json(graph))
    } else {
      console.log(toDot(graph, { title: `trace: ${label}` }))
    }
  }

  else if (command === 'reverse') {
    const query = args[1]
    if (!query) { console.error('error: search query required (email, name, or org)'); process.exit(1) }

    const typeArg = args.indexOf('--type')
    const queryType = (typeArg >= 0 ? args[typeArg + 1] : 'email') as 'email' | 'name' | 'organization' | 'phone'

    console.error(`[trace] reverse WHOIS: ${queryType}="${query}"`)

    // try WhoisFreaks first, fall back to ViewDNS
    let result = await reverseWhoisFreaks(query, queryType)
    if (result.data.domains.length === 0 && result.warnings.some(w => w.includes('API_KEY'))) {
      console.error('[trace]   no API key, falling back to ViewDNS...')
      result = await reverseWhoisViewDns(query)
    }

    console.error(`[trace] ${result.data.totalCount} domain(s) found`)
    console.log(JSON.stringify(result.data, null, 2))
  }

  else if (command === 'history') {
    const domain = args[1]
    if (!domain) { console.error('error: domain required'); process.exit(1) }

    console.error(`[trace] fetching WHOIS history for ${domain}...`)
    const result = await whoisHistory(domain)

    console.error(`[trace] ${result.data.snapshots.length} historical records`)
    if (result.data.hasUnredactedRecords) {
      console.error(`[trace]   unredacted registrant found in historical records`)
      for (const r of result.data.distinctRegistrants) {
        console.error(`[trace]     ${r.name ?? r.email ?? r.org} (first seen: ${r.firstSeen})`)
      }
    }

    console.log(JSON.stringify(result.data, null, 2))
  }

  else if (command === 'ip') {
    const ip = args[1]
    if (!ip) { console.error('error: IP address required'); process.exit(1) }

    const result = await lookupIp(ip)
    console.log(JSON.stringify({
      ip: result.data.ip,
      country: result.data.country,
      countryCode: result.data.countryCode,
      city: result.data.city,
      region: result.data.region,
      isp: result.data.isp,
      org: result.data.org,
      asn: result.data.asn ? `AS${result.data.asn}` : null,
      asName: result.data.asName,
      isHosting: result.data.isHosting,
      isProxy: result.data.isProxy,
      timezone: result.data.timezone,
      coordinates: result.data.lat && result.data.lon ? { lat: result.data.lat, lon: result.data.lon } : null,
      signals: result.signals,
    }, null, 2))
  }

  else {
    console.error(`unknown command: ${command}`)
    usage()
  }
}

main().catch(err => {
  console.error(`[trace] fatal: ${err.message}`)
  process.exit(1)
})
