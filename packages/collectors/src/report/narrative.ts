/**
 * Forensic report generator.
 *
 * Produces a structured investigation report following the format
 * expected by UK courts for expert evidence submissions.
 *
 * Style: factual, terse, sourced. No adjectives. No emphasis.
 * Every claim references the data that supports it. Every method
 * references the paper or standard it implements. Reads like a
 * forensic accountant wrote it, not a marketing team.
 */

import type { InvestigationResult } from '../orchestrator.js'
import { generateLegalBasis, checkAcpoCompliance } from '@trace/core'

export function generateReport(result: InvestigationResult): string {
  const lines: string[] = []
  const { anonymity, attribution, signals, collectors, chain } = result

  // ── header ────────────────────────────────────────────────
  lines.push(`# ${result.label}`)
  lines.push('')
  lines.push('Investigation Report')
  lines.push('')
  lines.push(`| Field | Value |`)
  lines.push(`|-------|-------|`)
  lines.push(`| Period | ${fmtDate(result.startedAt)} to ${fmtDate(result.completedAt)} |`)
  lines.push(`| Analyst | ${chain.analyst} |`)
  lines.push(`| Methodology | Berkeley Protocol on Digital Open Source Investigations (OHCHR, 2020) [1] |`)
  lines.push(`| Evidence entries | ${chain.entries.length} |`)
  lines.push(`| Chain integrity | ${result.chainIntegrity.intact ? 'Verified (SHA-256)' : 'Compromised'} |`)
  lines.push(`| Signals collected | ${signals.length} |`)
  lines.push(`| Data sources | ${countCollectors(collectors)} |`)
  lines.push('')

  // ── findings ──────────────────────────────────────────────
  lines.push('## Findings')
  lines.push('')

  // anonymity
  lines.push(`Starting population: ${fmtNum(anonymity.population)} (${anonymity.priorBits.toFixed(1)} bits).`)
  lines.push(`Evidence reduced anonymity by ${anonymity.totalGainBits.toFixed(1)} bits to ${anonymity.remainingBits.toFixed(1)} bits (effective set: ${fmtNum(Math.round(anonymity.anonymitySet))}).`)
  if (anonymity.identified) {
    lines.push('Remaining anonymity is below 1 bit. The evidence is sufficient to narrow the subject to a single identity.')
  }
  lines.push('')

  // attribution
  lines.push(`Dempster-Shafer evidence fusion [2] across ${signals.length} signals:`)
  lines.push(`Belief: ${attribution.belief.toFixed(3)}. Plausibility: ${attribution.plausibility.toFixed(3)}. Conflict: ${attribution.conflict.toFixed(3)}.`)
  if (attribution.conflict > 0.5) {
    lines.push(`Conflict mass exceeds 0.5. Evidence sources disagree. The attribution score should not be relied upon without resolving the conflicting signals identified in the table below.`)
  } else if (attribution.conflict > 0.3) {
    lines.push(`Moderate conflict between evidence sources. Some signals contradict others.`)
  }
  lines.push('')

  // ── data sources ──────────────────────────────────────────
  lines.push('## Data Sources')
  lines.push('')

  if (collectors.dns) {
    lines.push(`DNS: ${collectors.dns.recordCount} records resolved via public DNS (1.1.1.1, 8.8.8.8). No zone transfer attempted.`)
    if (collectors.dns.warnings.length > 0) {
      lines.push(`Warnings: ${collectors.dns.warnings.join('; ')}.`)
    }
    lines.push('')
  }

  if (collectors.ct) {
    lines.push(`Certificate Transparency: ${collectors.ct.certCount} certificates from crt.sh (operated by Sectigo, indexing public CT logs per RFC 6962). ${collectors.ct.subdomains} subdomain(s) identified. ${collectors.ct.relatedDomains} domain(s) sharing certificates with the target.`)
    lines.push('')
  }

  if (collectors.headers) {
    lines.push(`HTTP headers: single GET request to target domain. Platform identified: ${collectors.headers.platform ?? 'not determined'}. ${collectors.headers.trackingIds} analytics/tracking identifier(s) found in response headers.`)
    lines.push('')
  }

  if (collectors.whois) {
    if (collectors.whois.privacyProtected) {
      lines.push(`WHOIS: registrant data redacted (privacy proxy or GDPR redaction). Registrar identified. Nameservers recorded.`)
    } else if (collectors.whois.registrant) {
      lines.push(`WHOIS: registrant identified as "${collectors.whois.registrant}" (TCP port 43 query, raw WHOIS protocol).`)
    } else {
      lines.push(`WHOIS: no registrant name available. Registrar and nameserver data recorded.`)
    }
    lines.push('')
  }

  if (collectors.reverseWhois) {
    lines.push(`Reverse WHOIS: ${collectors.reverseWhois.domainsFound} domain(s) registered to the same entity.`)
    lines.push('')
  }

  if (collectors.whoisHistory) {
    lines.push(`WHOIS history: ${collectors.whoisHistory.snapshots} historical snapshot(s) retrieved.${collectors.whoisHistory.hasUnredacted ? ' Pre-redaction registrant data found in historical records.' : ' No unredacted registrant data in history.'}`)
    lines.push('')
  }

  if (collectors.ipGeo) {
    lines.push(`IP geolocation: ${collectors.ipGeo.ipsLookedUp} address(es) resolved via ip-api.com. Country, city, ASN, and hosting/proxy classification recorded.`)
    lines.push('')
  }

  if (collectors.email) {
    lines.push(`Email headers: parsed per RFC 5322. Originating IP: ${collectors.email.originatingIp ?? 'not available (stripped by provider)'}. ${collectors.email.anomalies} timestamp anomaly/anomalies.`)
    lines.push('')
  }

  if (collectors.correlation) {
    lines.push(`Cross-domain correlation: ${collectors.correlation.correlationsFound} shared attribute(s) identified across investigated domains. ${collectors.correlation.clusters} domain cluster(s) formed.`)
    lines.push('')
  }

  // ── signal table ──────────────────────────────────────────
  lines.push('## Signals')
  lines.push('')
  lines.push('Each signal represents a single observation from a data source. Score indicates attribution strength (0-1). Confidence indicates measurement reliability (0-1). Information gain measured in bits per Shannon (1948) [3].')
  lines.push('')
  lines.push('| # | Source | Observation | Score | Conf. | Bits |')
  lines.push('|---|--------|-------------|------:|------:|-----:|')

  const sorted = [...signals].sort((a, b) =>
    (b.informationBits * b.confidence) - (a.informationBits * a.confidence),
  )

  sorted.forEach((s, i) => {
    lines.push(`| ${i + 1} | ${s.source} | ${truncate(s.observation, 80)} | ${s.score.toFixed(2)} | ${s.confidence.toFixed(2)} | ${s.informationBits.toFixed(1)} |`)
  })
  lines.push('')

  // ── anonymity detail ──────────────────────────────────────
  lines.push('## Anonymity Reduction')
  lines.push('')
  lines.push('Anonymity measured as Shannon entropy of the suspect population. Each evidence item contributes I(x) = -log2 p(x) bits, weighted by confidence. Remaining anonymity H = H_prior - sum of weighted gains, floored at 0.')
  lines.push('')
  lines.push(`| Metric | Value |`)
  lines.push(`|--------|------:|`)
  lines.push(`| Prior entropy | ${anonymity.priorBits.toFixed(1)} bits |`)
  lines.push(`| Total information gain | ${anonymity.totalGainBits.toFixed(1)} bits |`)
  lines.push(`| Remaining entropy | ${anonymity.remainingBits.toFixed(1)} bits |`)
  lines.push(`| Effective anonymity set | ${fmtNum(Math.round(anonymity.anonymitySet))} |`)
  lines.push('')

  if (anonymity.breakdown.length > 0) {
    lines.push('Largest contributors:')
    lines.push('')
    for (const e of anonymity.breakdown.slice(0, 5)) {
      const effective = e.informationGain * e.confidence
      lines.push(`- ${e.source}: ${truncate(e.observation, 70)} (${effective.toFixed(1)} bits)`)
    }
    lines.push('')
  }

  // ── methodology ───────────────────────────────────────────
  lines.push('## Methodology')
  lines.push('')
  lines.push('All data collected from publicly accessible sources. No authentication was used. No systems were accessed without authorisation. Collection complies with the Computer Misuse Act 1990 (UK) [4] and the Berkeley Protocol [1].')
  lines.push('')
  lines.push('Mathematical methods:')
  lines.push('')
  lines.push('- Anonymity: Shannon entropy. H(X) = -sum p(x) log2 p(x). Reference: Shannon, C.E. (1948). "A Mathematical Theory of Communication." Bell System Technical Journal, 27(3). [3]')
  lines.push('- Evidence fusion: Dempster-Shafer theory. Combines mass functions over {ATTRIBUTED, NOT_ATTRIBUTED} with conflict detection. Reference: Shafer, G. (1976). "A Mathematical Theory of Evidence." Princeton University Press. [2]')
  lines.push('- Identity correlation: Fellegi-Sunter probabilistic record linkage. Log-likelihood ratios per field. Reference: Fellegi, I.P. and Sunter, A.B. (1969). "A Theory for Record Linkage." JASA 64(328). [5]')
  lines.push('- String similarity: Jaro-Winkler. Reference: Jaro, M.A. (1989). "Advances in Record-Linkage Methodology." JASA 84(406). [6]')
  lines.push('- Coordination detection: Kolmogorov-Smirnov test against exponential distribution. Reference: Kolmogorov, A.N. (1933). [7]')
  lines.push('- Authorship attribution: stylometric features including Yule\'s K, character bigrams, Jensen-Shannon divergence. Reference: Abbasi, A. and Chen, H. (2008). "Writeprints." ACM TOIS 26(2). [8]')
  lines.push('')

  // ── evidence chain ────────────────────────────────────────
  lines.push('## Evidence Chain')
  lines.push('')
  lines.push(`${chain.entries.length} entries. Each entry records: sequential index, timestamp, SHA-256 hash of content, source, description, and a chain hash linking to the previous entry. Altering any entry invalidates all subsequent hashes.`)
  lines.push('')
  lines.push(`Integrity: ${result.chainIntegrity.intact ? 'verified' : 'COMPROMISED'}.`)
  lines.push('')

  if (chain.entries.length > 0) {
    lines.push('| Seq | Time (UTC) | Type | Source | Hash (first 12) |')
    lines.push('|----:|------------|------|--------|-----------------|')
    for (const entry of chain.entries) {
      lines.push(`| ${entry.seq} | ${fmtTime(entry.timestamp)} | ${entry.type} | ${truncate(entry.source, 40)} | ${entry.contentHash.slice(0, 12)} |`)
    }
    lines.push('')
  }

  // ── ACPO compliance ───────────────────────────────────────
  lines.push('## ACPO Compliance')
  lines.push('')
  lines.push('Assessed against the ACPO Good Practice Guide for Digital Evidence, v5 (2012) [9].')
  lines.push('')
  const acpo = checkAcpoCompliance(
    result.chainIntegrity.intact,
    result.chainIntegrity.totalEntries,
    chain.analyst,
  )
  lines.push('| Principle | Result | Basis |')
  lines.push('|-----------|--------|-------|')
  lines.push(`| 1. No action changed the data | ${acpo.dataIntegrity.compliant ? 'Met' : 'Not met'} | ${acpo.dataIntegrity.evidence} |`)
  lines.push(`| 2. Competent analyst identified | ${acpo.competence.compliant ? 'Met' : 'Not met'} | ${acpo.competence.evidence} |`)
  lines.push(`| 3. Audit trail preserved | ${acpo.auditTrail.compliant ? 'Met' : 'Not met'} | ${acpo.auditTrail.evidence} |`)
  lines.push(`| 4. Case officer responsible | ${acpo.overallResponsibility.compliant ? 'Met' : 'Not met'} | ${acpo.overallResponsibility.evidence} |`)
  lines.push('')

  // ── legal framework ───────────────────────────────────────
  lines.push('## Applicable Law')
  lines.push('')
  lines.push('Evidence admissibility:')
  lines.push('- Civil Evidence Act 1995, c.38 — electronic documents admissible; copies admissible regardless of removes from original [10]')
  lines.push('- BS 10008-1:2020 — British Standard for evidential weight of electronically stored information [11]')
  lines.push('- Criminal Practice Direction 19A (2014) — enhanced reliability test for expert evidence [12]')
  lines.push('')
  lines.push('Investigation legality:')
  lines.push('- Computer Misuse Act 1990, c.18, s.1 — no unauthorised access to computer material [4]')
  lines.push('- Data Protection Act 2018, c.12 — legitimate interest basis; data minimisation [13]')
  lines.push('- NPCC Guidance on Open Source Investigation/Research (2023) [14]')
  lines.push('')
  lines.push('Remedies available to the subject of an attack:')
  lines.push('- Digital Markets, Competition and Consumers Act 2024, c.13, Sched. 20 — fake reviews are a banned practice; CMA enforcement without court proceedings; fines up to 10% global turnover [15]')
  lines.push('- Defamation Act 2013, c.26, s.5 — website operator defence; Norwich Pharmacal order for identity disclosure [16]')
  lines.push('- Protection from Harassment Act 1997, c.40, s.1 — course of conduct causing alarm or distress; civil injunction and damages [17]')
  lines.push('')

  // ── references ────────────────────────────────────────────
  lines.push('## References')
  lines.push('')
  lines.push('[1] UC Berkeley Human Rights Center & OHCHR. "Berkeley Protocol on Digital Open Source Investigations." 2020. https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf')
  lines.push('[2] Shafer, G. "A Mathematical Theory of Evidence." Princeton University Press, 1976. See also: Dempster, A.P. "Upper and lower probabilities induced by a multivalued mapping." Ann. Math. Stat. 38(2), 1967.')
  lines.push('[3] Shannon, C.E. "A Mathematical Theory of Communication." Bell System Technical Journal, 27(3), 1948.')
  lines.push('[4] Computer Misuse Act 1990. https://www.legislation.gov.uk/ukpga/1990/18')
  lines.push('[5] Fellegi, I.P. and Sunter, A.B. "A Theory for Record Linkage." Journal of the American Statistical Association, 64(328), 1969.')
  lines.push('[6] Jaro, M.A. "Advances in Record-Linkage Methodology as Applied to Matching the 1985 Census of Tampa, Florida." JASA, 84(406), 1989.')
  lines.push('[7] Kolmogorov, A.N. "Sulla determinazione empirica di una legge di distribuzione." Giornale dell\'Istituto Italiano degli Attuari, 4, 1933.')
  lines.push('[8] Abbasi, A. and Chen, H. "Writeprints: A stylometric approach to identity-level identification and similarity detection in cyberspace." ACM Trans. Inf. Syst., 26(2), 2008.')
  lines.push('[9] ACPO. "Good Practice Guide for Digital Evidence." v5, March 2012. https://www.digital-detective.net/digital-forensics-documents/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.pdf')
  lines.push('[10] Civil Evidence Act 1995. https://www.legislation.gov.uk/ukpga/1995/38')
  lines.push('[11] BSI. "BS 10008-1:2020 Evidential weight and legal admissibility of electronically stored information (ESI) — Specification."')
  lines.push('[12] Criminal Practice Direction [2014] EWCA Crim 1570, Part 19A.')
  lines.push('[13] Data Protection Act 2018. https://www.legislation.gov.uk/ukpga/2018/12')
  lines.push('[14] NPCC. "Guidance on Open Source Investigation/Research." 2023. https://www.npcc.police.uk/SysSiteAssets/media/downloads/publications/disclosure-logs/workforce-coordination-committee/2023/061-2023-07-published-npcc-guidance-osint---reserach.pdf')
  lines.push('[15] Digital Markets, Competition and Consumers Act 2024, Schedule 20. https://www.legislation.gov.uk/ukpga/2024/13/schedule/20')
  lines.push('[16] Defamation Act 2013, s.5. https://www.legislation.gov.uk/ukpga/2013/26/section/5')
  lines.push('[17] Protection from Harassment Act 1997, s.1. https://www.legislation.gov.uk/ukpga/1997/40/section/1')
  lines.push('')

  // ── notice ────────────────────────────────────────────────
  lines.push('---')
  lines.push('')
  lines.push('This report records publicly available data with mathematical analysis. It does not constitute legal advice. The investigation used only passive observation of publicly accessible sources. No system was accessed without authorisation. No credential was tested. Consult a solicitor before acting on these findings.')
  lines.push('')
  lines.push(`Report generated ${new Date().toISOString()}.`)

  return lines.join('\n')
}

function fmtDate(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toISOString().slice(0, 10)
  } catch {
    return iso
  }
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toISOString().replace('T', ' ').slice(0, 19)
  } catch {
    return iso
  }
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toString()
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '\u2026' : s
}

function countCollectors(c: InvestigationResult['collectors']): number {
  return [c.dns, c.ct, c.headers, c.whois, c.email, c.reverseWhois, c.whoisHistory, c.ipGeo, c.correlation].filter(Boolean).length
}
