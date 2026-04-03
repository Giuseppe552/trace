/**
 * Human-readable forensic report generator.
 *
 * Converts raw investigation results into a structured narrative
 * suitable for legal review, management briefing, or portfolio
 * case study publication.
 *
 * Output: Markdown document following a forensic report structure.
 */

import type { InvestigationResult } from '../orchestrator.js'

/**
 * Generate a forensic narrative report from investigation results.
 */
export function generateReport(result: InvestigationResult): string {
  const lines: string[] = []
  const { anonymity, attribution, signals, collectors, chain } = result

  // header
  lines.push(`# Investigation Report: ${result.label}`)
  lines.push('')
  lines.push(`**Period:** ${fmtDate(result.startedAt)} – ${fmtDate(result.completedAt)}`)
  lines.push(`**Analyst:** trace v0.1`)
  lines.push(`**Evidence chain:** ${chain.entries.length} entries, integrity ${result.chainIntegrity.intact ? 'VERIFIED' : 'BROKEN'}`)
  lines.push(`**Methodology:** Berkeley Protocol on Digital Open Source Investigations (OHCHR, 2020)`)
  lines.push('')

  // executive summary
  lines.push('## Executive Summary')
  lines.push('')
  lines.push(`This investigation collected **${signals.length} signals** from ${countCollectors(collectors)} data sources.`)
  lines.push('')

  if (anonymity.identified) {
    lines.push(`The subject's anonymity has been **effectively eliminated**. Starting from a population of ${fmtNum(anonymity.population)} (${anonymity.priorBits.toFixed(1)} bits of anonymity), evidence reduced the anonymity set to **${Math.round(anonymity.anonymitySet)}** (${anonymity.remainingBits.toFixed(1)} bits remaining).`)
  } else {
    lines.push(`The subject's anonymity has been **partially reduced**. Starting from ${fmtNum(anonymity.population)} (${anonymity.priorBits.toFixed(1)} bits), evidence narrowed the set to approximately **${fmtNum(Math.round(anonymity.anonymitySet))}** (${anonymity.remainingBits.toFixed(1)} bits remaining).`)
  }
  lines.push('')

  lines.push(`Attribution confidence: **${attribution.level.toUpperCase()}** (Bel=${attribution.belief.toFixed(3)}, Pl=${attribution.plausibility.toFixed(3)}, conflict=${attribution.conflict.toFixed(3)}).`)
  if (attribution.conflict > 0.3) {
    lines.push(`> Note: High conflict mass (K=${attribution.conflict.toFixed(3)}) indicates evidence sources disagree. Attribution should be treated with caution until conflict is resolved.`)
  }
  lines.push('')

  // data sources
  lines.push('## Data Sources')
  lines.push('')

  if (collectors.dns) {
    lines.push(`### DNS Records`)
    lines.push(`- ${collectors.dns.recordCount} records resolved`)
    if (collectors.dns.warnings.length > 0) {
      lines.push(`- Warnings: ${collectors.dns.warnings.join(', ')}`)
    }
    lines.push('')
  }

  if (collectors.ct) {
    lines.push(`### Certificate Transparency`)
    lines.push(`- ${collectors.ct.certCount} certificates found in public CT logs (crt.sh)`)
    lines.push(`- ${collectors.ct.subdomains} subdomains discovered`)
    if (collectors.ct.relatedDomains > 0) {
      lines.push(`- **${collectors.ct.relatedDomains} related domains** found via shared certificates`)
    }
    lines.push('')
  }

  if (collectors.headers) {
    lines.push(`### HTTP Header Fingerprint`)
    lines.push(`- Platform: ${collectors.headers.platform ?? 'unknown'}`)
    if (collectors.headers.trackingIds > 0) {
      lines.push(`- **${collectors.headers.trackingIds} tracking ID(s)** found — these link to specific analytics accounts`)
    }
    lines.push('')
  }

  if (collectors.whois) {
    lines.push(`### WHOIS Registration`)
    if (collectors.whois.privacyProtected) {
      lines.push(`- Registrant data is **privacy-protected** (GDPR redacted)`)
      lines.push(`- Historical WHOIS records may reveal the original registrant`)
    } else {
      lines.push(`- Registrant: **${collectors.whois.registrant}**`)
    }
    lines.push('')
  }

  if (collectors.email) {
    lines.push(`### Email Header Analysis`)
    lines.push(`- Originating IP: ${collectors.email.originatingIp ?? 'not available (stripped by provider)'}`)
    if (collectors.email.anomalies > 0) {
      lines.push(`- **${collectors.email.anomalies} timestamp anomalies detected** — possible header manipulation`)
    }
    lines.push('')
  }

  // signal breakdown
  lines.push('## Signal Analysis')
  lines.push('')
  lines.push('| # | Source | Observation | Score | Confidence | Info (bits) |')
  lines.push('|---|--------|-------------|-------|------------|-------------|')

  const sorted = [...signals].sort((a, b) =>
    (b.informationBits * b.confidence) - (a.informationBits * a.confidence),
  )

  sorted.forEach((s, i) => {
    lines.push(`| ${i + 1} | ${s.source} | ${s.observation} | ${s.score.toFixed(2)} | ${s.confidence.toFixed(2)} | ${s.informationBits.toFixed(1)} |`)
  })
  lines.push('')

  // anonymity breakdown
  lines.push('## Anonymity Reduction')
  lines.push('')
  lines.push(`| Prior | Evidence Gain | Remaining | Set Size | Status |`)
  lines.push(`|-------|-------------|-----------|----------|--------|`)
  lines.push(`| ${anonymity.priorBits.toFixed(1)} bits | ${anonymity.totalGainBits.toFixed(1)} bits | ${anonymity.remainingBits.toFixed(1)} bits | ${fmtNum(Math.round(anonymity.anonymitySet))} | ${anonymity.identified ? 'IDENTIFIED' : 'PARTIAL'} |`)
  lines.push('')

  if (anonymity.breakdown.length > 0) {
    lines.push('Top contributors to anonymity reduction:')
    lines.push('')
    for (const e of anonymity.breakdown.slice(0, 5)) {
      const effectiveGain = e.informationGain * e.confidence
      lines.push(`- **${e.source}**: ${e.observation} (${effectiveGain.toFixed(1)} effective bits)`)
    }
    lines.push('')
  }

  // methodology
  lines.push('## Methodology')
  lines.push('')
  lines.push('This investigation follows the Berkeley Protocol on Digital Open Source Investigations (OHCHR, 2020). All data was collected from publicly accessible sources without authentication or authorization bypass.')
  lines.push('')
  lines.push('Mathematical frameworks:')
  lines.push('- **Anonymity quantification**: Shannon entropy (1948). Anonymity measured in bits; each evidence item reduces H by I(x) weighted by confidence.')
  lines.push('- **Evidence fusion**: Dempster-Shafer theory (Dempster 1967, Shafer 1976). Handles conflicting evidence without averaging.')
  lines.push('- **Identity correlation**: Fellegi-Sunter probabilistic record linkage (1969) with Jaro-Winkler string similarity.')
  lines.push('- **Coordination detection**: Kolmogorov-Smirnov test against exponential inter-arrival times.')
  lines.push('- **Authorship attribution**: Writeprints stylometric features (Abbasi & Chen, 2008, ACM TOIS 26(2)).')
  lines.push('')

  // evidence chain
  lines.push('## Evidence Chain')
  lines.push('')
  lines.push(`${chain.entries.length} evidence entries preserved with SHA-256 hash chain.`)
  lines.push(`Chain integrity: **${result.chainIntegrity.intact ? 'INTACT' : 'COMPROMISED'}**`)
  lines.push('')

  if (chain.entries.length > 0) {
    lines.push('| # | Timestamp | Type | Layer | Description | Content Hash |')
    lines.push('|---|-----------|------|-------|-------------|-------------|')
    for (const entry of chain.entries) {
      lines.push(`| ${entry.seq} | ${fmtDate(entry.timestamp)} | ${entry.type} | ${entry.layer} | ${entry.description.slice(0, 60)} | \`${entry.contentHash.slice(0, 12)}...\` |`)
    }
    lines.push('')
  }

  // legal notice
  lines.push('## Legal Notice')
  lines.push('')
  lines.push('This report is based entirely on publicly available information collected through passive observation. No authentication bypass, credential testing, or active exploitation was performed. All collection methods comply with the Computer Misuse Act 1990 (UK), Data Protection Act 2018, and the Berkeley Protocol standards for digital open source investigations.')
  lines.push('')
  lines.push('---')
  lines.push(`*Generated by trace v0.1 at ${new Date().toISOString()}*`)

  return lines.join('\n')
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
  } catch {
    return iso
  }
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toString()
}

function countCollectors(c: InvestigationResult['collectors']): number {
  return [c.dns, c.ct, c.headers, c.whois, c.email].filter(Boolean).length
}
