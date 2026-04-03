/**
 * UK legal framework for digital attribution investigations.
 *
 * Every investigation trace produces must reference the specific
 * legal basis for: (1) why the evidence collection was lawful,
 * (2) what legal remedies are available, (3) what standards the
 * evidence must meet for admissibility.
 *
 * This module provides structured legal references that are
 * included in every forensic report. It does NOT provide legal
 * advice — it provides the framework for a solicitor to assess.
 *
 * Key legislation:
 *
 * EVIDENCE ADMISSIBILITY:
 * - Civil Evidence Act 1995 — electronic documents admissible,
 *   copies are admissible regardless of number of removes from original
 * - BS 10008:2020 — British Standard for evidential weight of ESI.
 *   Requires: authenticity, integrity, availability throughout lifecycle.
 * - Criminal Practice Direction 19A (2014) — enhanced Daubert test
 *   for expert evidence reliability in UK courts
 * - ACPO Good Practice Guide v5 (2012) — four principles for
 *   digital evidence: integrity, competence, documentation, audit trail
 *
 * INVESTIGATION LEGALITY:
 * - Computer Misuse Act 1990 — all collection must be passive,
 *   publicly available, no unauthorized access
 * - Data Protection Act 2018 / UK GDPR — legitimate interest basis,
 *   proportionality, data minimization
 * - Berkeley Protocol (OHCHR, 2020) — international standard for
 *   digital open source investigations
 *
 * LEGAL REMEDIES (what the victim can do):
 * - DMCC Act 2024, Schedule 20 — fake reviews are a banned practice.
 *   CMA can fine up to 10% global turnover without going to court.
 *   In force 6 April 2025.
 * - Defamation Act 2013, Section 5 — website operator defence.
 *   If operator can't identify poster, claimant can seek
 *   Norwich Pharmacal order for identity disclosure.
 * - Protection from Harassment Act 1997 — course of conduct
 *   (2+ occasions) causing alarm/distress. Civil injunction + damages.
 *   Breach of injunction is criminal.
 * - Norwich Pharmacal Orders — High Court order compelling
 *   platform (Google, Trustpilot) to disclose anonymous poster identity.
 *   Requires: evidence of wrongdoing, respondent holds info, disclosure
 *   necessary and proportionate. 4-8 weeks typical.
 */

/** A legal reference with citation */
export interface LegalReference {
  /** short name */
  name: string
  /** full citation */
  citation: string
  /** what it covers */
  relevance: string
  /** legislation.gov.uk or other authoritative URL */
  url: string
  /** which part of the investigation it applies to */
  applicableTo: 'evidence_admissibility' | 'investigation_legality' | 'legal_remedy' | 'methodology'
}

/** All legal references relevant to trace investigations */
export const UK_LEGAL_FRAMEWORK: LegalReference[] = [
  // ── Evidence admissibility ────────────────────────────────
  {
    name: 'Civil Evidence Act 1995',
    citation: 'Civil Evidence Act 1995, c.38',
    relevance: 'Electronic documents are admissible in civil proceedings. A copy is admissible regardless of how many removes from the original. Business records admissible with officer certificate.',
    url: 'https://www.legislation.gov.uk/ukpga/1995/38',
    applicableTo: 'evidence_admissibility',
  },
  {
    name: 'BS 10008:2020',
    citation: 'BS 10008-1:2020 Evidential weight and legal admissibility of ESI',
    relevance: 'British Standard specifying requirements for electronic information management where authenticity, integrity and availability are important for legal admissibility. Requires demonstrable chain of custody.',
    url: 'https://knowledge.bsigroup.com/products/evidential-weight-and-legal-admissibility-of-electronically-stored-information-esi-specification',
    applicableTo: 'evidence_admissibility',
  },
  {
    name: 'Criminal Practice Direction 19A',
    citation: 'Criminal Practice Direction [2014] EWCA Crim 1570, Part 19A',
    relevance: 'Enhanced Daubert test for expert evidence reliability in UK courts. Expert methodology must be testable, peer-reviewed, have known error rate, and be generally accepted. Applied to digital forensics.',
    url: 'https://www.cps.gov.uk/prosecution-guidance/expert-evidence',
    applicableTo: 'evidence_admissibility',
  },
  {
    name: 'ACPO Good Practice Guide v5',
    citation: 'ACPO Good Practice Guide for Digital Evidence, v5 (March 2012)',
    relevance: 'Four principles: (1) no action should change data relied upon in court, (2) person accessing data must be competent, (3) audit trail of all actions must be created and preserved, (4) case officer has overall responsibility. Hash values verify integrity.',
    url: 'https://www.digital-detective.net/digital-forensics-documents/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.pdf',
    applicableTo: 'evidence_admissibility',
  },

  // ── Investigation legality ────────────────────────────────
  {
    name: 'Computer Misuse Act 1990',
    citation: 'Computer Misuse Act 1990, c.18',
    relevance: 'Section 1 prohibits unauthorized access to computer material. All trace data collection is passive OSINT from publicly available sources — no authentication bypass, no credential testing, no active exploitation.',
    url: 'https://www.legislation.gov.uk/ukpga/1990/18',
    applicableTo: 'investigation_legality',
  },
  {
    name: 'Data Protection Act 2018',
    citation: 'Data Protection Act 2018, c.12 (UK GDPR)',
    relevance: 'Processing of personal data requires lawful basis. Legitimate interest basis applies to fraud investigation. Data minimization: only collect what is necessary. Retain only for duration of investigation.',
    url: 'https://www.legislation.gov.uk/ukpga/2018/12',
    applicableTo: 'investigation_legality',
  },
  {
    name: 'Berkeley Protocol',
    citation: 'Berkeley Protocol on Digital Open Source Investigations (OHCHR/UC Berkeley, 2020)',
    relevance: 'International standard for digital OSINT investigations. Requires: only publicly accessible sources, every step documented, chain of custody preserved, cross-corroboration, transparent methodology.',
    url: 'https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf',
    applicableTo: 'methodology',
  },
  {
    name: 'NPCC OSINT Guidance',
    citation: 'NPCC Guidance on Open Source Investigation/Research (2023)',
    relevance: 'UK police guidance on lawful OSINT. Defines boundary between passive research (lawful) and active investigation requiring authorization.',
    url: 'https://www.npcc.police.uk/SysSiteAssets/media/downloads/publications/disclosure-logs/workforce-coordination-committee/2023/061-2023-07-published-npcc-guidance-osint---reserach.pdf',
    applicableTo: 'investigation_legality',
  },

  // ── Legal remedies ────────────────────────────────────────
  {
    name: 'DMCC Act 2024 (fake reviews)',
    citation: 'Digital Markets, Competition and Consumers Act 2024, c.13, Schedule 20',
    relevance: 'Fake reviews are a banned practice from 6 April 2025. CMA can fine up to 10% global turnover without court proceedings. Covers: submitting/commissioning fake reviews, concealed incentivised reviews, publishing reviews in misleading way.',
    url: 'https://www.legislation.gov.uk/ukpga/2024/13/schedule/20',
    applicableTo: 'legal_remedy',
  },
  {
    name: 'CMA Fake Reviews Guidance',
    citation: 'CMA208 — Fake reviews guidance (April 2025)',
    relevance: 'CMA enforcement guidance on fake review detection and compliance. Defines what constitutes a fake review, publisher obligations, and enforcement approach.',
    url: 'https://assets.publishing.service.gov.uk/media/67eeb64fe9c76fa33048c790/CMA208_-_Fake_reviews_guidance.pdf',
    applicableTo: 'legal_remedy',
  },
  {
    name: 'Defamation Act 2013',
    citation: 'Defamation Act 2013, c.26, Section 5',
    relevance: 'Section 5 provides website operator defence. If poster cannot be identified, claimant can seek Norwich Pharmacal order. Serious harm threshold (s.1) must be met. Truth is absolute defence.',
    url: 'https://www.legislation.gov.uk/ukpga/2013/26/section/5',
    applicableTo: 'legal_remedy',
  },
  {
    name: 'Norwich Pharmacal Orders',
    citation: 'Norwich Pharmacal Co v Customs and Excise Commissioners [1974] AC 133',
    relevance: 'High Court order compelling platform (Google, Trustpilot) to disclose anonymous poster identity. Requires: evidence of wrongdoing, respondent holds identifying info, disclosure necessary and proportionate. Typically 4-8 weeks.',
    url: 'https://civillitigationlawyers.co.uk/anonymous-posters-norwich-pharmacal-orders-explained/',
    applicableTo: 'legal_remedy',
  },
  {
    name: 'Protection from Harassment Act 1997',
    citation: 'Protection from Harassment Act 1997, c.40',
    relevance: 'Course of conduct (2+ occasions) causing alarm/distress. Covers: fake reviews, malicious posts, brand damage by competitors. Civil remedies: injunction + damages. Breach of injunction is criminal offence.',
    url: 'https://www.legislation.gov.uk/ukpga/1997/40/section/1',
    applicableTo: 'legal_remedy',
  },
]

/**
 * Get legal references applicable to a specific investigation aspect.
 */
export function getLegalReferences(
  applicableTo: LegalReference['applicableTo'],
): LegalReference[] {
  return UK_LEGAL_FRAMEWORK.filter(r => r.applicableTo === applicableTo)
}

/**
 * Generate the legal basis section of a forensic report.
 */
export function generateLegalBasis(): string {
  const lines: string[] = []

  lines.push('## Legal Framework')
  lines.push('')

  lines.push('### Evidence Admissibility')
  lines.push('')
  for (const ref of getLegalReferences('evidence_admissibility')) {
    lines.push(`**${ref.name}** (${ref.citation})`)
    lines.push(`${ref.relevance}`)
    lines.push(`Source: ${ref.url}`)
    lines.push('')
  }

  lines.push('### Investigation Legality')
  lines.push('')
  for (const ref of getLegalReferences('investigation_legality')) {
    lines.push(`**${ref.name}** (${ref.citation})`)
    lines.push(`${ref.relevance}`)
    lines.push(`Source: ${ref.url}`)
    lines.push('')
  }

  lines.push('### Methodology Standard')
  lines.push('')
  for (const ref of getLegalReferences('methodology')) {
    lines.push(`**${ref.name}** (${ref.citation})`)
    lines.push(`${ref.relevance}`)
    lines.push(`Source: ${ref.url}`)
    lines.push('')
  }

  lines.push('### Available Legal Remedies')
  lines.push('')
  for (const ref of getLegalReferences('legal_remedy')) {
    lines.push(`**${ref.name}** (${ref.citation})`)
    lines.push(`${ref.relevance}`)
    lines.push(`Source: ${ref.url}`)
    lines.push('')
  }

  return lines.join('\n')
}

/**
 * ACPO Principle alignment checker.
 *
 * Checks whether the evidence chain ALIGNS with the four ACPO
 * principles. This is NOT a full compliance assessment — real ACPO
 * compliance requires qualified personnel, validated methodology,
 * and independent reproducibility testing. This check verifies
 * the technical prerequisites only.
 *
 * Labeled as "alignment" rather than "compliance" per audit #14.
 */
export interface AcpoCompliance {
  /** Principle 1: data integrity — no data was changed */
  dataIntegrity: { compliant: boolean; evidence: string }
  /** Principle 2: competence — analyst is identified */
  competence: { compliant: boolean; evidence: string }
  /** Principle 3: audit trail — all actions documented */
  auditTrail: { compliant: boolean; evidence: string }
  /** Principle 4: overall responsibility — case officer identified */
  overallResponsibility: { compliant: boolean; evidence: string }
  /** overall compliance */
  allCompliant: boolean
}

/**
 * Check ACPO compliance for an evidence chain.
 */
export function checkAcpoCompliance(
  chainIntact: boolean,
  totalEntries: number,
  analyst: string,
): AcpoCompliance {
  const dataIntegrity = {
    compliant: chainIntact,
    evidence: chainIntact
      ? `SHA-256 hash chain verified intact across ${totalEntries} entries`
      : 'CHAIN INTEGRITY BROKEN — evidence may have been altered',
  }

  const competence = {
    compliant: analyst.length > 0,
    evidence: analyst.length > 0
      ? `Analyst identified: ${analyst}`
      : 'No analyst identified',
  }

  const auditTrail = {
    compliant: totalEntries > 0,
    evidence: totalEntries > 0
      ? `${totalEntries} evidence entries with timestamps, sources, and content hashes`
      : 'No evidence entries recorded',
  }

  const overallResponsibility = {
    compliant: analyst.length > 0 && chainIntact,
    evidence: `Investigation conducted by ${analyst}, chain integrity ${chainIntact ? 'verified' : 'compromised'}`,
  }

  return {
    dataIntegrity,
    competence,
    auditTrail,
    overallResponsibility,
    allCompliant: dataIntegrity.compliant && competence.compliant && auditTrail.compliant && overallResponsibility.compliant,
  }
}
