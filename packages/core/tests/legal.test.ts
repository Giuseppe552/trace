import { describe, it, expect } from 'vitest'
import {
  UK_LEGAL_FRAMEWORK,
  getLegalReferences,
  generateLegalBasis,
  checkAcpoCompliance,
} from '../src/legal/framework.js'

describe('UK_LEGAL_FRAMEWORK', () => {
  it('contains all required categories', () => {
    const categories = new Set(UK_LEGAL_FRAMEWORK.map(r => r.applicableTo))
    expect(categories.has('evidence_admissibility')).toBe(true)
    expect(categories.has('investigation_legality')).toBe(true)
    expect(categories.has('legal_remedy')).toBe(true)
    expect(categories.has('methodology')).toBe(true)
  })

  it('all references have URLs', () => {
    for (const ref of UK_LEGAL_FRAMEWORK) {
      expect(ref.url.length).toBeGreaterThan(10)
    }
  })

  it('all references have citations', () => {
    for (const ref of UK_LEGAL_FRAMEWORK) {
      expect(ref.citation.length).toBeGreaterThan(5)
    }
  })

  it('includes Civil Evidence Act 1995', () => {
    const cea = UK_LEGAL_FRAMEWORK.find(r => r.name === 'Civil Evidence Act 1995')
    expect(cea).toBeDefined()
    expect(cea!.url).toContain('legislation.gov.uk')
  })

  it('includes DMCC Act 2024', () => {
    const dmcc = UK_LEGAL_FRAMEWORK.find(r => r.name === 'DMCC Act 2024 (fake reviews)')
    expect(dmcc).toBeDefined()
    expect(dmcc!.relevance).toContain('banned practice')
    expect(dmcc!.relevance).toContain('10%')
  })

  it('includes Computer Misuse Act 1990', () => {
    const cma = UK_LEGAL_FRAMEWORK.find(r => r.name === 'Computer Misuse Act 1990')
    expect(cma).toBeDefined()
    expect(cma!.applicableTo).toBe('investigation_legality')
  })

  it('includes Norwich Pharmacal Orders', () => {
    const npo = UK_LEGAL_FRAMEWORK.find(r => r.name === 'Norwich Pharmacal Orders')
    expect(npo).toBeDefined()
    expect(npo!.applicableTo).toBe('legal_remedy')
  })

  it('includes Protection from Harassment Act', () => {
    const pha = UK_LEGAL_FRAMEWORK.find(r => r.name === 'Protection from Harassment Act 1997')
    expect(pha).toBeDefined()
    expect(pha!.relevance.toLowerCase()).toContain('course of conduct')
  })

  it('includes ACPO Guide', () => {
    const acpo = UK_LEGAL_FRAMEWORK.find(r => r.name === 'ACPO Good Practice Guide v5')
    expect(acpo).toBeDefined()
    expect(acpo!.relevance.toLowerCase()).toContain('four principles')
  })

  it('includes Berkeley Protocol', () => {
    const bp = UK_LEGAL_FRAMEWORK.find(r => r.name === 'Berkeley Protocol')
    expect(bp).toBeDefined()
    expect(bp!.url).toContain('ohchr.org')
  })

  it('includes BS 10008', () => {
    const bs = UK_LEGAL_FRAMEWORK.find(r => r.name === 'BS 10008:2020')
    expect(bs).toBeDefined()
    expect(bs!.relevance).toContain('chain of custody')
  })
})

describe('getLegalReferences', () => {
  it('filters by evidence_admissibility', () => {
    const refs = getLegalReferences('evidence_admissibility')
    expect(refs.length).toBeGreaterThan(2)
    for (const r of refs) {
      expect(r.applicableTo).toBe('evidence_admissibility')
    }
  })

  it('filters by investigation_legality', () => {
    const refs = getLegalReferences('investigation_legality')
    expect(refs.length).toBeGreaterThan(1)
    for (const r of refs) {
      expect(r.applicableTo).toBe('investigation_legality')
    }
  })

  it('filters by legal_remedy', () => {
    const refs = getLegalReferences('legal_remedy')
    expect(refs.length).toBeGreaterThan(3)
    for (const r of refs) {
      expect(r.applicableTo).toBe('legal_remedy')
    }
  })
})

describe('generateLegalBasis', () => {
  const report = generateLegalBasis()

  it('includes all section headers', () => {
    expect(report).toContain('## Legal Framework')
    expect(report).toContain('### Evidence Admissibility')
    expect(report).toContain('### Investigation Legality')
    expect(report).toContain('### Methodology Standard')
    expect(report).toContain('### Available Legal Remedies')
  })

  it('includes legislation citations', () => {
    expect(report).toContain('Civil Evidence Act 1995')
    expect(report).toContain('Computer Misuse Act 1990')
    expect(report).toContain('DMCC Act 2024')
    expect(report).toContain('Defamation Act 2013')
    expect(report).toContain('Norwich Pharmacal')
  })

  it('includes URLs', () => {
    expect(report).toContain('legislation.gov.uk')
    expect(report).toContain('ohchr.org')
  })
})

describe('checkAcpoCompliance', () => {
  it('all principles pass for valid investigation', () => {
    const result = checkAcpoCompliance(true, 10, 'giuseppe')
    expect(result.allCompliant).toBe(true)
    expect(result.dataIntegrity.compliant).toBe(true)
    expect(result.competence.compliant).toBe(true)
    expect(result.auditTrail.compliant).toBe(true)
    expect(result.overallResponsibility.compliant).toBe(true)
  })

  it('fails if chain is broken', () => {
    const result = checkAcpoCompliance(false, 10, 'giuseppe')
    expect(result.allCompliant).toBe(false)
    expect(result.dataIntegrity.compliant).toBe(false)
    expect(result.dataIntegrity.evidence).toContain('BROKEN')
  })

  it('fails if no analyst', () => {
    const result = checkAcpoCompliance(true, 10, '')
    expect(result.allCompliant).toBe(false)
    expect(result.competence.compliant).toBe(false)
  })

  it('fails if no evidence entries', () => {
    const result = checkAcpoCompliance(true, 0, 'giuseppe')
    expect(result.allCompliant).toBe(false)
    expect(result.auditTrail.compliant).toBe(false)
  })

  it('includes hash chain verification in evidence', () => {
    const result = checkAcpoCompliance(true, 15, 'giuseppe')
    expect(result.dataIntegrity.evidence).toContain('SHA-256')
    expect(result.dataIntegrity.evidence).toContain('15')
  })
})
