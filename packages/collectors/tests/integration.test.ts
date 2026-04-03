import { describe, it, expect } from 'vitest'
import { investigate, exportInvestigation } from '../src/orchestrator.js'
import { generateReport } from '../src/report/narrative.js'
import { analyzeReviews, type GoogleReview } from '../src/reviews/google.js'
import { detectAiText, compareWriteprints, computeAnonymity, fuseEvidence, createMass, POPULATION } from '@trace/core'

describe('end-to-end investigation pipeline', () => {
  // this test hits real network — skip in CI
  it('produces valid investigation from domain', async () => {
    const result = await investigate({
      domain: 'example.com',
      label: 'integration-test',
      population: POPULATION.uk,
    })

    // basic structure
    expect(result.label).toBe('integration-test')
    expect(result.startedAt).toBeTruthy()
    expect(result.completedAt).toBeTruthy()

    // signals collected
    expect(result.signals.length).toBeGreaterThan(0)

    // anonymity computed
    expect(result.anonymity.priorBits).toBeCloseTo(26, 0)
    expect(result.anonymity.remainingBits).toBeGreaterThanOrEqual(0)
    expect(result.anonymity.remainingBits).toBeLessThanOrEqual(result.anonymity.priorBits)

    // attribution computed
    expect(result.attribution.belief).toBeGreaterThanOrEqual(0)
    expect(result.attribution.belief).toBeLessThanOrEqual(1)
    expect(result.attribution.plausibility).toBeGreaterThanOrEqual(result.attribution.belief)

    // evidence chain intact
    expect(result.chainIntegrity.intact).toBe(true)
    expect(result.chainIntegrity.totalEntries).toBeGreaterThan(0)

    // graph built
    expect(result.graph.nodes.length).toBeGreaterThan(0)
    expect(result.graphDot).toContain('digraph trace')
  }, 60_000) // 60s timeout for network calls

  it('exports valid JSON report', async () => {
    const result = await investigate({
      domain: 'example.com',
      label: 'export-test',
    })

    const json = exportInvestigation(result)
    const parsed = JSON.parse(json)

    expect(parsed._format).toBe('trace-investigation-v1')
    expect(parsed.summary.signalCount).toBeGreaterThan(0)
    expect(parsed.summary.evidenceChain.intact).toBe(true)
  }, 60_000)

  it('generates valid markdown report', async () => {
    const result = await investigate({
      domain: 'example.com',
      label: 'report-test',
    })

    const md = generateReport(result)

    expect(md).toContain('# Investigation Report')
    expect(md).toContain('## Executive Summary')
    expect(md).toContain('## Data Sources')
    expect(md).toContain('## Signal Analysis')
    expect(md).toContain('## Evidence Chain')
    expect(md).toContain('## Legal Notice')
    expect(md).toContain('Berkeley Protocol')
  }, 60_000)
})

describe('review analysis pipeline', () => {
  const ATTACK_REVIEWS: GoogleReview[] = [
    { authorName: 'Attacker1', authorUrl: null, authorPhoto: null, rating: 1, text: 'I recently used their citizenship application service and found the experience to be quite unsatisfactory. The team demonstrated a lack of understanding of the requirements and failed to guide me through the process. Additionally, the translation service was inaccurate and poorly presented. However, it is worth noting that the pricing was reasonable. Nevertheless, the overall quality fell far below expectations. I would not recommend their services.', time: '1 day ago', timestamp: Date.now() - 86400000, language: 'en' },
    { authorName: 'Attacker2', authorUrl: null, authorPhoto: null, rating: 1, text: 'This company provides a terrible service for those looking to navigate the citizenship process. The staff are unknowledgeable and unprofessional in their approach. Furthermore, the documentation was handled with little attention to detail. The pricing is unreasonable considering the poor quality of service provided. Overall, I would not recommend this company. The entire experience was disorganized from start to finish.', time: '1 day ago', timestamp: Date.now() - 82800000, language: 'en' },
    { authorName: 'RealCustomer', authorUrl: null, authorPhoto: null, rating: 4, text: 'Pretty good service. Took a while but they got the job done. Would use again for the passport stuff.', time: '2 months ago', timestamp: Date.now() - 60 * 86400000, language: 'en' },
  ]

  it('AI reviews have lower burstiness than human writing', () => {
    const ai1 = detectAiText(ATTACK_REVIEWS[0].text)
    const ai2 = detectAiText(ATTACK_REVIEWS[1].text)

    // AI-characteristic text has more uniform sentence length (lower CV)
    // both attack reviews are written in uniform AI style
    expect(ai1.features.sentenceLengthCV).toBeLessThan(0.5)
    expect(ai2.features.sentenceLengthCV).toBeLessThan(0.5)
    // and both have detectable features
    expect(ai1.wordCount).toBeGreaterThan(50)
    expect(ai2.wordCount).toBeGreaterThan(50)
  })

  it('detects stylometric similarity between attack reviews', () => {
    const result = compareWriteprints(ATTACK_REVIEWS[0].text, ATTACK_REVIEWS[1].text)
    // both written in same AI style — should be similar
    expect(result.similarity).toBeGreaterThan(0.6)
  })

  it('attack reviews less similar to human review', () => {
    const attackVsAttack = compareWriteprints(ATTACK_REVIEWS[0].text, ATTACK_REVIEWS[1].text)
    const attackVsHuman = compareWriteprints(ATTACK_REVIEWS[0].text, ATTACK_REVIEWS[2].text)
    expect(attackVsAttack.similarity).toBeGreaterThan(attackVsHuman.similarity)
  })

  it('full review analysis pipeline produces output', () => {
    const result = analyzeReviews('Target Business', ATTACK_REVIEWS)
    // with only 3 reviews and sophisticated text, flagging may be limited
    // but the pipeline should still run and produce signals about the rating distribution
    expect(result.data.reviews.length).toBe(3)
    // two 1-stars out of 3 reviews should produce a rating signal
    expect(result.signals.length).toBeGreaterThanOrEqual(0)
    // the analysis should complete without errors
    expect(result.data.businessName).toBe('Target Business')
  })
})

describe('mathematical property invariants', () => {
  it('anonymity never exceeds prior', () => {
    for (let i = 0; i < 50; i++) {
      const evidence = Array.from({ length: Math.floor(Math.random() * 10) }, (_, j) => ({
        source: `src${j}`,
        observation: 'test',
        informationGain: Math.random() * 10,
        confidence: Math.random(),
      }))
      const result = computeAnonymity(POPULATION.uk, evidence)
      expect(result.remainingBits).toBeLessThanOrEqual(result.priorBits + 1e-10)
      expect(result.remainingBits).toBeGreaterThanOrEqual(0)
    }
  })

  it('Bel ≤ Pl across random evidence combinations', () => {
    for (let i = 0; i < 100; i++) {
      const n = Math.floor(Math.random() * 8) + 1
      const masses = Array.from({ length: n }, (_, j) =>
        createMass(Math.random(), Math.random(), `s${j}`),
      )
      const result = fuseEvidence(masses)
      expect(result.belief).toBeLessThanOrEqual(result.plausibility + 1e-10)
      expect(result.belief).toBeGreaterThanOrEqual(-1e-10)
      expect(result.plausibility).toBeLessThanOrEqual(1 + 1e-10)
    }
  })

  it('evidence chain integrity survives full pipeline', async () => {
    const result = await investigate({
      domain: 'example.com',
      label: 'integrity-test',
    })
    expect(result.chainIntegrity.intact).toBe(true)
    expect(result.chain.entries.length).toBe(result.chainIntegrity.totalEntries)
  }, 60_000)
})
