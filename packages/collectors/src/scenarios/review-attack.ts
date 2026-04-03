/**
 * Review attack investigation scenario.
 *
 * End-to-end pipeline for investigating a coordinated fake review
 * campaign. Chains together all relevant collectors and analysis
 * modules into a single workflow.
 *
 * Investigation flow:
 * 1. Analyze reviews for suspicious patterns + AI detection
 * 2. Analyze reviewer profiles (rating bias, category concentration)
 * 3. Cross-compare reviewer writing styles (stylometry)
 * 4. Cross-compare reviewer behavior (geographic, categorical)
 * 5. Detect coordinated timing
 * 6. If competitor domain found: investigate domain infrastructure
 * 7. Cross-reference reviewer location with competitor location
 * 8. Build attribution graph
 * 9. Compute anonymity reduction + evidence fusion
 * 10. Generate forensic report
 */

import {
  computeAnonymity,
  fuseEvidence,
  createMass,
  LAYER_RELIABILITY,
  POPULATION,
  detectCoordination,
  compareWriteprints,
  detectAiText,
  createChain,
  appendEvidence,
  verifyChain,
  buildGraphFromSignals,
  toDot,
  type EvidenceItem,
  type AttributionGraph,
  type GraphNode,
  type GraphEdge,
} from '@trace/core'

import { analyzeReviews, type GoogleReview } from '../reviews/google.js'
import { analyzeReviewerProfile, compareReviewerBehavior, type ReviewerProfileData } from '../reviews/profile-osint.js'
import { collectDns } from '../dns/resolver.js'
import { collectHeaders } from '../headers/fingerprint.js'
import type { Signal } from '../types.js'

/** Input for a review attack investigation */
export interface ReviewAttackInput {
  /** the business being attacked */
  businessName: string
  /** domain of the attacked business */
  businessDomain?: string
  /** all reviews to analyze */
  reviews: GoogleReview[]
  /** reviewer profiles (if available) */
  reviewerProfiles?: ReviewerProfileData[]
  /** suspected competitor domain (if known) */
  suspectedCompetitorDomain?: string
  /** suspect population */
  population?: number
}

/** Result of a review attack investigation */
export interface ReviewAttackResult {
  /** investigation label */
  label: string
  startedAt: string
  completedAt: string

  /** review analysis */
  reviewAnalysis: {
    totalReviews: number
    suspiciousCount: number
    aiDetectedCount: number
    burstGroups: number
  }

  /** stylometry findings — pairs of reviews likely by same author */
  stylometryMatches: Array<{
    authorA: string
    authorB: string
    similarity: number
  }>

  /** AI detection results per review */
  aiDetection: Array<{
    author: string
    verdict: string
    probability: number
    triggers: string[]
  }>

  /** behavioral matches between reviewer profiles */
  behavioralMatches: Array<{
    profileA: string
    profileB: string
    similarity: number
    sharedTraits: string[]
  }>

  /** timing analysis */
  timingAnalysis: {
    likelyCoordinated: boolean
    confidence: number
    reason: string
  } | null

  /** competitor domain investigation (if applicable) */
  competitorInvestigation: {
    domain: string
    platform: string | null
    sharedInfrastructure: string[]
  } | null

  /** all attribution signals */
  signals: Signal[]

  /** anonymity assessment */
  anonymity: {
    priorBits: number
    remainingBits: number
    anonymitySet: number
    identified: boolean
  }

  /** evidence fusion */
  attribution: {
    belief: number
    plausibility: number
    conflict: number
    level: string
  }

  /** attribution graph */
  graph: AttributionGraph

  /** graph in DOT format */
  graphDot: string
}

/**
 * Run a full review attack investigation.
 */
export async function investigateReviewAttack(
  input: ReviewAttackInput,
): Promise<ReviewAttackResult> {
  const startedAt = new Date().toISOString()
  const allSignals: Signal[] = []
  const label = `review-attack-${input.businessName.toLowerCase().replace(/\s+/g, '-')}`

  // ── Phase 1: Review analysis ──────────────────────────────────
  const reviewResult = analyzeReviews(input.businessName, input.reviews)
  allSignals.push(...reviewResult.signals)

  // ── Phase 2: AI detection on all reviews ──────────────────────
  const aiDetection: ReviewAttackResult['aiDetection'] = []
  let aiDetectedCount = 0

  for (const review of input.reviews) {
    if (review.text.length > 40) {
      const aiResult = detectAiText(review.text)
      aiDetection.push({
        author: review.authorName,
        verdict: aiResult.verdict,
        probability: aiResult.aiProbability,
        triggers: aiResult.triggers,
      })
      if (aiResult.verdict === 'likely_ai') {
        aiDetectedCount++
        allSignals.push({
          source: 'ai_detection',
          observation: `review by "${review.authorName}" likely AI-generated (p=${aiResult.aiProbability.toFixed(2)}, ${aiResult.triggers.length} triggers)`,
          score: aiResult.aiProbability,
          confidence: aiResult.confidence,
          informationBits: 3.0,
          rawData: JSON.stringify(aiResult),
          sourceUrl: `ai-detection:${review.authorName}`,
        })
      }
    }
  }

  // ── Phase 3: Stylometry cross-comparison ──────────────────────
  const stylometryMatches: ReviewAttackResult['stylometryMatches'] = []
  const suspiciousReviews = input.reviews.filter(r => r.text.length > 50)

  for (let i = 0; i < suspiciousReviews.length; i++) {
    for (let j = i + 1; j < suspiciousReviews.length; j++) {
      const cmp = compareWriteprints(suspiciousReviews[i].text, suspiciousReviews[j].text)
      if (cmp.similarity > 0.65) {
        stylometryMatches.push({
          authorA: suspiciousReviews[i].authorName,
          authorB: suspiciousReviews[j].authorName,
          similarity: cmp.similarity,
        })
        allSignals.push({
          source: 'stylometry',
          observation: `"${suspiciousReviews[i].authorName}" and "${suspiciousReviews[j].authorName}" have similar writing style (${cmp.similarity.toFixed(3)})`,
          score: cmp.similarity,
          confidence: 0.55,
          informationBits: 4.0,
          rawData: JSON.stringify(cmp),
          sourceUrl: `stylometry:${suspiciousReviews[i].authorName}+${suspiciousReviews[j].authorName}`,
        })
      }
    }
  }

  // ── Phase 4: Timing analysis ──────────────────────────────────
  const timestamps = input.reviews
    .map(r => r.timestamp)
    .filter((t): t is number => t !== null)

  let timingAnalysis: ReviewAttackResult['timingAnalysis'] = null
  if (timestamps.length >= 4) {
    const timing = detectCoordination(timestamps)
    timingAnalysis = {
      likelyCoordinated: timing.likelyCoordinated,
      confidence: timing.confidence,
      reason: timing.reason,
    }
    if (timing.likelyCoordinated) {
      allSignals.push({
        source: 'timing',
        observation: `review timing shows coordination: ${timing.reason}`,
        score: 0.7,
        confidence: timing.confidence,
        informationBits: 3.0,
        rawData: JSON.stringify(timing),
        sourceUrl: 'timing-analysis',
      })
    }
  }

  // ── Phase 5: Reviewer profile analysis ────────────────────────
  const behavioralMatches: ReviewAttackResult['behavioralMatches'] = []

  if (input.reviewerProfiles && input.reviewerProfiles.length >= 2) {
    const analyses = input.reviewerProfiles.map(p => analyzeReviewerProfile(p))

    for (const a of analyses) {
      allSignals.push(...a.signals)
    }

    for (let i = 0; i < analyses.length; i++) {
      for (let j = i + 1; j < analyses.length; j++) {
        const cmp = compareReviewerBehavior(analyses[i], analyses[j])
        if (cmp.similarity > 0.4) {
          behavioralMatches.push({
            profileA: analyses[i].displayName,
            profileB: analyses[j].displayName,
            similarity: cmp.similarity,
            sharedTraits: cmp.sharedTraits,
          })
          allSignals.push({
            source: 'reviewer_behavior',
            observation: `"${analyses[i].displayName}" and "${analyses[j].displayName}" show similar behavior (${cmp.similarity.toFixed(3)})`,
            score: cmp.similarity,
            confidence: 0.60,
            informationBits: 3.5,
            rawData: JSON.stringify(cmp),
            sourceUrl: `behavior:${analyses[i].displayName}+${analyses[j].displayName}`,
          })
        }
      }
    }
  }

  // ── Phase 6: Competitor investigation ─────────────────────────
  let competitorInvestigation: ReviewAttackResult['competitorInvestigation'] = null

  if (input.suspectedCompetitorDomain) {
    const [compDns, compHeaders] = await Promise.allSettled([
      collectDns(input.suspectedCompetitorDomain),
      collectHeaders(input.suspectedCompetitorDomain),
    ])

    const sharedInfra: string[] = []

    // check for shared infrastructure with victim's domain
    if (input.businessDomain && compDns.status === 'fulfilled') {
      const victimDns = await collectDns(input.businessDomain).catch(() => null)
      if (victimDns) {
        // shared nameservers
        const sharedNs = compDns.value.data.ns.filter(ns => victimDns.data.ns.includes(ns))
        if (sharedNs.length > 0) sharedInfra.push(`shared NS: ${sharedNs.join(', ')}`)

        // shared IPs
        const sharedIps = compDns.value.data.a.filter(ip => victimDns.data.a.includes(ip))
        if (sharedIps.length > 0) sharedInfra.push(`shared IP: ${sharedIps.join(', ')}`)
      }
    }

    competitorInvestigation = {
      domain: input.suspectedCompetitorDomain,
      platform: compHeaders.status === 'fulfilled' ? compHeaders.value.data.platform : null,
      sharedInfrastructure: sharedInfra,
    }
  }

  // ── Phase 7: Compute results ──────────────────────────────────
  const population = input.population ?? POPULATION.uk
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

  // ── Phase 8: Build graph ──────────────────────────────────────
  const nodes: GraphNode[] = [
    { id: input.businessName, type: 'domain', label: input.businessName },
  ]
  const edges: GraphEdge[] = []

  // add reviewer nodes
  for (const review of reviewResult.data.suspiciousReviews) {
    const reviewerId = `reviewer:${review.review.authorName}`
    if (!nodes.find(n => n.id === reviewerId)) {
      nodes.push({ id: reviewerId, type: 'review_profile', label: review.review.authorName })
      edges.push({ source: reviewerId, target: input.businessName, type: 'reviewed_by', weight: review.suspicionScore })
    }
  }

  // add stylometry links
  for (const match of stylometryMatches) {
    edges.push({
      source: `reviewer:${match.authorA}`,
      target: `reviewer:${match.authorB}`,
      type: 'writing_match',
      weight: match.similarity,
      evidence: `stylometry: ${match.similarity.toFixed(3)}`,
    })
  }

  // add competitor node
  if (input.suspectedCompetitorDomain) {
    nodes.push({ id: input.suspectedCompetitorDomain, type: 'domain', label: input.suspectedCompetitorDomain })
    edges.push({ source: input.suspectedCompetitorDomain, target: input.businessName, type: 'linked_to', weight: 0.5, evidence: 'suspected competitor' })
  }

  const graph: AttributionGraph = { nodes, edges }
  const graphDot = toDot(graph, { title: `trace: ${label}` })

  return {
    label,
    startedAt,
    completedAt: new Date().toISOString(),
    reviewAnalysis: {
      totalReviews: input.reviews.length,
      suspiciousCount: reviewResult.data.suspiciousReviews.length,
      aiDetectedCount,
      burstGroups: reviewResult.data.timingAnalysis.burstGroups.length,
    },
    stylometryMatches,
    aiDetection,
    behavioralMatches,
    timingAnalysis,
    competitorInvestigation,
    signals: allSignals,
    anonymity: {
      priorBits: anonymity.priorBits,
      remainingBits: anonymity.remainingBits,
      anonymitySet: Math.round(anonymity.anonymitySet),
      identified: anonymity.identified,
    },
    attribution: {
      belief: attribution.belief,
      plausibility: attribution.plausibility,
      conflict: attribution.conflict,
      level: attribution.level,
    },
    graph,
    graphDot,
  }
}
