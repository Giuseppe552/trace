/**
 * Google Maps review profile OSINT collector.
 *
 * Given a Google Maps Place ID or business name, extracts:
 * - All reviews with full text, dates, ratings, reviewer info
 * - Reviewer profile data: name, other reviews, photo URL
 * - Review timing patterns for coordination detection
 *
 * Two modes:
 * 1. Google Places API (requires API key, structured data, limited to 5 reviews)
 * 2. SerpApi Google Maps Reviews (paid, full review extraction)
 *
 * For OSINT without API keys, this module also provides manual
 * review data ingestion (paste JSON from browser inspection).
 *
 * Attribution value:
 * - Reviewer's other reviews → pattern of targeting competitors?
 * - Profile name → social media correlation
 * - Review timing → KS test for coordination
 * - Review text → stylometry comparison with suspect's known writing
 */

import type { CollectorResult, Signal } from '../types.js'
import { detectAiText } from '@trace/core'

/** A single Google review */
export interface GoogleReview {
  /** reviewer display name */
  authorName: string
  /** reviewer profile URL (Google Maps contributor) */
  authorUrl: string | null
  /** reviewer profile photo URL */
  authorPhoto: string | null
  /** star rating (1-5) */
  rating: number
  /** review text */
  text: string
  /** when the review was posted (ISO 8601 or relative like "2 months ago") */
  time: string
  /** Unix timestamp if available */
  timestamp: number | null
  /** language of the review */
  language: string | null
}

/** A reviewer's profile (aggregated from their public reviews) */
export interface ReviewerProfile {
  name: string
  /** total number of reviews they've left */
  totalReviews: number | null
  /** other businesses they've reviewed */
  otherReviews: GoogleReview[]
  /** photo URL */
  photoUrl: string | null
  /** Google Maps contributor URL */
  profileUrl: string | null
  /** are they a "Local Guide"? */
  isLocalGuide: boolean
  /** level if Local Guide */
  localGuideLevel: number | null
}

/** Result from review collection */
export interface ReviewCollectionResult {
  /** business name */
  businessName: string
  /** Google Place ID if known */
  placeId: string | null
  /** all reviews collected */
  reviews: GoogleReview[]
  /** suspicious reviews flagged */
  suspiciousReviews: SuspiciousReview[]
  /** reviewer profiles analyzed */
  reviewerProfiles: ReviewerProfile[]
  /** timing analysis across all reviews */
  timingAnalysis: {
    totalReviews: number
    timestamps: number[]
    /** reviews that came in bursts (within 24h of each other) */
    burstGroups: Array<{ reviews: GoogleReview[]; windowHours: number }>
  }
}

/** A review flagged as suspicious with reasons */
export interface SuspiciousReview {
  review: GoogleReview
  flags: string[]
  suspicionScore: number // 0-1
}

/** Suspicion heuristics */
const SUSPICION_RULES: Array<{
  name: string
  test: (review: GoogleReview, allReviews: GoogleReview[]) => boolean
  weight: number
}> = [
  {
    name: 'single_review_account',
    test: (_review, _all) => false, // needs profile data — set in analyzeReviews
    weight: 0.3,
  },
  {
    name: 'extreme_rating_no_text',
    test: (review) => (review.rating === 1 || review.rating === 5) && review.text.length < 20,
    weight: 0.4,
  },
  {
    name: 'very_short_text',
    test: (review) => review.text.length > 0 && review.text.length < 30,
    weight: 0.2,
  },
  {
    name: 'competitor_mention',
    test: (review) => {
      const lower = review.text.toLowerCase()
      return /better|instead|go to|recommend .+ instead|try .+ instead|use .+ instead/.test(lower)
    },
    weight: 0.5,
  },
  {
    name: 'generic_praise_or_attack',
    test: (review) => {
      const lower = review.text.toLowerCase()
      const generic = ['great service', 'terrible service', 'worst ever', 'best ever',
        'highly recommend', 'do not recommend', 'stay away', 'scam', 'fraud', 'rip off']
      return generic.some(phrase => lower.includes(phrase)) && review.text.length < 100
    },
    weight: 0.35,
  },
]

/**
 * Analyze a set of reviews for suspicious patterns.
 *
 * This is the manual-ingestion path: paste review data as JSON
 * (extracted from browser devtools or Google Maps HTML).
 */
export function analyzeReviews(
  businessName: string,
  reviews: GoogleReview[],
  placeId?: string,
): CollectorResult<ReviewCollectionResult> {
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  // flag suspicious reviews
  const suspiciousReviews: SuspiciousReview[] = []
  for (const review of reviews) {
    const flags: string[] = []
    let score = 0

    for (const rule of SUSPICION_RULES) {
      if (rule.test(review, reviews)) {
        flags.push(rule.name)
        score += rule.weight
      }
    }

    if (flags.length > 0) {
      suspiciousReviews.push({
        review,
        flags,
        suspicionScore: Math.min(score, 1),
      })
    }
  }

  // AI detection on suspicious reviews
  for (const sr of suspiciousReviews) {
    if (sr.review.text.length > 50) {
      const aiResult = detectAiText(sr.review.text)
      if (aiResult.verdict === 'likely_ai') {
        sr.flags.push('likely_ai_generated')
        sr.suspicionScore = Math.min(1, sr.suspicionScore + 0.3)
      }
    }
  }

  // also check all reviews for AI patterns (not just flagged ones)
  for (const review of reviews) {
    if (review.text.length > 75) {
      const aiResult = detectAiText(review.text)
      if (aiResult.verdict === 'likely_ai') {
        const existing = suspiciousReviews.find(sr => sr.review === review)
        if (!existing) {
          suspiciousReviews.push({
            review,
            flags: ['likely_ai_generated'],
            suspicionScore: 0.4,
          })
        }
      }
    }
  }

  // timing analysis
  const timestamps = reviews
    .map(r => r.timestamp)
    .filter((t): t is number => t !== null)
    .sort((a, b) => a - b)

  // find burst groups (reviews within 24h of each other)
  const burstGroups: ReviewCollectionResult['timingAnalysis']['burstGroups'] = []
  const WINDOW_MS = 24 * 60 * 60 * 1000

  let currentBurst: GoogleReview[] = []
  const sortedByTime = reviews
    .filter(r => r.timestamp !== null)
    .sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0))

  for (const review of sortedByTime) {
    if (currentBurst.length === 0) {
      currentBurst.push(review)
    } else {
      const lastTime = currentBurst[currentBurst.length - 1].timestamp ?? 0
      if ((review.timestamp ?? 0) - lastTime <= WINDOW_MS) {
        currentBurst.push(review)
      } else {
        if (currentBurst.length >= 3) {
          burstGroups.push({ reviews: [...currentBurst], windowHours: 24 })
        }
        currentBurst = [review]
      }
    }
  }
  if (currentBurst.length >= 3) {
    burstGroups.push({ reviews: [...currentBurst], windowHours: 24 })
  }

  const data: ReviewCollectionResult = {
    businessName,
    placeId: placeId ?? null,
    reviews,
    suspiciousReviews,
    reviewerProfiles: [],
    timingAnalysis: {
      totalReviews: reviews.length,
      timestamps,
      burstGroups,
    },
  }

  // build signals
  const signals: Signal[] = []

  if (suspiciousReviews.length > 0) {
    const avgSuspicion = suspiciousReviews.reduce((s, r) => s + r.suspicionScore, 0) / suspiciousReviews.length
    signals.push({
      source: 'review_profile',
      observation: `${suspiciousReviews.length}/${reviews.length} reviews flagged as suspicious (avg score: ${avgSuspicion.toFixed(2)})`,
      score: avgSuspicion,
      confidence: 0.60,
      informationBits: Math.log2(reviews.length / Math.max(suspiciousReviews.length, 1)),
      rawData: JSON.stringify(suspiciousReviews.map(r => ({ author: r.review.authorName, flags: r.flags, score: r.suspicionScore }))),
      sourceUrl: `google-maps:${businessName}`,
    })
  }

  if (burstGroups.length > 0) {
    const totalBurstReviews = burstGroups.reduce((s, g) => s + g.reviews.length, 0)
    signals.push({
      source: 'review_profile',
      observation: `${burstGroups.length} review burst(s) detected: ${totalBurstReviews} reviews in 24h windows`,
      score: 0.65,
      confidence: 0.55,
      informationBits: 2.0,
      rawData: JSON.stringify(burstGroups.map(g => ({ count: g.reviews.length, authors: g.reviews.map(r => r.authorName) }))),
      sourceUrl: `google-maps:${businessName}`,
    })
  }

  const oneStarCount = reviews.filter(r => r.rating === 1).length
  if (oneStarCount > 0) {
    signals.push({
      source: 'review_profile',
      observation: `${oneStarCount} one-star reviews out of ${reviews.length} total`,
      score: oneStarCount / reviews.length,
      confidence: 0.50,
      informationBits: 1.0,
      rawData: `${oneStarCount}/${reviews.length}`,
      sourceUrl: `google-maps:${businessName}`,
    })
  }

  const raw = JSON.stringify(data, null, 2)

  return {
    data,
    signals,
    raw,
    url: `google-maps:${businessName}`,
    collectedAt,
    warnings,
  }
}

/**
 * Compare a suspicious review's writing style against known samples.
 * Returns stylometric similarity per sample.
 *
 * Uses the core stylometry module — this is just a convenience wrapper.
 */
export function compareReviewToSamples(
  reviewText: string,
  knownSamples: Array<{ label: string; text: string }>,
): Array<{ label: string; similarity: number }> {
  // dynamic import to avoid circular dep at load time
  // the actual comparison uses @trace/core stylometry
  const { compareWriteprints } = require('@trace/core') as typeof import('@trace/core')

  return knownSamples.map(sample => ({
    label: sample.label,
    similarity: compareWriteprints(reviewText, sample.text).similarity,
  }))
}
