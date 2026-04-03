/**
 * Google reviewer profile deep analysis.
 *
 * Given a reviewer's publicly visible profile data, builds an
 * intelligence picture: review patterns, geographic focus, category
 * distribution, timing behavior, Local Guide status.
 *
 * This module works on pre-collected data (from Google Maps HTML
 * or API). It does NOT scrape Google directly — that would violate
 * ToS and the Computer Misuse Act boundary we set.
 *
 * Input: reviewer's full review history (from browser inspection
 * or Maps API). Output: behavioral analysis + suspicion signals.
 *
 * Attribution value:
 * - Review history reveals geographic focus (city/region)
 * - Category patterns reveal industry (competitor if concentrated)
 * - Rating distribution reveals bias (normal ≈ 4.0 avg, attacker ≈ 1.0 or 5.0)
 * - Timing patterns reveal coordination or automation
 * - Account age vs review count reveals fake account indicators
 * - Cross-referencing reviewed businesses reveals the reviewer's orbit
 */

import { detectCoordination, type CoordinationResult } from '@trace/core'
import type { Signal } from '../types.js'

/** A reviewer's full profile as extracted from Google Maps */
export interface ReviewerProfileData {
  displayName: string
  profileUrl: string | null
  photoUrl: string | null
  isLocalGuide: boolean
  localGuideLevel: number | null
  totalReviews: number
  totalPhotos: number | null
  totalRatings: number | null
  /** all reviews this person has left across all businesses */
  reviews: ReviewEntry[]
}

/** A single review in a reviewer's history */
export interface ReviewEntry {
  businessName: string
  businessCategory: string | null
  businessCity: string | null
  rating: number
  text: string
  timestamp: number | null
}

/** Analysis result for a reviewer profile */
export interface ReviewerAnalysis {
  displayName: string
  /** how old is this account? (estimated from earliest review) */
  estimatedAccountAge: { days: number; label: string } | null
  /** average rating across all reviews */
  averageRating: number
  /** standard deviation of ratings */
  ratingStdDev: number
  /** distribution of ratings (1-5) */
  ratingDistribution: Record<number, number>
  /** is the rating distribution abnormal? (clustered at extremes) */
  ratingBias: 'extreme_negative' | 'extreme_positive' | 'balanced' | 'insufficient_data'
  /** cities/regions this reviewer focuses on */
  geographicFocus: Array<{ city: string; count: number; percentage: number }>
  /** business categories this reviewer focuses on */
  categoryFocus: Array<{ category: string; count: number; percentage: number }>
  /** is there suspicious concentration in one category? */
  categoryConcentration: boolean
  /** coordination analysis of review timing */
  timingAnalysis: CoordinationResult | null
  /** reviews per month rate */
  reviewsPerMonth: number | null
  /** ratio of reviews with text vs rating-only */
  textReviewRatio: number
  /** signals for attribution */
  signals: Signal[]
  /** red flags */
  flags: string[]
}

/**
 * Analyze a reviewer's profile and review history.
 */
export function analyzeReviewerProfile(profile: ReviewerProfileData): ReviewerAnalysis {
  const flags: string[] = []
  const signals: Signal[] = []
  const reviews = profile.reviews

  // rating analysis
  const ratings = reviews.map(r => r.rating)
  const averageRating = ratings.length > 0
    ? ratings.reduce((a, b) => a + b, 0) / ratings.length
    : 0
  const ratingStdDev = stdDev(ratings)

  const ratingDistribution: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 }
  for (const r of ratings) {
    ratingDistribution[r] = (ratingDistribution[r] ?? 0) + 1
  }

  // rating bias detection
  let ratingBias: ReviewerAnalysis['ratingBias'] = 'insufficient_data'
  if (ratings.length >= 5) {
    const extremeRatio = ((ratingDistribution[1] ?? 0) + (ratingDistribution[5] ?? 0)) / ratings.length
    if (averageRating <= 2.0 && extremeRatio > 0.7) {
      ratingBias = 'extreme_negative'
      flags.push(`extreme negative bias: avg ${averageRating.toFixed(1)}, ${((ratingDistribution[1] ?? 0) / ratings.length * 100).toFixed(0)}% are 1-star`)
    } else if (averageRating >= 4.5 && extremeRatio > 0.8) {
      ratingBias = 'extreme_positive'
      flags.push(`extreme positive bias: avg ${averageRating.toFixed(1)}, ${((ratingDistribution[5] ?? 0) / ratings.length * 100).toFixed(0)}% are 5-star`)
    } else {
      ratingBias = 'balanced'
    }
  }

  // geographic focus
  const cityCount = new Map<string, number>()
  for (const r of reviews) {
    if (r.businessCity) {
      const city = r.businessCity.toLowerCase().trim()
      cityCount.set(city, (cityCount.get(city) ?? 0) + 1)
    }
  }
  const geographicFocus = [...cityCount.entries()]
    .map(([city, count]) => ({ city, count, percentage: count / reviews.length * 100 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)

  // category focus
  const catCount = new Map<string, number>()
  for (const r of reviews) {
    if (r.businessCategory) {
      const cat = r.businessCategory.toLowerCase().trim()
      catCount.set(cat, (catCount.get(cat) ?? 0) + 1)
    }
  }
  const categoryFocus = [...catCount.entries()]
    .map(([category, count]) => ({ category, count, percentage: count / reviews.length * 100 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)

  // category concentration — if >60% of reviews are in one category, that's suspicious
  const categoryConcentration = categoryFocus.length > 0 && categoryFocus[0].percentage > 60
  if (categoryConcentration) {
    flags.push(`${categoryFocus[0].percentage.toFixed(0)}% of reviews target "${categoryFocus[0].category}" businesses`)
  }

  // timing analysis
  const timestamps = reviews
    .map(r => r.timestamp)
    .filter((t): t is number => t !== null)
  const timingAnalysis = timestamps.length >= 4
    ? detectCoordination(timestamps)
    : null

  if (timingAnalysis?.likelyCoordinated) {
    flags.push(`review timing shows coordination (KS p=${timingAnalysis.ksExponential.pValue.toFixed(4)}, CV=${timingAnalysis.cv.toFixed(3)})`)
  }

  // account age
  let estimatedAccountAge: ReviewerAnalysis['estimatedAccountAge'] = null
  if (timestamps.length > 0) {
    const earliest = Math.min(...timestamps)
    const days = Math.floor((Date.now() - earliest) / (86400 * 1000))
    const label = days < 30 ? 'very new' : days < 90 ? 'new' : days < 365 ? 'moderate' : 'established'
    estimatedAccountAge = { days, label }

    if (days < 30 && reviews.length > 5) {
      flags.push(`very new account (${days} days) with ${reviews.length} reviews — possible purchased account`)
    }
  }

  // reviews per month
  let reviewsPerMonth: number | null = null
  if (estimatedAccountAge && estimatedAccountAge.days > 0) {
    reviewsPerMonth = reviews.length / (estimatedAccountAge.days / 30)
    if (reviewsPerMonth > 15) {
      flags.push(`unusually high review rate: ${reviewsPerMonth.toFixed(1)} per month`)
    }
  }

  // text review ratio
  const textReviews = reviews.filter(r => r.text.length > 10).length
  const textReviewRatio = reviews.length > 0 ? textReviews / reviews.length : 0

  if (textReviewRatio < 0.2 && reviews.length > 5) {
    flags.push(`low text ratio: only ${(textReviewRatio * 100).toFixed(0)}% of reviews have text (rating-only accounts are often fake)`)
  }

  // Local Guide check — real users often have this, fake accounts rarely do
  if (!profile.isLocalGuide && reviews.length > 20) {
    flags.push('not a Local Guide despite 20+ reviews (unusual for legitimate reviewer)')
  }

  // build signals
  if (flags.length > 0) {
    signals.push({
      source: 'reviewer_profile',
      observation: `${flags.length} red flags on reviewer "${profile.displayName}": ${flags.join('; ')}`,
      score: Math.min(1, flags.length * 0.2),
      confidence: 0.65,
      informationBits: Math.min(5, flags.length * 1.5),
      rawData: JSON.stringify({ flags, ratingBias, categoryConcentration, reviewsPerMonth }),
      sourceUrl: profile.profileUrl ?? `reviewer:${profile.displayName}`,
    })
  }

  if (geographicFocus.length > 0 && geographicFocus[0].percentage > 50) {
    signals.push({
      source: 'reviewer_profile',
      observation: `reviewer concentrated in ${geographicFocus[0].city} (${geographicFocus[0].percentage.toFixed(0)}% of reviews)`,
      score: 0.5,
      confidence: 0.70,
      informationBits: 3.0,
      rawData: JSON.stringify(geographicFocus),
      sourceUrl: profile.profileUrl ?? `reviewer:${profile.displayName}`,
    })
  }

  return {
    displayName: profile.displayName,
    estimatedAccountAge,
    averageRating,
    ratingStdDev,
    ratingDistribution,
    ratingBias,
    geographicFocus,
    categoryFocus,
    categoryConcentration,
    timingAnalysis,
    reviewsPerMonth,
    textReviewRatio,
    signals,
    flags,
  }
}

/**
 * Compare two reviewer profiles for behavioral similarity.
 *
 * If two "different" reviewers have similar rating distributions,
 * similar geographic focus, and similar timing patterns, they may
 * be the same person operating multiple accounts.
 */
export function compareReviewerBehavior(
  a: ReviewerAnalysis,
  b: ReviewerAnalysis,
): { similarity: number; sharedTraits: string[] } {
  const sharedTraits: string[] = []
  let score = 0
  let maxScore = 0

  // rating distribution similarity (Jensen-Shannon divergence)
  const aDist = normalizeDistribution(a.ratingDistribution)
  const bDist = normalizeDistribution(b.ratingDistribution)
  const ratingJsd = jsd(aDist, bDist)
  if (ratingJsd < 0.1) {
    score += 0.3
    sharedTraits.push(`similar rating patterns (JSD=${ratingJsd.toFixed(3)})`)
  }
  maxScore += 0.3

  // geographic overlap
  const aCities = new Set(a.geographicFocus.map(g => g.city))
  const bCities = new Set(b.geographicFocus.map(g => g.city))
  const sharedCities = [...aCities].filter(c => bCities.has(c))
  if (sharedCities.length > 0) {
    score += 0.25
    sharedTraits.push(`shared geographic focus: ${sharedCities.join(', ')}`)
  }
  maxScore += 0.25

  // category overlap
  const aCats = new Set(a.categoryFocus.map(c => c.category))
  const bCats = new Set(b.categoryFocus.map(c => c.category))
  const sharedCats = [...aCats].filter(c => bCats.has(c))
  if (sharedCats.length > 0) {
    score += 0.25
    sharedTraits.push(`shared category focus: ${sharedCats.join(', ')}`)
  }
  maxScore += 0.25

  // similar review rate
  if (a.reviewsPerMonth && b.reviewsPerMonth) {
    const rateRatio = Math.min(a.reviewsPerMonth, b.reviewsPerMonth) / Math.max(a.reviewsPerMonth, b.reviewsPerMonth)
    if (rateRatio > 0.7) {
      score += 0.1
      sharedTraits.push(`similar review rate (${a.reviewsPerMonth.toFixed(1)} vs ${b.reviewsPerMonth.toFixed(1)} per month)`)
    }
  }
  maxScore += 0.1

  // both have same rating bias
  if (a.ratingBias === b.ratingBias && a.ratingBias !== 'balanced' && a.ratingBias !== 'insufficient_data') {
    score += 0.1
    sharedTraits.push(`both show ${a.ratingBias} rating bias`)
  }
  maxScore += 0.1

  return { similarity: maxScore > 0 ? score / maxScore : 0, sharedTraits }
}

function stdDev(values: number[]): number {
  if (values.length < 2) return 0
  const mean = values.reduce((a, b) => a + b, 0) / values.length
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (values.length - 1)
  return Math.sqrt(variance)
}

function normalizeDistribution(dist: Record<number, number>): number[] {
  const values = [1, 2, 3, 4, 5].map(k => dist[k] ?? 0)
  const sum = values.reduce((a, b) => a + b, 0)
  return sum > 0 ? values.map(v => v / sum) : values.map(() => 0.2)
}

function jsd(p: number[], q: number[]): number {
  const m = p.map((pi, i) => (pi + q[i]) / 2)
  return (kl(p, m) + kl(q, m)) / 2
}

function kl(p: number[], q: number[]): number {
  let sum = 0
  for (let i = 0; i < p.length; i++) {
    if (p[i] > 0 && q[i] > 0) {
      sum += p[i] * Math.log2(p[i] / q[i])
    }
  }
  return sum
}
