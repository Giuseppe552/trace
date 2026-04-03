import { describe, it, expect } from 'vitest'
import { analyzeReviews, type GoogleReview } from '../src/reviews/google.js'

function makeReview(overrides: Partial<GoogleReview> = {}): GoogleReview {
  return {
    authorName: 'Test User',
    authorUrl: null,
    authorPhoto: null,
    rating: 4,
    text: 'Good service, helped us with the documents quickly.',
    time: '2 months ago',
    timestamp: Date.now() - 60 * 86400 * 1000,
    language: 'en',
    ...overrides,
  }
}

const LEGITIMATE_REVIEWS: GoogleReview[] = [
  makeReview({ authorName: 'Sarah M', rating: 5, text: 'Excellent service from start to finish. They handled our citizenship application with great care and kept us informed at every stage. The team was very knowledgeable about the Italian consulate requirements.', timestamp: Date.now() - 90 * 86400000 }),
  makeReview({ authorName: 'James W', rating: 4, text: 'Professional and efficient. Minor communication delay but overall very happy with the outcome.', timestamp: Date.now() - 75 * 86400000 }),
  makeReview({ authorName: 'Maria G', rating: 5, text: 'My family used their translation service and it was perfect. The certified translator understood exactly what was needed for the comune in Italy.', timestamp: Date.now() - 50 * 86400000 }),
  makeReview({ authorName: 'David K', rating: 3, text: 'Service was ok but took longer than expected. Would have appreciated more proactive updates.', timestamp: Date.now() - 30 * 86400000 }),
  makeReview({ authorName: 'Emma L', rating: 5, text: 'Cannot recommend enough. After struggling with the process for two years on our own, they sorted everything in four months.', timestamp: Date.now() - 15 * 86400000 }),
]

const SUSPICIOUS_REVIEWS: GoogleReview[] = [
  // generic attack with competitor mention
  makeReview({ authorName: 'Reviewer123', rating: 1, text: 'Terrible. Go to CompetitorAgency instead, much better.', timestamp: Date.now() - 2 * 86400000 }),
  // very short, no substance
  makeReview({ authorName: 'Anonymous', rating: 1, text: 'Scam', timestamp: Date.now() - 2 * 86400000 + 3600000 }),
  // generic praise (potential fake positive)
  makeReview({ authorName: 'John', rating: 5, text: 'Best ever!', timestamp: Date.now() - 2 * 86400000 + 7200000 }),
  // another short attack
  makeReview({ authorName: 'Jane D', rating: 1, text: 'Stay away from this company. Fraud.', timestamp: Date.now() - 2 * 86400000 + 10800000 }),
]

describe('analyzeReviews', () => {
  it('returns correct review count', () => {
    const result = analyzeReviews('Test Business', LEGITIMATE_REVIEWS)
    expect(result.data.reviews.length).toBe(5)
  })

  it('flags suspicious reviews', () => {
    const result = analyzeReviews('Test Business', SUSPICIOUS_REVIEWS)
    expect(result.data.suspiciousReviews.length).toBeGreaterThan(0)
  })

  it('flags competitor mentions', () => {
    const result = analyzeReviews('Test Business', SUSPICIOUS_REVIEWS)
    const competitorFlag = result.data.suspiciousReviews.find(r =>
      r.flags.includes('competitor_mention'),
    )
    expect(competitorFlag).toBeDefined()
    expect(competitorFlag!.review.authorName).toBe('Reviewer123')
  })

  it('flags very short reviews', () => {
    const result = analyzeReviews('Test Business', SUSPICIOUS_REVIEWS)
    const shortFlag = result.data.suspiciousReviews.find(r =>
      r.flags.includes('very_short_text') && r.review.text === 'Scam',
    )
    expect(shortFlag).toBeDefined()
  })

  it('flags generic praise/attack', () => {
    const result = analyzeReviews('Test Business', SUSPICIOUS_REVIEWS)
    const genericFlags = result.data.suspiciousReviews.filter(r =>
      r.flags.includes('generic_praise_or_attack'),
    )
    expect(genericFlags.length).toBeGreaterThan(0)
  })

  it('does not flag legitimate detailed reviews', () => {
    const result = analyzeReviews('Test Business', LEGITIMATE_REVIEWS)
    // legitimate reviews should have very few flags
    const flaggedCount = result.data.suspiciousReviews.length
    expect(flaggedCount).toBeLessThanOrEqual(1) // maybe one borderline
  })

  it('detects review bursts', () => {
    const result = analyzeReviews('Test Business', SUSPICIOUS_REVIEWS)
    // 4 reviews within hours of each other
    expect(result.data.timingAnalysis.burstGroups.length).toBeGreaterThan(0)
    const burst = result.data.timingAnalysis.burstGroups[0]
    expect(burst.reviews.length).toBeGreaterThanOrEqual(3)
  })

  it('no burst in naturally spaced reviews', () => {
    const result = analyzeReviews('Test Business', LEGITIMATE_REVIEWS)
    // reviews spread over months
    expect(result.data.timingAnalysis.burstGroups.length).toBe(0)
  })

  it('generates signals for suspicious reviews', () => {
    const result = analyzeReviews('Test Business', SUSPICIOUS_REVIEWS)
    const suspicionSignal = result.signals.find(s =>
      s.observation.includes('suspicious'),
    )
    expect(suspicionSignal).toBeDefined()
    expect(suspicionSignal!.source).toBe('review_profile')
  })

  it('generates burst detection signal', () => {
    const result = analyzeReviews('Test Business', SUSPICIOUS_REVIEWS)
    const burstSignal = result.signals.find(s =>
      s.observation.includes('burst'),
    )
    expect(burstSignal).toBeDefined()
  })

  it('suspicion score ∈ [0, 1]', () => {
    const result = analyzeReviews('Test Business', [...LEGITIMATE_REVIEWS, ...SUSPICIOUS_REVIEWS])
    for (const sr of result.data.suspiciousReviews) {
      expect(sr.suspicionScore).toBeGreaterThanOrEqual(0)
      expect(sr.suspicionScore).toBeLessThanOrEqual(1)
    }
  })

  it('handles empty reviews array', () => {
    const result = analyzeReviews('Empty Business', [])
    expect(result.data.reviews.length).toBe(0)
    expect(result.data.suspiciousReviews.length).toBe(0)
    expect(result.signals.length).toBe(0)
  })
})
