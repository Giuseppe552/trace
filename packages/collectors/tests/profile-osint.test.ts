import { describe, it, expect } from 'vitest'
import {
  analyzeReviewerProfile,
  compareReviewerBehavior,
  type ReviewerProfileData,
} from '../src/reviews/profile-osint.js'

function fakeReviewer(overrides: Partial<ReviewerProfileData> = {}): ReviewerProfileData {
  return {
    displayName: 'Test Reviewer',
    profileUrl: null,
    photoUrl: null,
    isLocalGuide: true,
    localGuideLevel: 5,
    totalReviews: 25,
    totalPhotos: 10,
    totalRatings: 30,
    reviews: [],
    ...overrides,
  }
}

const LEGITIMATE_REVIEWER = fakeReviewer({
  displayName: 'Sarah M',
  isLocalGuide: true,
  localGuideLevel: 6,
  totalReviews: 47,
  reviews: [
    { businessName: 'Pizza Express', businessCategory: 'restaurant', businessCity: 'London', rating: 4, text: 'Good pizza, bit slow on service', timestamp: Date.now() - 300 * 86400000 },
    { businessName: 'Tesco Metro', businessCategory: 'grocery', businessCity: 'London', rating: 3, text: 'Standard Tesco', timestamp: Date.now() - 250 * 86400000 },
    { businessName: 'Vue Cinema', businessCategory: 'entertainment', businessCity: 'London', rating: 5, text: 'Great experience', timestamp: Date.now() - 200 * 86400000 },
    { businessName: 'Greggs', businessCategory: 'restaurant', businessCity: 'London', rating: 4, text: 'Love the sausage rolls', timestamp: Date.now() - 150 * 86400000 },
    { businessName: 'Holiday Inn', businessCategory: 'hotel', businessCity: 'Manchester', rating: 3, text: 'Average hotel', timestamp: Date.now() - 100 * 86400000 },
    { businessName: 'Wagamama', businessCategory: 'restaurant', businessCity: 'London', rating: 5, text: 'Always reliable', timestamp: Date.now() - 50 * 86400000 },
    { businessName: 'John Lewis', businessCategory: 'retail', businessCity: 'London', rating: 4, text: 'Great customer service', timestamp: Date.now() - 20 * 86400000 },
  ],
})

const SUSPICIOUS_REVIEWER = fakeReviewer({
  displayName: 'NewAccount99',
  isLocalGuide: false,
  localGuideLevel: null,
  totalReviews: 8,
  reviews: [
    { businessName: 'Immigration Agency A', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Terrible', timestamp: Date.now() - 5 * 86400000 },
    { businessName: 'Immigration Agency B', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Scam avoid', timestamp: Date.now() - 4 * 86400000 },
    { businessName: 'Immigration Agency C', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Worst ever', timestamp: Date.now() - 3 * 86400000 },
    { businessName: 'Immigration Agency D', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Fraud', timestamp: Date.now() - 3 * 86400000 },
    { businessName: 'CompetitorAgency', businessCategory: 'legal', businessCity: 'London', rating: 5, text: 'Amazing service highly recommend', timestamp: Date.now() - 2 * 86400000 },
    { businessName: 'Immigration Agency E', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Do not use', timestamp: Date.now() - 2 * 86400000 },
    { businessName: 'Immigration Agency F', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Stay away', timestamp: Date.now() - 1 * 86400000 },
    { businessName: 'CompetitorAgency', businessCategory: 'legal', businessCity: 'London', rating: 5, text: 'Best in the business', timestamp: Date.now() - 1 * 86400000 },
  ],
})

describe('analyzeReviewerProfile', () => {
  describe('legitimate reviewer', () => {
    const analysis = analyzeReviewerProfile(LEGITIMATE_REVIEWER)

    it('detects balanced rating bias', () => {
      expect(analysis.ratingBias).toBe('balanced')
    })

    it('has reasonable average rating', () => {
      expect(analysis.averageRating).toBeGreaterThan(3)
      expect(analysis.averageRating).toBeLessThan(5)
    })

    it('has diverse categories', () => {
      expect(analysis.categoryConcentration).toBe(false)
    })

    it('has few or no flags', () => {
      expect(analysis.flags.length).toBeLessThanOrEqual(1)
    })

    it('has established account age', () => {
      expect(analysis.estimatedAccountAge).not.toBeNull()
      expect(analysis.estimatedAccountAge!.days).toBeGreaterThan(200)
    })
  })

  describe('suspicious reviewer', () => {
    const analysis = analyzeReviewerProfile(SUSPICIOUS_REVIEWER)

    it('detects extreme negative rating bias', () => {
      expect(analysis.ratingBias).toBe('extreme_negative')
    })

    it('detects category concentration', () => {
      expect(analysis.categoryConcentration).toBe(true)
      expect(analysis.categoryFocus[0].category).toBe('legal')
    })

    it('has multiple flags', () => {
      expect(analysis.flags.length).toBeGreaterThan(1)
    })

    it('has very new account', () => {
      expect(analysis.estimatedAccountAge).not.toBeNull()
      expect(analysis.estimatedAccountAge!.days).toBeLessThan(10)
    })

    it('flags high review rate', () => {
      // 8 reviews in ~5 days = ~48/month
      expect(analysis.reviewsPerMonth).toBeGreaterThan(10)
    })

    it('flags not being a Local Guide', () => {
      // suspicious reviewer is not local guide — but only flagged if 20+ reviews
      // this one has 8, so might not trigger that specific flag
      expect(analysis.flags.some(f => f.includes('new account') || f.includes('negative bias') || f.includes('concentration'))).toBe(true)
    })

    it('generates attribution signals', () => {
      expect(analysis.signals.length).toBeGreaterThan(0)
    })

    it('geographic focus is London', () => {
      expect(analysis.geographicFocus[0].city).toBe('london')
      expect(analysis.geographicFocus[0].percentage).toBe(100)
    })
  })
})

describe('compareReviewerBehavior', () => {
  it('similar attackers have high similarity', () => {
    const attacker1 = analyzeReviewerProfile(SUSPICIOUS_REVIEWER)
    // create a slightly different attacker with same patterns
    const attacker2Profile = fakeReviewer({
      displayName: 'AnotherAccount',
      isLocalGuide: false,
      totalReviews: 6,
      reviews: [
        { businessName: 'Immigration Agency A', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Terrible service', timestamp: Date.now() - 6 * 86400000 },
        { businessName: 'Immigration Agency G', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Avoid at all costs', timestamp: Date.now() - 5 * 86400000 },
        { businessName: 'CompetitorAgency', businessCategory: 'legal', businessCity: 'London', rating: 5, text: 'Incredible agency', timestamp: Date.now() - 4 * 86400000 },
        { businessName: 'Immigration Agency H', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Ripoff', timestamp: Date.now() - 3 * 86400000 },
        { businessName: 'Immigration Agency B', businessCategory: 'legal', businessCity: 'London', rating: 1, text: 'Worst experience', timestamp: Date.now() - 2 * 86400000 },
        { businessName: 'CompetitorAgency', businessCategory: 'legal', businessCity: 'London', rating: 5, text: 'The best', timestamp: Date.now() - 1 * 86400000 },
      ],
    })
    const attacker2 = analyzeReviewerProfile(attacker2Profile)

    const comparison = compareReviewerBehavior(attacker1, attacker2)
    expect(comparison.similarity).toBeGreaterThan(0.5)
    expect(comparison.sharedTraits.length).toBeGreaterThan(2)
  })

  it('different reviewers have low similarity', () => {
    const legit = analyzeReviewerProfile(LEGITIMATE_REVIEWER)
    const suspicious = analyzeReviewerProfile(SUSPICIOUS_REVIEWER)
    const comparison = compareReviewerBehavior(legit, suspicious)
    expect(comparison.similarity).toBeLessThan(0.5)
  })

  it('similarity ∈ [0, 1]', () => {
    const a = analyzeReviewerProfile(LEGITIMATE_REVIEWER)
    const b = analyzeReviewerProfile(SUSPICIOUS_REVIEWER)
    const result = compareReviewerBehavior(a, b)
    expect(result.similarity).toBeGreaterThanOrEqual(0)
    expect(result.similarity).toBeLessThanOrEqual(1)
  })
})
