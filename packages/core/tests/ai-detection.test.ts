import { describe, it, expect } from 'vitest'
import { detectAiText, batchDetectAi } from '../src/stylometry/ai-detection.js'

// genuinely human-written: varied sentence length, idiosyncratic punctuation,
// natural speech patterns, messy structure
const HUMAN_REVIEW_1 = `Used them for my citizenship application. Took about 6 months which honestly felt like forever but they warned me upfront so can't complain. The translator was great — picked up on a weird discrepancy in my birth cert that I wouldn't have noticed. Only negative: their office is hard to find. Like genuinely confusing. I walked past it twice. But the actual service? Solid. Would use again for the passport appointment stuff.`

const HUMAN_REVIEW_2 = `Hmm. Mixed feelings. The translation was fine, accurate, all that. But the communication was... not great? I'd email and hear back 4-5 days later. For £300 I expected faster turnaround. The end result was good though and the consulate accepted everything first try, so maybe that's what matters. Three stars feels right.`

const HUMAN_REVIEW_3 = `DO NOT USE. They lost my original birth certificate. LOST IT. Took them 3 weeks to even admit it. Had to get a replacement from Italy which cost me €50 and delayed everything by two months. The manager was apologetic but that doesn't fix the problem does it? Still waiting for them to reimburse the replacement cost. Update: they did reimburse eventually. Bumping to 2 stars.`

// AI-characteristic: uniform sentence length, hedging, predictable structure,
// balanced vocabulary, transition words
const AI_REVIEW_1 = `I recently used their citizenship application service and found the experience to be quite satisfactory. The team demonstrated a thorough understanding of the requirements and guided me through each step of the process. Additionally, the translation service was accurate and well-presented. However, it is worth noting that the timeline was slightly longer than initially anticipated. Nevertheless, the overall quality of the work exceeded my expectations. I would recommend their services to anyone seeking assistance with Italian citizenship applications.`

const AI_REVIEW_2 = `This company provides an excellent service for those looking to navigate the complex process of obtaining Italian citizenship. The staff are knowledgeable and professional in their approach. Furthermore, the documentation was handled with great attention to detail. The pricing is reasonable considering the quality of service provided. Overall, I would highly recommend this company to anyone considering pursuing their Italian heritage. The entire experience was seamless and well-organized from start to finish.`

const AI_REVIEW_3 = `I had the pleasure of working with this agency for my citizenship application. The process was handled efficiently and professionally throughout. The team was responsive to my queries and provided clear explanations at every stage. Additionally, their knowledge of consulate requirements was impressive and thorough. However, I would suggest that they could improve their online booking system. Nevertheless, the final outcome was entirely satisfactory and I am grateful for their assistance. I would certainly recommend their services to others.`

// edge case: very short
const SHORT_TEXT = `Great service. Recommended.`

describe('detectAiText', () => {
  describe('human-written reviews', () => {
    it('classifies varied human writing as likely human', () => {
      const result = detectAiText(HUMAN_REVIEW_1)
      expect(result.verdict).not.toBe('likely_ai')
      expect(result.aiProbability).toBeLessThan(0.6)
    })

    it('classifies terse human writing as likely human', () => {
      const result = detectAiText(HUMAN_REVIEW_2)
      expect(result.verdict).not.toBe('likely_ai')
    })

    it('classifies emotional human writing as likely human', () => {
      const result = detectAiText(HUMAN_REVIEW_3)
      expect(result.verdict).not.toBe('likely_ai')
      // emotional writing has high burstiness
      expect(result.features.sentenceLengthCV).toBeGreaterThan(0.3)
    })

    it('human text has higher sentence length variance', () => {
      const human = detectAiText(HUMAN_REVIEW_1)
      const ai = detectAiText(AI_REVIEW_1)
      expect(human.features.sentenceLengthCV).toBeGreaterThan(ai.features.sentenceLengthCV)
    })
  })

  describe('AI-characteristic reviews', () => {
    it('flags uniform AI text', () => {
      const result = detectAiText(AI_REVIEW_1)
      expect(result.aiProbability).toBeGreaterThan(0.3)
      expect(result.triggers.length).toBeGreaterThan(0)
    })

    it('flags hedging-heavy AI text', () => {
      const result = detectAiText(AI_REVIEW_2)
      // should detect hedging phrases like "i would highly recommend"
      expect(result.triggers.some(t => t.includes('hedging') || t.includes('opener') || t.includes('uniform'))).toBe(true)
    })

    it('flags transition-heavy AI text', () => {
      const result = detectAiText(AI_REVIEW_3)
      // "additionally", "however", "nevertheless", "certainly"
      expect(result.aiProbability).toBeGreaterThan(0.2)
    })

    it('AI text has more triggers than human text', () => {
      const ai = detectAiText(AI_REVIEW_1)
      const human = detectAiText(HUMAN_REVIEW_1)
      expect(ai.triggers.length).toBeGreaterThanOrEqual(human.triggers.length)
    })
  })

  describe('AI scores higher than human on average', () => {
    it('average AI score > average human score', () => {
      const aiScores = [
        detectAiText(AI_REVIEW_1).aiProbability,
        detectAiText(AI_REVIEW_2).aiProbability,
        detectAiText(AI_REVIEW_3).aiProbability,
      ]
      const humanScores = [
        detectAiText(HUMAN_REVIEW_1).aiProbability,
        detectAiText(HUMAN_REVIEW_2).aiProbability,
        detectAiText(HUMAN_REVIEW_3).aiProbability,
      ]

      const avgAi = aiScores.reduce((a, b) => a + b, 0) / aiScores.length
      const avgHuman = humanScores.reduce((a, b) => a + b, 0) / humanScores.length

      expect(avgAi).toBeGreaterThan(avgHuman)
    })
  })

  describe('edge cases', () => {
    it('very short text returns uncertain with low confidence', () => {
      const result = detectAiText(SHORT_TEXT)
      expect(result.verdict).toBe('uncertain')
      expect(result.confidence).toBeLessThan(0.3)
    })

    it('empty text returns uncertain', () => {
      const result = detectAiText('')
      expect(result.verdict).toBe('uncertain')
      expect(result.confidence).toBe(0)
    })

    it('aiProbability ∈ [0, 1]', () => {
      const texts = [HUMAN_REVIEW_1, HUMAN_REVIEW_2, HUMAN_REVIEW_3, AI_REVIEW_1, AI_REVIEW_2, AI_REVIEW_3, SHORT_TEXT, '']
      for (const text of texts) {
        const result = detectAiText(text)
        expect(result.aiProbability).toBeGreaterThanOrEqual(0)
        expect(result.aiProbability).toBeLessThanOrEqual(1)
      }
    })

    it('confidence ∈ [0, 1]', () => {
      const texts = [HUMAN_REVIEW_1, AI_REVIEW_1, SHORT_TEXT, '']
      for (const text of texts) {
        const result = detectAiText(text)
        expect(result.confidence).toBeGreaterThanOrEqual(0)
        expect(result.confidence).toBeLessThanOrEqual(1)
      }
    })

    it('wordCount is accurate', () => {
      const result = detectAiText('one two three four five')
      expect(result.wordCount).toBe(5)
    })
  })

  describe('feature properties', () => {
    it('sentenceLengthCV ≥ 0', () => {
      expect(detectAiText(HUMAN_REVIEW_1).features.sentenceLengthCV).toBeGreaterThanOrEqual(0)
      expect(detectAiText(AI_REVIEW_1).features.sentenceLengthCV).toBeGreaterThanOrEqual(0)
    })

    it('typeTokenRatio ∈ (0, 1]', () => {
      const result = detectAiText(HUMAN_REVIEW_1)
      expect(result.features.typeTokenRatio).toBeGreaterThan(0)
      expect(result.features.typeTokenRatio).toBeLessThanOrEqual(1)
    })

    it('openerDiversity ∈ [0, 1]', () => {
      const result = detectAiText(AI_REVIEW_1)
      expect(result.features.openerDiversity).toBeGreaterThanOrEqual(0)
      expect(result.features.openerDiversity).toBeLessThanOrEqual(1)
    })

    it('hedgingDensity ≥ 0', () => {
      expect(detectAiText(HUMAN_REVIEW_1).features.hedgingDensity).toBeGreaterThanOrEqual(0)
    })
  })
})

describe('batchDetectAi', () => {
  it('processes multiple texts', () => {
    const results = batchDetectAi([
      { id: 'review-1', text: HUMAN_REVIEW_1 },
      { id: 'review-2', text: AI_REVIEW_1 },
      { id: 'review-3', text: HUMAN_REVIEW_3 },
    ])
    expect(results.length).toBe(3)
    expect(results[0].id).toBe('review-1')
    expect(results[1].id).toBe('review-2')
  })

  it('AI review scores higher than human in batch', () => {
    const results = batchDetectAi([
      { id: 'human', text: HUMAN_REVIEW_1 },
      { id: 'ai', text: AI_REVIEW_1 },
    ])
    const human = results.find(r => r.id === 'human')!
    const ai = results.find(r => r.id === 'ai')!
    expect(ai.result.aiProbability).toBeGreaterThanOrEqual(human.result.aiProbability)
  })
})
