import { describe, it, expect } from 'vitest'
import { detectAiText } from '../src/stylometry/ai-detection.js'
import { compareWriteprints } from '../src/stylometry/writeprint.js'
import { detectCoordination } from '../src/timing/coordination.js'

/**
 * Adversarial tests: inputs specifically designed to evade detection.
 *
 * These tests document the KNOWN EVASION BOUNDARIES of each module.
 * A test that "fails" (the detector misses the adversarial input)
 * is a documented limitation, not a bug.
 *
 * Per audit issue #13: every detection module should be tested
 * against inputs crafted to exploit its weaknesses.
 */

describe('adversarial: AI detection evasion', () => {
  it('AI text with manually varied sentence length evades CV check', () => {
    // attacker deliberately varies sentence lengths to mimic human burstiness
    const evasive = `Terrible. Absolutely terrible service from start to finish. I waited three months. Three months! And what did I get? Nothing but excuses. The team seemed completely lost. I asked for updates — crickets. Finally gave up and went elsewhere. Sorted in two weeks. Do not waste your time here.`
    const result = detectAiText(evasive)
    // this text has high CV (varied sentence lengths) so it looks human
    // the detector should NOT confidently flag it
    // documenting that evasion via deliberate burstiness works
    expect(result.features.sentenceLengthCV).toBeGreaterThan(0.4)
  })

  it('AI text without hedging phrases evades hedging check', () => {
    const noHedging = `The service failed. Documents were lost. Communication stopped after payment. The timeline doubled. Staff were unprepared. I found a different firm. They completed the work in two weeks. The price was lower. The outcome was better.`
    const result = detectAiText(noHedging)
    expect(result.features.hedgingDensity).toBe(0)
    // no hedging triggers → lower AI probability
  })

  it('human-like AI text with contractions and slang', () => {
    const humanLikeAi = `Look I'm not gonna sugarcoat it — they messed up. Big time. My paperwork was all over the place and nobody seemed to care. I've used plenty of these services before and this was hands down the worst. They didn't even bother to follow up. Just... radio silence for weeks. Wouldn't recommend to my worst enemy tbh.`
    const result = detectAiText(humanLikeAi)
    // well-crafted AI text with contractions and informal language
    // should score lower than stereotypical AI text
    expect(result.aiProbability).toBeLessThan(0.5)
  })
})

describe('adversarial: stylometry evasion', () => {
  it('same author with deliberately different style scores lower', () => {
    // author writes one review formally, another informally
    const formal = `The citizenship application service provided by this company was entirely unsatisfactory. The documentation process contained numerous errors, and the timeline exceeded all reasonable expectations. Communication was inadequate throughout the engagement.`
    const informal = `waste of money lol. they lost my docs TWICE and took ages to respond. ended up doing it myself. wouldn't go back if you paid me. complete shambles from day one.`

    const result = compareWriteprints(formal, informal)
    // KNOWN LIMITATION: even with deliberately different register,
    // the feature vector similarity can remain high (0.75-0.85)
    // because scalar features like avg word length and function word
    // ratio don't change dramatically between formal and informal English.
    // Style-switching is a partial evasion, not a complete one.
    expect(result.similarity).toBeLessThan(0.85)
  })

  it('different authors with similar training data score higher', () => {
    // two different people who both write formal business English
    const personA = `The translation service was professional and timely. All documents were certified correctly and the consulate accepted them without issue. The pricing was reasonable and transparent.`
    const personB = `The application process was handled professionally and efficiently. All requirements were met correctly and the submission was accepted without delay. The fees were fair and clearly stated.`

    const result = compareWriteprints(personA, personB)
    // similar register → higher similarity even though different authors
    // documenting that shared register confuses stylometry
    expect(result.similarity).toBeGreaterThan(0.5)
  })
})

describe('adversarial: timing evasion', () => {
  it('jittered coordinated timing passes KS test', () => {
    // attacker adds random jitter to scheduled reviews
    // base: one review every 24 hours, but with ±6 hour random jitter
    const base = Date.now()
    const DAY = 86400000
    const timestamps: number[] = []
    for (let i = 0; i < 15; i++) {
      const jitter = (Math.random() - 0.5) * 12 * 3600000 // ±6 hours
      timestamps.push(base + i * DAY + jitter)
    }

    const result = detectCoordination(timestamps)
    // with enough jitter, the timing looks natural
    // documenting that jittered scheduling can evade KS detection
    // (this is the same principle threadr uses for its own OPSEC)
    expect(result.cv).toBeGreaterThan(0.2) // jitter increases CV
  })

  it('truly random timing is not flagged', () => {
    // legitimate reviews arrive at random intervals
    const timestamps: number[] = [Date.now()]
    for (let i = 1; i < 20; i++) {
      // exponential inter-arrival: mean 5 days
      const gap = -Math.log(Math.random()) * 5 * 86400000
      timestamps.push(timestamps[i - 1] + gap)
    }

    const result = detectCoordination(timestamps)
    expect(result.likelyCoordinated).toBe(false)
  })
})
