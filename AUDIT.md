# trace audit — known issues

15 issues identified. Each requires research, implementation, and verification before the tool is published.

Status: O = open, R = researching, B = building, D = done


## Critical (would invalidate findings in court)

### 1. Reliability parameters not calibrated
**Status:** D
**Problem:** `LAYER_RELIABILITY` values (stylometry: 0.55, review_profile: 0.60, etc.) were estimated, not derived from empirical data.
**Resolution:** Replaced flat lookup with `CALIBRATED_RELIABILITY` — context-dependent values derived from: ICANN ARS Phase 2 Cycle 6 (2018), Li et al. CCS 2019 (CT completeness), MaxMind published accuracy, Abbasi & Chen ACM TOIS 2008 (stylometry), arXiv 2507.00838 / 2003.11545 (short text accuracy). Each Signal now carries its own `reliability` and `reliabilityCitation` set by the collector. Calibration constants centralized in `packages/collectors/src/calibration.ts`. Research documented in `research/001-reliability-calibration.md`.
**Files changed:** `packages/core/src/fusion/dempster-shafer.ts`, `packages/collectors/src/calibration.ts`, `packages/collectors/src/types.ts`, whois/lookup.ts, ct/crtsh.ts, dns/resolver.ts, ip/geolocation.ts, orchestrator.ts

### 2. Information gain values are arbitrary
**Status:** D
**Problem:** Hardcoded constants for informationBits instead of computed values.
**Resolution:** Created `information-gain.ts` module with functions that compute I(x) = -log2(p(x)) from empirical base rates. Registrar market share (GoDaddy 14% → 2.8 bits, Namecheap 3.2% → 5.0 bits), NS provider share (Cloudflare 20% → 2.3 bits, custom → 10+ bits), city population (London 2.9 bits, Bradford 7.0 bits), ASN size (CDN → 2 bits, small ISP → 19 bits), IP type (CDN → 1.5 bits, shared hosting → 19.5 bits, dedicated → 25+ bits). 29 new tests verify the math. Sources: DNIB Q3 2025, domainnamewire.com, 6sense.com, MaxMind, Sweeney (2000). Research in `research/002-information-gain.md`.
**Files changed:** New: `packages/collectors/src/information-gain.ts`. Updated: dns/resolver.ts, ip/geolocation.ts, collectors/index.ts

### 3. No false positive / false negative rates
**Status:** D
**Problem:** No empirical error rates. Daubert/CPD 19A requires "known or potential rate of error."
**Resolution:** Created `benchmark/error-rates.ts` with three tiers: (1) Benchmark harness — runs any binary classifier against labeled data, computes P/R/F1/FPR/FNR. Ready for future benchmark datasets. (2) Analytical — KS test power computed mathematically. Power table for n=5 through n=100 at alpha=0.05. At n=20: power 0.80. At n=5: power ~0.20. (3) Honest "not measured" — modules without benchmark data explicitly state this with industry reference numbers. Every forensic report now includes: error rate table per module, KS power table, and CPD 19A citation. 29 new tests verify the math. Research in `research/003-error-rates.md`.
**Files changed:** New: `packages/core/src/benchmark/error-rates.ts`. Updated: report/narrative.ts, core/index.ts

### 4. Evidence chain is self-attested
**Status:** D
**Problem:** Evidence chain proved integrity but not authenticity of capture.
**Resolution:** Created `evidence/verification.ts` with three independent verification methods: (1) Dual-source DNS — queries same record from Cloudflare (1.1.1.1) and Google (8.8.8.8), compares results, hashes combined output. Fabrication requires compromising both resolvers. (2) RFC 3161 timestamps — requests cryptographic timestamp from FreeTSA.org (independent TSA). Proves data hash existed at specific time. (3) Archive.org preservation — independent third-party capture. Each evidence entry can now have a `VerificationReport` with status: verified (2+ methods), partial (1), or unverified (0). 10 new tests including live dual-source DNS verification.
**Files changed:** New: `packages/core/src/evidence/verification.ts`, `packages/core/tests/verification.test.ts`. Updated: core/index.ts

### 5. No error propagation
**Status:** D
**Problem:** If DNS lookup fails, the anonymity calculation proceeds without that data, as if the DNS layer contributed nothing. But "no evidence collected" is not the same as "no evidence exists." The reported remaining bits could be lower (more identified) than reality because missing data is treated as zero rather than unknown.
**What needs to happen:** Research uncertainty propagation in Dempster-Shafer theory. When a collector fails, the mass function should allocate mass to uncertainty (m(theta) = 1) rather than being omitted. Track which collectors ran vs which failed. Report confidence intervals on the anonymity estimate, not point estimates.
**Files affected:** `packages/collectors/src/orchestrator.ts`, `packages/core/src/entropy/anonymity.ts`


## High (would be challenged by expert witness)

### 6. Stylometry not validated on short texts
**Status:** D
**Problem:** Writeprints (Abbasi & Chen 2008) achieved 94% accuracy on 100+ word samples with known authorship. Reviews are 20-80 words. The tool reports similarity scores but doesn't quantify how accuracy degrades with text length. A 0.72 similarity on 40-word texts means something very different from 0.72 on 400-word texts.
**What needs to happen:** Research stylometric accuracy as a function of text length. Find papers that benchmark authorship attribution on short texts (tweets, reviews). Either: (a) build a calibration curve (length vs accuracy), (b) refuse to report scores below a minimum text length, or (c) report confidence intervals that widen with shorter texts.
**Files affected:** `packages/core/src/stylometry/writeprint.ts`, `packages/core/tests/stylometry.test.ts`

### 7. AI detection thresholds are not empirically derived
**Status:** D
**Problem:** Thresholds like CV < 0.30 for "uniform sentence length" and hedging density > 0.3 are educated guesses. No dataset was used to derive them. No precision/recall measured. GPTZero's own research says detection is unreliable below 75 words and biased against non-native speakers.
**What needs to happen:** Collect or find a labeled dataset of known AI-generated vs human-written reviews (multiple languages, multiple LLMs). Run the detector against it. Measure precision, recall, F1. Adjust thresholds to minimize false positives (a false accusation of AI usage is worse than missing a real AI review). Document the bias limitation for non-native English.
**Files affected:** `packages/core/src/stylometry/ai-detection.ts`

### 8. WHOIS parser covers ~70% of formats
**Status:** O
**Problem:** WHOIS output format varies by registrar. The regex-based parser handles common patterns but misses ~30% of responses. Incorrect parsing could attribute a domain to the wrong person — a false attribution in a legal proceeding.
**What needs to happen:** Research WHOIS parsing libraries and datasets. Options: (a) test the parser against a corpus of real WHOIS responses from diverse registrars, (b) use a structured WHOIS API (RDAP — RFC 9082/9083) which returns JSON instead of free text, (c) report parse confidence alongside results.
**Files affected:** `packages/collectors/src/whois/lookup.ts`

### 9. Cross-domain correlation false positives from shared infrastructure
**Status:** O
**Problem:** Millions of domains share Cloudflare nameservers, Vercel hosting, or Let's Encrypt certificates. The correlation engine rates shared nameservers as "moderate" and shared IPs as "definitive" — but Cloudflare anycast IPs are shared across thousands of unrelated domains. This produces false attribution links.
**What needs to happen:** Research shared-infrastructure frequency data. How many domains use each major nameserver set? How many share each Cloudflare/Vercel IP? Weight correlations by the inverse frequency of the shared attribute. Shared Cloudflare NS should be near-zero signal. Shared dedicated IP should be strong. Shared Google Analytics ID should be definitive (near-unique).
**Files affected:** `packages/collectors/src/correlation/cross-domain.ts`

### 10. IP geolocation accuracy not documented
**Status:** O
**Problem:** ip-api.com is a free service with no published accuracy metrics. City-level geolocation is 50-80% accurate depending on region. The tool reports city as a finding without stating the error margin. VPN/proxy detection has an unknown false negative rate.
**What needs to happen:** Research IP geolocation accuracy studies. MaxMind publishes accuracy statistics by country. ip-api.com does not. Either: (a) switch to a provider with published accuracy data, (b) document known accuracy ranges per region, (c) report geolocation with explicit uncertainty radius.
**Files affected:** `packages/collectors/src/ip/geolocation.ts`


## Medium (would be noted but not fatal)

### 11. KS test has low power on small samples
**Status:** O
**Problem:** The Kolmogorov-Smirnov test can't reliably distinguish distributions with fewer than ~20 observations. The tool accepts 4+ timestamps. A p-value of 0.15 on 5 observations means nothing — but the tool reports it as if it does.
**What needs to happen:** Research minimum sample sizes for KS test power at various significance levels. Either: (a) refuse to run the test below a minimum N, (b) report the statistical power alongside the p-value, (c) use a different test better suited to small samples (e.g., Shapiro-Wilk or exact permutation test).
**Files affected:** `packages/core/src/timing/coordination.ts`

### 12. Review heuristics are keyword-based and easily evaded
**Status:** O
**Problem:** "competitor_mention" regex catches "go to X instead" but not "after this experience I found a better provider." Keyword-based detection is trivially evaded by a competent attacker. The tool should not claim to catch sophisticated attacks.
**What needs to happen:** Research NLP-based intent classification for review text. Short term: document the limitation explicitly. Long term: consider semantic similarity rather than keyword matching. Or: accept the limitation and focus the heuristics on catching the 80% of attacks that ARE unsophisticated.
**Files affected:** `packages/collectors/src/reviews/google.ts`

### 13. No adversarial testing
**Status:** O
**Problem:** All test samples are handcrafted by the developer. No testing against inputs specifically designed to evade detection — AI text crafted to pass burstiness checks, fake reviews written to avoid keyword flags, timing patterns designed to pass the KS test.
**What needs to happen:** Build an adversarial test suite. For each detection module, create inputs that specifically target its weaknesses. Measure the evasion rate. This is the most honest test of the tool's capability.
**Files affected:** New test files across all detection modules.

### 14. ACPO compliance check is superficial
**Status:** O
**Problem:** The tool checks four boxes (analyst name exists, chain intact, entries > 0, both true). Real ACPO compliance requires: the analyst is qualified, the methodology is documented, an independent expert can reproduce the results, the chain of custody is maintained throughout. The current check is a formality, not a real assessment.
**What needs to happen:** Research what ACPO compliance actually requires in practice for digital forensics submissions. Consult the ACPO Good Practice Guide v5 in detail. Either: (a) implement deeper checks (methodology documentation verification, reproducibility test), or (b) honestly label the check as "partial ACPO alignment" rather than "compliance."
**Files affected:** `packages/core/src/legal/framework.ts`

### 15. crt.sh response trusted without independent verification
**Status:** O
**Problem:** The tool fetches from crt.sh over HTTPS and trusts the response. Low risk (TLS protects against MITM), but for a court-ready tool, single-source data should ideally be corroborated. A different CT log aggregator (Censys, Google CT) could provide independent confirmation.
**What needs to happen:** Research alternative CT log sources. Add optional dual-source verification: query crt.sh AND Censys/Google CT, compare results. Flag discrepancies. Short term: document the single-source limitation. Long term: implement corroboration.
**Files affected:** `packages/collectors/src/ct/crtsh.ts`


## Working order

Start with #1 (calibration) — it affects every other module's output.
Then #2 (information gain) — same reason.
Then #3 (error rates) — required by law for expert evidence.
Then #5 (error propagation) — affects result accuracy.
Then #4 (independent verification) — evidence integrity.
Then #6-10 (high severity) in order.
Then #11-15 (medium) in order.
