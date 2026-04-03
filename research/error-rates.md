# Research #3: False Positive / False Negative Rates

Issue: AUDIT.md #3 — Criminal Practice Direction 19A requires "known or potential rate of error."

## The requirement

For expert evidence to be admissible in UK courts under the enhanced Daubert test (Criminal Practice Direction 19A, 2014), the methodology must have a "known or potential rate of error." A tool that claims forensic capability without stating its error rate does not meet this standard.

## What we can measure vs. what we can't

### CAN measure (benchmark data exists):
1. **AI text detection** — HC3, HATC-2025 datasets (50K+ labeled samples). Top detectors: 92-98% accuracy. Our statistical detector will score lower than ML-based tools (GPTZero, Originality.ai) because we don't use a neural model — but we can measure exactly how much lower.
2. **Stylometry** — PAN shared task datasets (2020-2023). Cross-domain authorship verification. Results vary significantly by text length and domain. Key finding: "the very good results obtained by top-performing submissions may have given the false impression that authorship verification is an almost solved problem, but this is in fact not the case."

### CAN estimate analytically:
3. **KS test (timing coordination)** — statistical power is computable analytically for any sample size and effect size. At n=20, alpha=0.05: power ≈ 0.80 for moderate effect sizes. At n=10: power drops to ≈ 0.50. At n=5: power ≈ 0.20 (essentially useless). These aren't measured — they're mathematical properties of the test.
4. **Information-theoretic bounds** — Shannon entropy computations are exact. There's no "error rate" for computing I(x) = -log2(p(x)). The error is in the input probability estimate, not the computation.

### CANNOT measure (no benchmark):
5. **Review suspicion heuristics** — no labeled dataset of "confirmed fake reviews with known attacker." The Yelp datasets use Yelp's own filter as ground truth, which itself has unknown accuracy.
6. **Cross-domain correlation** — no dataset of "confirmed same-operator domain pairs vs different-operator pairs."
7. **WHOIS attribution** — no dataset of "WHOIS registrant matches confirmed owner."

## Implementation approach

### For measurable modules:

Build a benchmark harness that:
1. Downloads/loads a labeled dataset
2. Runs our detector against it
3. Computes precision, recall, F1, accuracy
4. Stores results as part of the tool's self-assessment
5. Reports these numbers in every forensic report

### For analytically estimable modules:

Compute and document the theoretical error bounds:
- KS test: type I error = alpha (user-configurable, default 0.05)
- KS test: type II error = 1 - power(n, effect_size, alpha)
- Provide power tables for common sample sizes

### For unmeasurable modules:

State "error rate: not empirically measured" explicitly in the report. This is honest and meets the Daubert requirement better than a fabricated number. The alternative — claiming an accuracy we haven't verified — is worse.

## Specific error rate implementation

### AI detection
- Build test using HC3 dataset format (human vs ChatGPT responses)
- Generate our own labeled test set: take 100 human review texts, generate 100 AI reviews on the same topics with GPT-4, run our detector
- Report: precision (of "likely_ai" verdicts), recall (what fraction of AI text caught), false positive rate on human text

### Stylometry
- Use PAN 2022 evaluation methodology: same-author vs different-author pairs
- Test on varying text lengths (50, 100, 200, 500 words)
- Report: ROC-AUC, EER (equal error rate), accuracy at our threshold

### KS test timing
- Analytical: compute power curves for n = 5, 10, 15, 20, 30, 50
- Against exponential (H0) with various alternative distributions
- Report as a power table in the forensic report

## What to report in the forensic report

```
Module                  | Error Rate           | Source
AI text detection       | P=X.X%, R=X.X%      | Self-benchmark against HC3 format
Stylometry (200+ words) | AUC=X.XX, EER=X.X%  | PAN evaluation methodology  
Stylometry (50-100)     | AUC=X.XX, EER=X.X%  | PAN evaluation methodology
KS timing (n=20)        | α=0.05, power=0.80   | Analytical (Kolmogorov distribution)
KS timing (n=10)        | α=0.05, power=0.50   | Analytical
Review heuristics       | Not measured          | No labeled benchmark available
Cross-domain corr.      | Not measured          | No labeled benchmark available
WHOIS attribution       | Not measured          | No labeled benchmark available
```

## Sources

- PAN authorship verification: https://pan.webis.de/clef23/pan23-web/author-identification.html
- PAN 2022 results: https://ceur-ws.org/Vol-3180/paper-184.pdf
- HC3 dataset: Human-ChatGPT Comparison Corpus
- HATC-2025: Stanford HAI benchmark, 50K+ samples
- KS test power: NIST Engineering Statistics Handbook https://www.itl.nist.gov/div898/handbook/eda/section3/eda35g.htm
- KS power analysis: Razali & Wah (2011) power comparisons
- YelpCHI dataset: 67,395 labeled reviews
- AI detection benchmark 2025: Originality.ai 92.3%, GPTZero 88.7%
- Criminal Practice Direction 19A (2014): enhanced Daubert test

## Status: research complete. Ready to implement.
