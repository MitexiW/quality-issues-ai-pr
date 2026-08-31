# Cross-RQ insight analysis

## 1. Sparse, heavy-tailed Quality risk

- AI: 8.13% of PRs were
  Quality-positive, while the top 1% of PRs contributed
  48.26% of
  introduced Quality alerts (Gini
  0.961).
- Human: 11.39% were
  Quality-positive, while the top 1% contributed
  51.66%
  (Gini 0.959).

This supports a tail-risk interpretation. It does not imply that alerts are
runtime defects or that the largest PRs are caused by authorship.

## 2. Incremental predictive value of provenance

Repository-grouped 2000-draw
cluster bootstrap intervals were computed from out-of-fold predictions.

- Context-only Brier score:
  0.07925; context plus provenance:
  0.07935; difference
  +0.00010
  [-0.00008,
  +0.00031].
- Context-only AUROC: 0.72652; context
  plus provenance: 0.72523;
  difference -0.00129
  [-0.00515,
  +0.00253].

This is a predictive, not causal, analysis. Its role is to quantify whether
the recorded AI/Human label improves out-of-repository risk ranking beyond the
same observable covariates used by the formal RQ2 model.

## 3. Issue-profile similarity

- Broad category Jensen--Shannon divergence:
  0.0004 bits; total-variation
  distance: 0.0136.
- Within-language rule-profile weighted mean Jensen--Shannon divergence:
  0.1033 bits; distribution
  overlap: 0.7923, across
  6 eligible languages.

The rule comparison is stratified by CodeQL database language and counts each
PR at most once per rule. It therefore avoids treating repeated alerts from
one PR or language-specific query packs as a distinct authorship signature.

## 4. LLM--CodeQL coverage

Pooled primary-Quality semantic recovery by category:

- correctness_reliability: 16/81 (19.75%).
- maintainability: 3/32 (9.38%).
- performance_efficiency: 1/1 (100.00%).

The deterministic location matcher recovered
26 of
45 manually accepted same-issue
relations and missed
19; it also made
3 false alignments. Exact
location matching is therefore not an adequate substitute for the frozen
same-root-cause review.

## Paper-level synthesis

The evidence supports one bounded argument: CodeQL-detectable Quality risk is
sparse and heavy-tailed rather than uniformly elevated in AI-authored PRs; the
recorded authorship label contributes little standalone predictive information
after observable context is included; and the tested LLM reviewer recovers
only a small, category-dependent subset of the static-analysis references.
Repository policy should therefore use layered, PR-level gates rather than AI
provenance alone.
