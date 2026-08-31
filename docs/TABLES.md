# Reproducing the paper tables

Run `python scripts/reproduce_analysis.py` from the repository root, using
Python 3.12 and the packages in `requirements.txt`. Use a fresh
`--output-dir` if a previous run already produced post-hoc results.

Open `outputs/reproduction/tables/index.html`. Each table number has CSV data
and an HTML view. These are numerical data bundles, not copies of the journal
LaTeX formatting: some contain additional rows or columns so readers can inspect
the calculations. Percentages and interval endpoints are not rounded until presentation.
No new CodeQL scan, model call, or human annotation is performed.

| Paper table | Numerical data |
|---|---|
| 1 | AI language profile |
| 2 | Top 30 Quality rules |
| 3 | Five root-cause categories |
| 4 | AI/Human language profiles and percentage-point differences |
| 5 | Quality-category review recovery |
| 6 | Root-cause review recovery |
| S1 | Fixed outcome definitions (not estimated data) |
| S2 | Final cohort PR/repository counts |
| S3 | Recomputed descriptive balance |
| S4 | Candidate-pool language/task/repository counts |
| S5–S7 | Rebuilt validation funnel, decisions and domains |
| S8–S9 | Rebuilt validation strata and rule-level confirmations |
| S10 | Re-review and consensus counts from final annotation records |
| S11–S14 | RQ1 profiles, intervals and within-PR counts |
| S15–S16 | Rule/root-cause cross-tabulation and unused-rule exclusions |
| S17–S18 | Raw-alert KLOC rates and concentration |
| S19–S21 | Adjusted comparison, unadjusted tasks and concentration |
| S22–S23 | Raw/confirmed outcomes and raw-alert filter checks |
| S24 | Final-label rule-exclusion refits |
| S25 | Primary, higher-severity and broad reference tiers |
| S26–S27 | Review recovery, execution and matching statistics |
| S28 | Root-cause recovery by authorship |

The full run compares regenerated statistical CSVs with the published numerical
results and stops on a mismatch. Quick mode reduces simulation draws and skips
those full-result comparisons; it must not be used for paper estimates.
The comparison is against statistical data, not a verbatim-cell audit of the
separately maintained manuscript.

Current statistical figures are Fig2 (change size/concentration), Fig3
(task/category/location), Fig4 (adjusted differences), and Fig5 (review recovery).
The full run draws these from its newly computed results. Fig1 is a manually
drawn workflow; editable SVG and draw.io files are under `assets/`.

The repository contains source excerpts and frozen decisions for qualitative
cases; scripts summarize those decisions but do not independently recreate
researcher judgments. Shared-repository adjusted inference failed numerical
checks and must not be presented as supporting robustness evidence.
