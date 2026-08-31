# Root-cause summary: full_ai_quality_population

This scope is the frozen full analysis frame; category shares may be reported with the study's stated uncertainty limits.

## Partition audit

- PRs: 251
- Alerts: 775
- Initial PR–Rule units: 316
- Root-cause clusters: 412
- PR–Rule units split across multiple clusters: 56
- Cross-rule clusters: 12
- Singleton-alert clusters: 271

## Five-category fit

- `incomplete_change_coordination`: 257 clusters (62.4%), covering 421 alerts (54.3%) in 167 PRs
- `redundant_or_locally_inconsistent_construction`: 70 clusters (17.0%), covering 119 alerts (15.4%) in 58 PRs
- `control_state_or_dataflow_miscomposition`: 44 clusters (10.7%), covering 67 alerts (8.6%) in 39 PRs
- `dependency_error_or_resource_mismanagement`: 25 clusters (6.1%), covering 63 alerts (8.1%) in 22 PRs
- `interface_or_contract_mismatch`: 16 clusters (3.9%), covering 105 alerts (13.5%) in 14 PRs

PR counts are non-exclusive because one PR may contain clusters from multiple categories.
These counts describe coded clusters, not independent causal events outside the sampled PRs.
