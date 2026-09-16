#!/usr/bin/env python3
"""Export numbered numerical data bundles for every main and supplementary table.

Tables are regenerated from row-level inputs/new analysis outputs, not parsed
from manuscript numbers. CSV/HTML bundles include source detail beyond the
printed cells. Journal typography is intentionally not replicated.
"""
import argparse
import html
import json
from pathlib import Path

import numpy as np
import pandas as pd


def truth(series):
    return series.astype(str).str.lower().isin(['1', 'true', 'yes'])


def compare(actual, expected, columns=None):
    if columns is not None:
        actual, expected = actual[columns], expected[columns]
    pd.testing.assert_frame_equal(actual.reset_index(drop=True), expected.reset_index(drop=True),
                                  check_dtype=False, check_exact=False, rtol=1e-9, atol=1e-10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--quick', action='store_true')
    args = parser.parse_args()
    root, out = args.root.resolve(), args.results.resolve()
    reports = root/'data/results'
    tables = out/'tables'
    tables.mkdir(exist_ok=True)
    entries, checks = [], []

    def read(path):
        return pd.read_csv(path, keep_default_na=False)

    def emit(number, frames, sources, kind='recomputed'):
        folder = tables/number
        folder.mkdir(exist_ok=True)
        sections = []
        for name, frame in frames.items():
            frame.to_csv(folder/f'{name}.csv', index=False)
            sections.append(f'<h2>{html.escape(name)}</h2>'+frame.to_html(index=False, escape=True))
        (folder/'table.html').write_text('<meta charset="utf-8"><h1>'+number+'</h1>'+''.join(sections))
        entries.append({'table': number, 'kind': kind, 'datasets': list(frames),
                        'inputs': [str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
                                   for p in sources]})

    def bundle(number, paths, kind='recomputed'):
        emit(number, {name: read(path) for name, path in paths.items()}, list(paths.values()), kind)

    ai, human = out/'rq1-ai', out/'rq1-human'
    profile = read(ai/'introduced_by_language.csv')
    # Preserve the eight-language presentation order in the manuscript.
    languages = ['C', 'C++', 'Go', 'Java', 'JavaScript', 'Python', 'Ruby', 'TypeScript']
    q = profile[profile.family.eq('quality') & profile.stratum.isin(languages)].copy()
    emit('Table1', {'language': q}, [ai/'introduced_by_language.csv'])
    rules = read(ai/'rule_profile.csv')
    rules = rules[rules.family.eq('quality') & rules.task_type.eq('all')].sort_values(
        ['introduced_alert_n', 'rule_id'], ascending=[False, True]).head(40)
    emit('Table2', {'top40_rules': rules}, [ai/'rule_profile.csv'])
    bundle('Table3', {'categories': out/'rq1-root-causes/category_summary.csv'})
    groups = []
    for group, path in [('ai', ai), ('human', human)]:
        frame = read(path/'introduced_by_language.csv')
        frame = frame[frame.family.eq('quality') & frame.stratum.isin(languages)].copy()
        frame.insert(0, 'group', group)
        groups.append(frame)
    combined = pd.concat(groups, ignore_index=True)
    difference = combined.pivot(index='stratum', columns='group', values='affected_pr_percent').reset_index()
    difference['AI_minus_human_pp'] = difference.ai - difference.human
    emit('Table4', {'groups_by_language': combined, 'differences': difference},
         [ai/'introduced_by_language.csv', human/'introduced_by_language.csv'])
    bundle('Table5', {'category_recovery': out/'insights/rq3_recovery_by_category.csv'})
    guided_summary = out/'rq3-guided/comparison_summary.csv'
    guided_categories = out/'rq3-guided/root_cause_comparison.csv'
    gs, gc = read(guided_summary), read(guided_categories)
    emit('Table6', {'review_settings': gs[gs.group.eq('all')]}, [guided_summary])
    emit('Table7', {'root_cause_recovery': gc[gc.group.eq('all') & gc.tier.eq('broad')]}, [guided_categories])

    raw_path = reports/'rq_analysis_final_20260727_v3/analysis_pr_level.csv'
    final_path = out/'validated-snapshot/analysis_pr_level.csv'
    raw, final = read(raw_path), read(final_path)
    raw = raw[truth(raw.quality_gate_pass)]
    final = final[truth(final.quality_gate_pass)]
    spec = root/'config/study/model_specification.yaml'
    emit('S1', {'definitions': pd.DataFrame([
        {'outcome': 'Human-confirmed any', 'definition': 'At least one family-specific alert with final disposition confirmed_valid'},
        {'outcome': 'Human-confirmed count', 'definition': 'Number of family-specific alerts with final disposition confirmed_valid'},
        {'outcome': 'Raw differential any', 'definition': 'At least one unmatched family-specific head result before contextual validation'},
        {'outcome': 'Raw differential count', 'definition': 'Number of unmatched family-specific head results before contextual validation'},
    ])}, [spec], 'measurement_definition')
    cohort = final.groupby('group').agg(prs=('pr_number', 'size'), repositories=('repo_name', 'nunique')).reset_index()
    emit('S2', {'cohort': cohort}, [final_path])
    bundle('S3', {'balance': out/'rq2-design/balance.csv'})
    candidates, summaries = [], []
    for group in ['ai', 'human']:
        path = root/f'data/manifests/{group}_prs.csv'
        frame = read(path)
        candidates.append(path)
        summaries.append({'group': group, 'prs': len(frame), 'repositories': frame.repo_name.nunique()})
        for dimension in ['language', 'task_type']:
            for value, count in frame[dimension].value_counts().items():
                summaries.append({'group': group, 'dimension': dimension, 'value': value, 'prs': count})
    emit('S4', {'candidates': pd.DataFrame(summaries)}, candidates)
    snap = out/'validated-snapshot'
    bundle('S5', {'funnel': snap/'adjudication_funnel.csv'})
    bundle('S6', {'dispositions': snap/'human_validation_dispositions.csv'})
    bundle('S7', {'domains': snap/'adjudication_funnel.csv'})
    strata_path = snap/'human_validation_strata.csv'
    strata = read(strata_path)
    emit('S8', {'strata': strata[~strata.dimension.eq('rule_id')]}, [strata_path])
    emit('S9', {'rules': strata[strata.dimension.eq('rule_id') & (strata.reviewed_alert_n >= 50)]}, [strata_path])
    labels_path = reports/'final_human_consensus_20260817_v1/final_alert_labels.csv'
    labels = read(labels_path)
    review = []
    selectors = [('Overall', pd.Series(True, index=labels.index)),
                 ('AI', labels.group.eq('ai')), ('Human', labels.group.eq('human')),
                 ('Quality', labels.issue_domain.eq('quality')), ('Security', labels.issue_domain.eq('security'))]
    for source in labels.source_set.unique():
        selectors.append((source, labels.source_set.eq(source)))
    for scope, mask in selectors:
        rows = labels[mask]
        initial = rows.source_disposition.eq('confirmed_valid')
        independent = rows.independent_rereview_disposition.eq('confirmed_valid') & initial
        retained = initial & ~independent & rows.disposition.eq('confirmed_valid')
        review.append({'scope': scope, 'initially_confirmed': int(initial.sum()),
                       'C_confirmed': int(independent.sum()),
                       'C_confirmation_percent': 100*independent.sum()/max(initial.sum(), 1),
                       'consensus_retained': int(retained.sum()),
                       'final_confirmed': int(rows.disposition.eq('confirmed_valid').sum())})
    emit('S10', {'rereview': pd.DataFrame(review)}, [labels_path])
    bundle('S11', {'overall_and_tasks': ai/'introduced_by_task.csv',
                   'confidence_intervals': ai/'repository_cluster_bootstrap_intervals.csv'})
    bundle('S12', {'category': ai/'quality_category_profile.csv', 'location': ai/'introduced_by_location.csv'})
    bundle('S13', {'tasks': ai/'introduced_by_task.csv'})
    bundle('S14', {n: ai/f'{n}.csv' for n in ['severity_profile', 'precision_profile', 'pr_issue_count_distribution']})
    bundle('S15', {'rule_category': out/'robustness/rule_category_crosstab.csv'})
    bundle('S16', {'root_cause_exclusions': out/'robustness/root_cause_filter_summary.csv'})
    bundle('S17', {'changed_kloc': out/'raw-sensitivities/rq1_ai_alerts_per_changed_kloc.csv'})
    concentration = []
    for group, subset in raw.groupby('group'):
        counts = subset.introduced_quality_alerts.astype(int).sort_values(ascending=False)
        total = counts.sum()
        n = round(len(counts)*.01)
        concentration.append({'group': group, 'alerts': int(total), 'max_per_pr': int(counts.max()),
                              **{f'top{k}_percent': float(100*counts.head(k).sum()/total) for k in [1, 5, 10]},
                              'top_one_percent_prs': n, 'top_one_percent_share': float(100*counts.head(n).sum()/total)})
    emit('S18', {'raw_concentration': pd.DataFrame(concentration)}, [raw_path])
    bundle('S19', {'effects': out/'rq2-models/standardized_effects.csv'})
    bundle('S20', {'ai_tasks': ai/'introduced_by_task.csv', 'human_tasks': human/'introduced_by_task.csv'})
    bundle('S21', {'concentration': out/'insights/concentration_metrics.csv'})
    measurement = []
    for name, frame in [('raw', raw), ('confirmed', final)]:
        for group, rows in frame.groupby('group'):
            for family in ['quality', 'security']:
                counts = rows[f'introduced_{family}_alerts'].astype(int)
                measurement.append({'layer': name, 'group': group, 'family': family,
                                    'prs': len(rows), 'positive_prs': int((counts>0).sum()),
                                    'alerts': int(counts.sum()), 'affected_percent': 100*(counts>0).mean(),
                                    'alerts_per_100_prs': 100*counts.mean()})
    emit('S22', {'measurement': pd.DataFrame(measurement)}, [raw_path, final_path])
    bundle('S23', {'filters': out/'raw-sensitivities/sensitivity_summary.csv'})
    bundle('S24', {'effects': out/'robustness/standardized_effects.csv',
                   'samples': out/'robustness/sample_profiles.csv'})
    refs_path = reports/'final_human_confirmed_rq3_20260817_v1/reference_adjudication_join_public.csv'
    refs = read(refs_path)
    common = (truth(refs.is_quality_alert) & refs.location_class.eq('production')
              & truth(refs.changed_file) & truth(refs.reference_visible_in_diff)
              & refs.precision.isin(['high', 'very-high']) & refs.lifecycle.eq('introduced'))
    primary_mask = common & ~refs.rule_tags.str.split('|').map(lambda tags: 'useless-code' in tags)
    severity_mask = primary_mask & refs.problem_severity.isin(['warning', 'error'])
    for name, mask in [('broad', common), ('primary', primary_mask), ('strict', severity_mask)]:
        if not mask.equals(truth(refs[f'quality_{name}_reference'])):
            raise ValueError(f'Frozen {name} flags disagree with released eligibility metadata')
    if not (pd.to_numeric(refs.start_line).between(
            pd.to_numeric(refs.hunk_new_start), pd.to_numeric(refs.hunk_new_end))).all():
        raise ValueError('Reference location outside its frozen head-side diff hunk')
    tiers = []
    for tier in ['primary', 'strict', 'broad']:
        mask = truth(refs[f'quality_{tier}_reference'])
        tiers.append({'tier': 'higher-severity' if tier == 'strict' else tier,
                      'raw': int(mask.sum()), 'confirmed': int((mask & truth(refs.validated_issue_reference)).sum())})
    assert [(x['raw'], x['confirmed']) for x in tiers] == [(420,114),(151,40),(535,187)]
    emit('S25', {'tiers': pd.DataFrame(tiers)}, [refs_path])
    recovery_path = out/'rq3-metrics/group_metrics.csv'
    recovery = read(recovery_path)
    recovery = recovery[recovery.layer.eq('human_confirmed_primary')].copy()
    if set(recovery.group) != {'ai', 'human'} or len(recovery) != 2:
        raise ValueError('S26 requires the AI and human confirmed-primary rows')
    emit('S26', {'recovery': recovery}, [recovery_path])
    cases_path = reports/'default_review/case_metrics.csv'
    relation_path = reports/'rq3_semantic_results_20260729_v1/semantic_finding_relations_public.csv'
    cases, relations = read(cases_path), read(relation_path)
    metrics = {'completed_cases': len(cases), 'findings': int(cases.review_finding_n.sum()),
               'valid_output': int(truth(cases.model_output_valid).sum()),
               'invalid_output': int((~truth(cases.model_output_valid)).sum()),
               'zero_finding': int(cases.review_finding_n.eq(0).sum()),
               'median_seconds': float(cases.latency_ms.median()/1000),
               'p95_seconds': float(cases.latency_ms.quantile(.95)/1000)}
    same = relations.codeql_relation.eq('same_issue')
    auto = truth(relations.automatic_recovered)
    audit = dict(TP=int((same&auto).sum()), FP=int((~same&auto).sum()), FN=int((same&~auto).sum()),
                 scope='Historical 1,016-finding matching audit; excludes new findings')
    emit('S27', {'execution': pd.DataFrame([metrics]),
                  'historical_matching_audit': pd.DataFrame([audit]),
                  'historical_relations': relations.groupby('codeql_relation').size().reset_index(name='n')}, [cases_path, relation_path])
    bundle('S28', {'root_cause_by_group': out/'rq3-mechanisms/recovery_by_rq1_mechanism.csv'})
    emit('S29', {'guided_by_group': gs[~gs.group.eq('all')]}, [guided_summary])
    emit('S30', {'guided_root_causes': gc[gc.group.eq('all') & gc.tier.eq('broad')]}, [guided_categories])
    assert {x['table'] for x in entries} == {f'Table{i}' for i in range(1,8)} | {f'S{i}' for i in range(1,31)}

    # Frozen CSVs are comparison oracles only, never inputs to computed tables.
    comparisons = [('validated-snapshot', 'final_human_confirmed_issue_analysis_20260817_v1',
                    ['adjudication_funnel.csv', 'human_validation_dispositions.csv', 'human_validation_strata.csv']),
                   ('rq1-ai', 'final_human_confirmed_rq1_ai_profile_20260820_v2', None),
                   ('rq1-human', 'final_human_confirmed_rq1_human_profile_20260817_v1', None),
                   ('rq2-design', 'rq2_design_unweighted_final_20260727_v3', ['balance.csv']),
                   ('rq2-models', 'final_human_confirmed_rq2_models_20260817_v1', ['standardized_effects.csv']),
                   ('raw-sensitivities', 'alert_sensitivities_final_20260727_v2', ['sensitivity_summary.csv', 'rq1_ai_alerts_per_changed_kloc.csv']),
                   ('insights', 'default_review/analysis/insights', None),
                   ('rq1-root-causes', 'ai_quality_root_cause_review_20260831_v1/full_summary_v1', None),
                   ('rq3-mechanisms', 'default_review/analysis/mechanisms', ['recovery_by_rq1_mechanism.csv']),
                   ('robustness', 'final_human_confirmed_supplementary_robustness_20260907_v2',
                    ['root_cause_filter_summary.csv', 'rule_category_crosstab.csv', 'standardized_effects.csv'])]
    comparisons.append(('rq3-guided', 'native_skill_review/analysis', None))
    for new, old, names in comparisons:
        for path in sorted((out/new).glob('*.csv')):
            expected = reports/old/path.name
            if not expected.exists() or (names is not None and path.name not in names):
                continue
            if args.quick:
                continue
            compare(read(path), read(expected))
            checks.append(f'{new}/{path.name}')
    manifest = {'table_count': len(entries), 'quick': args.quick,
                'comparison': 'skipped_in_quick_mode' if args.quick else 'passed',
                'frozen_comparisons': checks, 'tables': entries,
                'scope': 'Numerical data bundles; CSV/HTML, not journal LaTeX typography or a verbatim-cell manuscript audit.'}
    (tables/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (tables/'index.html').write_text('<meta charset="utf-8"><h1>Paper table data</h1>'+''.join(
        f'<p><a href="{x["table"]}/table.html">{x["table"]}</a></p>' for x in entries))
    print(f'Exported {len(entries)} table data bundles; verified {len(checks)} frozen CSVs.')


if __name__ == '__main__':
    main()
