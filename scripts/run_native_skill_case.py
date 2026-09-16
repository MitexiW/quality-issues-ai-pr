"""Isolated native-Skill variant of the existing single-PR review runner."""
import json
import sys
from pathlib import Path

import native_review_base as base
from claude_agent_sdk import HookMatcher

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'config/native_review/plugin'
SKILL = 'rq3-quality:review'
ALLOWED = [SKILL]
BUILD = base.build_options
PREFLIGHT = base.build_preflight


class SkillLoadingError(base.ClaudeReviewError):
    pass


def native_options(**kwargs):
    options = BUILD(**kwargs)
    options.extra_args.pop('bare', None)
    options.setting_sources = []  # Only explicit plugin, not repository/user instructions.
    options.plugins = [{'type': 'local', 'path': str(PLUGIN)}]
    options.skills = ALLOWED
    options.tools = list(options.tools) + ['Skill']
    options.can_use_tool = native_permission
    return options


async def native_permission(name, inputs, context):
    if name == 'Skill':
        if inputs.get('skill') in ALLOWED:
            return base.PermissionResultAllow()
        return base.PermissionResultDeny(message='Only frozen study skills are permitted', interrupt=False)
    return await base.read_only_permission(name, inputs, context)


def native_preflight(**kwargs):
    result = PREFLIGHT(**kwargs)
    result['native_skill'] = {'plugin': str(PLUGIN), 'name': SKILL,
        'skill_sha256': base.sha256_file(PLUGIN/'skills/review/SKILL.md'),
        'setting_sources': [], 'bare': False,
        'verification': 'user-dispatched /code-review and successful custom Skill PostToolUse required'}
    result['permissions']['tools'].append('Skill')
    result.pop('preflight_sha256')
    result['preflight_sha256'] = base.sha256_bytes(base.canonical_bytes(result))
    return result


async def collect_native(options, query_fn=base.query, on_message=None):
    command_sent = False
    command_available = False
    async def prompt():
        nonlocal command_sent
        command_sent = True
        yield {'type':'user','session_id':'','parent_tool_use_id':None,
               'message':{'role':'user','content':'/code-review'}}
    output = Path(sys.argv[sys.argv.index('--output-dir')+1])
    successful = []
    async def before_tool(data, tool_use_id, context):
        name = data.get('tool_name')
        if name == 'Skill' and data.get('tool_input',{}).get('skill') == SKILL:
            return {}
        if SKILL not in successful:
            return {'hookSpecificOutput': {'hookEventName':'PreToolUse',
                'permissionDecision':'deny',
                'permissionDecisionReason':f'Load {SKILL} through Skill before inspecting code or reporting findings.'}}
        return {}
    async def after_skill(data, tool_use_id, context):
        name = data.get('tool_input', {}).get('skill')
        response = data.get('tool_response')
        error = isinstance(response, dict) and (response.get('is_error') or response.get('isError'))
        if name in ALLOWED and not error:
            successful.append(name)
        with (output/'skill_calls.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'event':'PostToolUse', 'skill':name,
                'tool_use_id':tool_use_id, 'reported_error':bool(error)})+'\n')
        return {}
    options.hooks = {'PostToolUse':[HookMatcher(matcher='Skill', hooks=[after_skill])],
                     'PreToolUse':[HookMatcher(matcher='.*', hooks=[before_tool])]}
    messages, results = [], []
    stream_error = None
    try:
        async for message in query_fn(prompt=prompt(), options=options):
            messages.append(message)
            if on_message:
                on_message(message)
            if isinstance(message, base.ResultMessage):
                results.append(message)
            if getattr(message, 'subtype', None) == 'init':
                data = getattr(message, 'data', {})
                command_available = 'code-review' in data.get('slash_commands', [])
    except Exception as exc:
        # SDK may yield error_max_turns and then raise a plain Exception.
        # Keep that ResultMessage so the base runner saves usage and failure.
        stream_error = type(exc).__name__
    finally:
        verified = command_sent and command_available and SKILL in successful
        (output/'skill_loading_audit.json').write_text(json.dumps({
            'required':ALLOWED,'successful_skill_calls':successful,'verified':verified,
            'command_sent':'/code-review' if command_sent else None,
            'command_available':command_available,
            'stream_error_type':stream_error,
            'criterion':'explicit /code-review dispatch, command advertised by CLI, and successful custom Skill PostToolUse; code inspection gated on skill load'},indent=2)+'\n')
    if len(results) != 1:
        raise SkillLoadingError('Expected exactly one SDK result; retain logs and inspect')
    if results[0].is_error:
        return messages, results[0]
    if stream_error:
        raise SkillLoadingError('SDK stream failed after result; retain logs and inspect')
    if base.is_provider_error_text(results[0].result):
        raise base.ProviderRequestError('Provider request failed during native skill review')
    if not verified:
        raise SkillLoadingError('Native skill invocation not verified; do not score as model miss')
    return messages, results[0]


if __name__ == '__main__':
    base.build_options = native_options
    base.build_preflight = native_preflight
    base.collect_review = collect_native
    base.main()
