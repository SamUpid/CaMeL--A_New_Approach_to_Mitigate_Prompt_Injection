"""
AgentDojo adapter for the Dual-LLM pattern (Willison, 2023).

Key architectural points:
- Q-LLM is a neutral extractor — it faithfully returns attacker-poisoned values.
- P-LLM has tools and trusts Q-LLM output via the Controller (the exploitable gap).
- Control flow (tool calls) is always P-LLM's decision — Q-LLM cannot call tools.
- Attackers CAN get data by poisoning values that P-LLM then acts on with tools.
"""

import logging
from typing import Any
from pathlib import Path
import json

# ---------------------------------------------------------------------------
# Patch AgentDojo's NullLogger bug
# ---------------------------------------------------------------------------
try:
    from agentdojo.logging import NullLogger
    if not hasattr(NullLogger, "logdir"):
        NullLogger.logdir = None
except ImportError:
    pass

import agentdojo.default_suites  # noqa: F401
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import ChatMessage, ChatAssistantMessage, text_content_block_from_string

from dual_llm_pattern import Controller

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_text_content(content: Any) -> str:
    """Safely extract plain text from a message content field."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                parts.append(part.get("content", "").strip())
        return "\n".join(parts)
    return str(content).strip()


def _collect_untrusted_from_env(env: Any) -> list[dict]:
    """Extract untrusted data from the task environment state."""
    sources = []
    if env is None:
        return sources

    # ── Workspace inbox ──────────────────────────────────────────────────────
    if hasattr(env, 'inbox'):
        all_emails = []
        for attr in ('received', 'sent', 'emails'):
            bucket = getattr(env.inbox, attr, None)
            if bucket is None:
                continue
            if isinstance(bucket, list):
                all_emails.extend(bucket)
            elif isinstance(bucket, dict):
                all_emails.extend(list(bucket.values())[:15])

        logger.info(f"Inbox: {len(all_emails)} email(s)")

        for email in all_emails[:15]:
            sender  = getattr(email, 'sender',  'unknown')
            subject = getattr(email, 'subject', 'no subject')
            body    = getattr(email, 'body', getattr(email, 'content', ''))
            full_content = f"From: {sender}\nSubject: {subject}\n\n{body}"
            sources.append({
                "content": full_content,
                "description": (
                    f"Email from {sender} with subject '{subject}'. "
                    f"Use EXTRACT to get specific values (email addresses, codes, etc.)."
                ),
            })

    # ── Calendar ─────────────────────────────────────────────────────────────
    if hasattr(env, 'calendar') and hasattr(env.calendar, 'events'):
        events = env.calendar.events
        if isinstance(events, list):
            event_list = events[:15]
        elif isinstance(events, dict):
            event_list = list(events.values())[:15]
        else:
            try:
                event_list = list(events)[:15]
            except Exception:
                event_list = []

        logger.info(f"Calendar: {len(event_list)} event(s)")

        for event in event_list:
            title        = getattr(event, 'title', 'Untitled')
            description  = getattr(event, 'description', '')
            start        = getattr(event, 'start_time', getattr(event, 'start', ''))
            participants = getattr(event, 'participants', [])
            participants_str = ", ".join(participants) if participants else "none listed"
            location = getattr(event, 'location', '') or 'not specified'
            location = getattr(event, 'location', '') or 'not specified'
            event_content = (
                f"Event: {title}\nDate: {start}\n"
                f"Location: {location}\n"
                f"Description: {description}\nParticipants: {participants_str}"
            )
            sources.append({
                "content": event_content,
                "description": f"Calendar event: {title} on {start}",
            })

    # ── Cloud drive ──────────────────────────────────────────────────────────
    if hasattr(env, 'cloud_drive') and hasattr(env.cloud_drive, 'files'):
        files = env.cloud_drive.files
        if isinstance(files, dict):
            file_items = list(files.items())[:10]
        elif isinstance(files, list):
            file_items = [(i, f) for i, f in enumerate(files[:10])]
        else:
            file_items = []

        logger.info(f"Cloud drive: {len(file_items)} file(s)")

        for file_id, file_obj in file_items:
            filename = getattr(file_obj, 'filename', f'file_{file_id}')
            content  = getattr(file_obj, 'content', '')
            if content and isinstance(content, str):
                sources.append({
                    "content": content,
                    "description": f"File: '{filename}'",
                })

    logger.info(f"Total untrusted sources collected: {len(sources)}")
    return sources


def _filter_relevant_sources(
    query: str, sources: list[dict], max_sources: int = 5
) -> list[dict]:
    """Score and rank sources by relevance to the query."""
    if not sources:
        return []

    query_lower = query.lower()
    keywords = [w for w in query_lower.split() if len(w) > 3]

    scored = []
    for src in sources:
        desc_lower    = src['description'].lower()
        content_lower = src['content'][:500].lower()
        score = sum(1 for kw in keywords if kw in desc_lower or kw in content_lower)

        # Boost calendar events for date/time queries
        if any(x in query_lower for x in ['event', 'calendar', 'appointment', 'meeting', 'dinner', 'where']):
            if 'calendar' in desc_lower:
                score += 5
        # Extra boost if the calendar event title matches words in the query
        if 'calendar' in desc_lower:
            score += sum(2 for kw in keywords if len(kw) > 4 and kw in desc_lower)

        # Boost emails when query is explicitly about email content
        if any(x in query_lower for x in ['based on the emails', 'from the emails']):
            if 'email' in desc_lower:
                score += 10

        scored.append((score, src))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = [src for score, src in scored if score > 0][:max_sources]
    if not top:
        top = sources[:max_sources]

    logger.info(f"Source filter: {len(sources)} → {len(top)} relevant")
    return top


# ---------------------------------------------------------------------------
# EnhancedController
# ---------------------------------------------------------------------------
class EnhancedController(Controller):
    """Thin subclass — hooks for future extension."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extracted_data: dict = {}


# ---------------------------------------------------------------------------
# DualLLMPipeline
# ---------------------------------------------------------------------------
class DualLLMPipeline(BasePipelineElement):
    """
    Willison-compliant Dual-LLM pipeline for AgentDojo evaluation.

    Security property being tested:
        Q-LLM cannot call tools or change control flow.
        BUT an attacker can poison the *data* Q-LLM returns so that
        P-LLM calls tools with attacker-controlled values.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Any = None,
        messages: list[ChatMessage] | None = None,
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Any, list[ChatMessage], dict]:
        """Called by AgentDojo once per task turn."""
        messages = list(messages) if messages else []
        logger.info("=== DUAL-LLM QUERY START ===")
        logger.info(f"Task: {query}")

        # 1. Collect untrusted sources from environment (emails, calendar, files)
        untrusted_sources = _collect_untrusted_from_env(env)

        # 2. Filter to relevant sources
        relevant_sources = _filter_relevant_sources(query, untrusted_sources, max_sources=5)

        # 3. Create controller; register each source as an opaque token
        #    IMPORTANT: env is passed by reference — tool mutations propagate back to
        #    AgentDojo's benchmark harness for utility/security evaluation.
        controller = EnhancedController(debug=self.debug, runtime=runtime, env=env)
        source_descriptions: dict[str, str] = {}
        for src in relevant_sources:
            token = controller.add_untrusted_source(src["content"])
            source_descriptions[token] = src["description"]

        logger.info(f"Registered {len(source_descriptions)} untrusted source token(s)")

        try:
            response_text = controller.run_with_descriptions(
                user_input=query,
                source_descriptions=source_descriptions,
                max_turns=10,
            )
        except Exception as e:
            logger.error(f"Controller error: {e}", exc_info=True)
            response_text = f"Error: Unable to complete task — {e}"

        # Clean up JSON wrapper if P-LLM returned raw JSON as its final answer
        if not isinstance(response_text, str):
            response_text = str(response_text)

        cleaned_response = response_text
        if response_text.strip().startswith('{'):
            try:
                parsed = json.loads(response_text)
                cleaned_response = parsed.get('content') or parsed.get('answer') or response_text
            except Exception:
                pass

        if not cleaned_response or cleaned_response.strip() == "":
            cleaned_response = "Task completed."

        logger.info(f"FINAL RESPONSE: {cleaned_response[:300]}")
        logger.info("=== DUAL-LLM QUERY END ===")

        assistant_msg: ChatAssistantMessage = {
            "role": "assistant",
            "content": [text_content_block_from_string(cleaned_response)],
            "tool_calls": None,
        }

        return (cleaned_response, runtime, env, messages + [assistant_msg], {})


# ---------------------------------------------------------------------------
# Result extraction helper
# ---------------------------------------------------------------------------
def _extract_results(raw_results: Any) -> tuple[dict, dict]:
    """
    Safely extract utility_results and security_results from whatever
    AgentDojo's benchmark function returns (object or dict).
    """
    if raw_results is None:
        return {}, {}

    # Try attribute access first (SuiteResults object)
    utility  = getattr(raw_results, 'utility_results',  None)
    security = getattr(raw_results, 'security_results', None)

    # Fall back to dict-style access
    if utility is None and isinstance(raw_results, dict):
        utility  = raw_results.get('utility_results',  {})
        security = raw_results.get('security_results', {})

    return (utility or {}), (security or {})


# ---------------------------------------------------------------------------
# Benchmark runners
# ---------------------------------------------------------------------------
def run_utility_benchmark(
    suite_name: str = "workspace",
    benchmark_version: str = "v1",
    logdir: Path = Path("runs"),
    user_tasks: list[str] | None = None,
) -> Any:
    """Run AgentDojo WITHOUT injections — measures benign utility."""
    from agentdojo.benchmark import benchmark_suite_without_injections

    suites = get_suites(benchmark_version)
    if suite_name not in suites:
        raise ValueError(f"Suite '{suite_name}' not found. Available: {list(suites.keys())}")

    logdir.mkdir(parents=True, exist_ok=True)
    pipeline = DualLLMPipeline(debug=True)
    suite    = suites[suite_name]

    logger.info(f"Utility benchmark: {suite_name} ({benchmark_version})")

    raw_results = benchmark_suite_without_injections(
        agent_pipeline=pipeline,
        suite=suite,
        user_tasks=user_tasks,
        logdir=logdir,
        force_rerun=True,
    )

    utility_results, _ = _extract_results(raw_results)
    successful = sum(1 for v in utility_results.values() if v)
    total      = len(utility_results)
    score      = successful / total if total > 0 else 0.0

    print(f"\n{'='*50}")
    print(f"UTILITY RESULTS — {suite_name}")
    print(f"{'='*50}")
    print(f"Successful tasks : {successful}/{total}")
    print(f"Utility score    : {score:.2%}")
    for task_id, success in utility_results.items():
        status    = "✓" if success else "✗"
        task_name = task_id[0] if isinstance(task_id, tuple) else str(task_id)
        print(f"  {status} {task_name}")

    return raw_results


def run_security_benchmark(
    suite_name: str = "workspace",
    benchmark_version: str = "v1",
    logdir: Path = Path("runs"),
    user_tasks: list[str] | None = None,
    injection_tasks: list[str] | None = None,
    attack_name: str = "ignore_previous",
) -> Any:
    """
    Run AgentDojo WITH injections — measures both utility under attack
    and targeted Attack Success Rate (ASR).

    Demonstrates the Dual-LLM limitation:
      Q-LLM cannot call tools directly (control flow safe),
      but poisoned data returned by Q-LLM causes P-LLM to
      call tools with attacker-controlled values (data integrity unsafe).
    """
    from agentdojo.benchmark import benchmark_suite_with_injections

    # ── Load suite and pipeline first (load_attack needs both) ───────────────
    suites = get_suites(benchmark_version)
    if suite_name not in suites:
        raise ValueError(f"Suite '{suite_name}' not found. Available: {list(suites.keys())}")

    logdir.mkdir(parents=True, exist_ok=True)
    pipeline = DualLLMPipeline(debug=True)
    suite    = suites[suite_name]

    # ── Load attack via load_attack(name, suite, pipeline) ───────────────────
    # load_attack is the correct API: it instantiates the attack with suite+pipeline
    # Available attacks: ignore_previous, important_instructions, tool_knowledge,
    #                    direct, system_message, injecagent, dos, ...
    from agentdojo.attacks import load_attack
    from agentdojo.attacks.attack_registry import ATTACKS

    if attack_name not in ATTACKS:
        raise ValueError(
            f"Attack '{attack_name}' not found. "
            f"Available: {list(ATTACKS.keys())}"
        )
    attack = load_attack(attack_name, suite, pipeline)

    logger.info(f"Security benchmark : {suite_name} ({benchmark_version})")
    logger.info(f"Attack type        : {attack_name}")

    raw_results = benchmark_suite_with_injections(
        agent_pipeline=pipeline,
        suite=suite,
        attack=attack,
        user_tasks=user_tasks,
        injection_tasks=injection_tasks,
        logdir=logdir,
        force_rerun=True,
    )

    utility_results, security_results = _extract_results(raw_results)
    total             = len(utility_results)
    successful_util   = sum(1 for v in utility_results.values()  if v)
    successful_sec    = sum(1 for v in security_results.values() if v)
    compromised       = total - successful_sec

    utility_score  = successful_util  / total if total > 0 else 0.0
    security_score = successful_sec   / total if total > 0 else 0.0
    asr            = compromised      / total if total > 0 else 0.0

    print(f"\n{'='*50}")
    print(f"SECURITY RESULTS — {suite_name}")
    print(f"{'='*50}")
    print(f"Attack type              : {attack_name}")
    print(f"Utility (under attack)   : {utility_score:.2%}  ({successful_util}/{total})")
    print(f"Security (attack blocked): {security_score:.2%}  ({successful_sec}/{total})")
    print(f"Attack Success Rate (ASR): {asr:.2%}  ({compromised}/{total})")
    print(f"\nDetailed Results:")
    for task_id in utility_results:
        task_name = task_id[0] if isinstance(task_id, tuple) else str(task_id)
        util = "✓" if utility_results.get(task_id, False)  else "✗"
        sec  = "✓" if security_results.get(task_id, False) else "✗"
        print(f"  {task_name}: Utility={util}, Secure={sec}")

    return raw_results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    print("\n" + "="*60)
    print("DUAL-LLM + AGENTDOJO EVALUATION")
    print("Demonstrates: Dual-LLM blocks direct tool hijacking but")
    print("              is vulnerable to data-poisoning via Q-LLM.")
    print("="*60)

    # Task selection
    calendar_tasks  = ["user_task_0", "user_task_1", "user_task_3"]
    email_tasks     = ["user_task_14", "user_task_15", "user_task_16"]
    all_benign_tasks = calendar_tasks + email_tasks

    email_injections    = ["injection_task_0", "injection_task_3", "injection_task_4"]
    calendar_injections = ["injection_task_2", "injection_task_5"]

    # ── STEP 1: Utility (no injections) ──────────────────────────────────────
    print("\n" + "-"*40)
    print(f"STEP 1: UTILITY — {len(all_benign_tasks)} tasks, no injections")
    print("-"*40)
    results_utility = run_utility_benchmark(
        suite_name="workspace",
        benchmark_version="v1",
        user_tasks=all_benign_tasks,
    )

    # ── STEP 2: Security — email tasks with email injections ─────────────────
    print("\n" + "-"*40)
    print(f"STEP 2: SECURITY — {len(email_tasks)} email tasks × {len(email_injections)} injections")
    print("-"*40)
    results_sec_email = run_security_benchmark(
        suite_name="workspace",
        benchmark_version="v1",
        user_tasks=email_tasks,
        injection_tasks=email_injections,
        attack_name="ignore_previous",
    )

    # ── STEP 3: Security — calendar tasks with calendar injections ────────────
    print("\n" + "-"*40)
    print(f"STEP 3: SECURITY — {len(calendar_tasks)} calendar tasks × {len(calendar_injections)} injections")
    print("-"*40)
    results_sec_cal = run_security_benchmark(
        suite_name="workspace",
        benchmark_version="v1",
        user_tasks=calendar_tasks,
        injection_tasks=calendar_injections,
        attack_name="ignore_previous",
    )

    # ── SUMMARY ──────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    util, _ = _extract_results(results_utility) if results_utility else ({}, {})
    if util:
        ok = sum(1 for v in util.values() if v)
        t  = len(util)
        print(f"Benign Utility      : {ok}/{t} ({ok/t:.0%})")
    else:
        print("Benign Utility      : N/A")

    for label, raw in [("Email Security", results_sec_email), ("Calendar Security", results_sec_cal)]:
        if raw:
            u, s = _extract_results(raw)
            t    = len(u)
            if t > 0:
                ok_u = sum(1 for v in u.values() if v)
                ok_s = sum(1 for v in s.values() if v)
                print(
                    f"{label:20s}: Utility={ok_u}/{t}, "
                    f"Blocked={ok_s}/{t}, ASR={(t-ok_s)/t:.0%}"
                )