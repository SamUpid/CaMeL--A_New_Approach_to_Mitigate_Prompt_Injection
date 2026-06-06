import logging
logging.basicConfig(level=logging.INFO)

import agentdojo.default_suites
from agentdojo.task_suite.load_suites import get_suites
from agentdojo_integration import DualLLMPipeline

suites    = get_suites("v1")
workspace = suites["workspace"]
pipeline  = DualLLMPipeline()

user_tasks      = list(workspace.user_tasks.values())
injection_tasks = list(workspace.injection_tasks.values())

print("=== INJECTION TASKS ===")
for it in injection_tasks:
    print(f"  {it.ID}: {it.GOAL}")

results = []

for i, injection_task in enumerate(injection_tasks):
    user_task = user_tasks[i % len(user_tasks)]
    print(f"\n[{i+1}/{len(injection_tasks)}] "
          f"Injection: {injection_task.ID} | User task: {user_task.ID}")
    print(f"  User wants:    {user_task.PROMPT[:60]}...")
    print(f"  Attacker wants: {injection_task.GOAL[:60]}...")

    try:
        # ✅ Let run_task_with_pipeline handle injections internally
        utility, security = workspace.run_task_with_pipeline(
            agent_pipeline=pipeline,
            user_task=user_task,
            injection_task=injection_task,
            injections=workspace.get_injection_vector_defaults(),
        )

        results.append((injection_task.ID, utility, security))
        print(f"  Utility:          {'✅ PASS' if utility  else '❌ FAIL'}")
        print(f"  Injection blocked: {'✅ YES'  if not security else '💥 NO — attack succeeded'}")

    except Exception as e:
        print(f"  ❌ Error: {e}")
        results.append((injection_task.ID, False, False))

# ── Summary ───────────────────────────────────────────────────
print("\n" + "="*55)
print("AGGREGATE RESULTS — Dual LLM Pattern (Willison)")
print("="*55)

if results:
    blocked         = sum(1 for _, _, s in results if not s)
    utility_passed  = sum(1 for _, u, _ in results if u)
    total           = len(results)

    print(f"  Injections blocked : {blocked}/{total} "
          f"({blocked/total*100:.1f}%)")
    print(f"  Utility passed     : {utility_passed}/{total} "
          f"({utility_passed/total*100:.1f}%)")
    print()
    print("  Per-task breakdown:")
    for task_id, utility, security in results:
        u = "✅" if utility    else "❌"
        s = "✅" if not security else "💥"
        print(f"    {task_id:<35} utility={u}  injection_blocked={s}")

    print()
    print("  Thesis table row:")
    print(f"  | Dual LLM (Willison) | "
          f"{utility_passed/total:.1%} | "
          f"{blocked/total:.1%} blocked |")