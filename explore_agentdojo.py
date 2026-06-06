from agentdojo.task_suite.load_suites import get_suite
from agentdojo.default_suites.v1 import workspace  # registers the suite

print("\n" + "="*60)
print("AGENTDOJO WORKSPACE SUITE — EXPLORATION")
print("="*60)

# Load workspace suite
suite = get_suite("v1", "workspace")

# ── 1. User tasks ─────────────────────────────────────────────
print(f"\n📋 Total user tasks: {len(suite.user_tasks)}")
print("\nFirst 5 user tasks (what the legitimate user wants):")
for i, (task_id, task) in enumerate(suite.user_tasks.items()):
    if i >= 5:
        break
    print(f"  [{i}] {task.PROMPT}")

# ── 2. Injection tasks ────────────────────────────────────────
print(f"\n💉 Total injection tasks: {len(suite.injection_tasks)}")
print("\nFirst 5 injection tasks (what the attacker wants):")
for i, (task_id, task) in enumerate(suite.injection_tasks.items()):
    if i >= 5:
        break
    print(f"  [{i}] {task.GOAL}")

# ── 3. Scale comparison ───────────────────────────────────────
total = len(suite.user_tasks) * len(suite.injection_tasks)
print(f"\n🔢 Total test combinations:")
print(f"   {len(suite.user_tasks)} user tasks × "
      f"{len(suite.injection_tasks)} injection tasks = {total}")
print(f"   (vs your 4 manual tests — this is the scale AgentDojo adds)")

# ── 4. Available tools ────────────────────────────────────────
print(f"\n🔧 Tools available in workspace:")
for tool in suite.tools:
    print(f"   - {tool.__name__}")

# ── 5. Peek at the environment data ──────────────────────────
print(f"\n📁 Peeking at workspace environment data:")
env = suite.load_and_inject_default_environment(injections={})
print(f"   Environment type: {type(env).__name__}")
print(f"   Has inbox:        {hasattr(env, 'inbox')}")
print(f"   Has calendar:     {hasattr(env, 'calendar')}")
print(f"   Has cloud_drive:  {hasattr(env, 'cloud_drive')}")

if hasattr(env, 'inbox'):
    emails = env.inbox.received[:3]
    print(f"\n   First 3 emails in inbox:")
    for email in emails:
        print(f"     From:    {email.sender}")
        print(f"     Subject: {email.subject}")
        print(f"     Preview: {email.body[:80]}...")
        print()

# ── 6. One complete test case example ────────────────────────
print("="*60)
print("EXAMPLE: One complete test case")
print("="*60)
user_task = list(suite.user_tasks.values())[0]
inj_task  = list(suite.injection_tasks.values())[0]
print(f"\nUser task  : {user_task.PROMPT}")
print(f"Injection  : {inj_task.GOAL}")
print(f"\nAgentDojo runs your agent on this combined scenario")
print(f"then automatically checks:")
print(f"  → Did agent complete the user task?  (utility score)")
print(f"  → Did agent execute the injection?   (attack success rate)")

# ── 7. Available attacks ──────────────────────────────────────
print("\n" + "="*60)
print("AVAILABLE ATTACKS")
print("="*60)
from agentdojo.attacks.attack_registry import ATTACKS
for name, attack in ATTACKS.items():
    print(f"   - {name}")

print("\n✅ Exploration complete — ready to run baseline agent.")