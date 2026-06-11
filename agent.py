#!/usr/bin/env python3
"""
SentinelMCP Builder Agent
=========================
Autonomous coding agent that uses Claude to build, test, and commit
SentinelMCP features with minimal human intervention.

Usage:
    python agent.py "Build Layer 1: schema cache and rug pull detection"
    python agent.py "Fix all failing tests in test_schema_layer.py"
    python agent.py "Add Splunk SIEM integration to alerts.py"

Requirements:
    pip install anthropic rich gitpython pytest subprocess32

Setup:
    export ANTHROPIC_API_KEY=your_key_here
    Place this file in the root of your sentinelmcp/ repo
"""

import os
import sys
import json
import subprocess
import anthropic
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ─── Configuration ─────────────────────────────────────────────────────────────

SKILL_PATH = Path("SKILL.md")
MAX_ITERATIONS = 5       # Max build→test→fix cycles before asking human
MAX_TOKENS    = 8096
MODEL         = "claude-opus-4-5"

# Files the agent is ALLOWED to create or modify
ALLOWED_PATHS = [
    "app/", "tests/", "worker/", "dashboard/src/",
    "docker-compose.yml", "Dockerfile", "pyproject.toml",
    "helm/templates/", ".env.example"
]

# Files the agent must NEVER touch
PROTECTED_PATHS = [
    "SKILL.md", ".env", "agent.py",
    ".git/", "*.pem", "*.key", "secrets/"
]

# ─── Helpers ───────────────────────────────────────────────────────────────────

def load_skill() -> str:
    if not SKILL_PATH.exists():
        console.print("[red]SKILL.md not found. Run from repo root.[/red]")
        sys.exit(1)
    return SKILL_PATH.read_text()


def read_file(path: str) -> str:
    try:
        return Path(path).read_text()
    except FileNotFoundError:
        return f"[File not found: {path}]"


def write_file(path: str, content: str) -> bool:
    """Write file — checks against ALLOWED_PATHS first."""
    p = Path(path)
    allowed = any(str(p).startswith(a.rstrip("/")) for a in ALLOWED_PATHS)
    protected = any(str(p).endswith(a.lstrip("*")) for a in PROTECTED_PATHS)

    if protected or not allowed:
        console.print(f"[red]BLOCKED: agent tried to write {path}[/red]")
        return False

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    console.print(f"[green]✓ Written: {path}[/green]")
    return True


def run_tests() -> tuple[bool, str]:
    """Run pytest, return (passed, output)."""
    result = subprocess.run(
        ["python", "-m", "pytest", "tests/", "-v", "--tb=short", "--no-header", "-q"],
        capture_output=True, text=True, timeout=120
    )
    output = result.stdout + result.stderr
    passed = result.returncode == 0
    return passed, output


def git_commit(message: str) -> bool:
    """Stage all changes and commit."""
    try:
        subprocess.run(["git", "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", message], check=True, capture_output=True)
        console.print(f"[green]✓ Committed: {message}[/green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Git commit skipped: {e}[/yellow]")
        return False


def get_relevant_files(goal: str) -> dict[str, str]:
    """Read files most likely relevant to the current goal."""
    candidates = []

    # Always include existing structure
    for pattern in ["app/**/*.py", "tests/**/*.py", "worker/*.py"]:
        candidates.extend(Path(".").glob(pattern))

    # Limit to 10 most recently modified to keep context manageable
    candidates = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[:10]

    return {str(p): p.read_text() for p in candidates if p.exists()}


def parse_agent_response(response_text: str) -> list[dict]:
    """
    Parse Claude's response for file operations.
    Claude should respond with JSON blocks like:
    {
        "action": "write_file",
        "path": "app/gateway/schema_layer.py",
        "content": "..."
    }
    """
    import re
    operations = []

    # Find JSON blocks in response
    json_pattern = r'```json\n(.*?)\n```'
    matches = re.findall(json_pattern, response_text, re.DOTALL)

    for match in matches:
        try:
            op = json.loads(match)
            if isinstance(op, list):
                operations.extend(op)
            elif isinstance(op, dict):
                operations.append(op)
        except json.JSONDecodeError:
            pass

    # Also look for direct file blocks
    file_pattern = r'```python\n# FILE: (.*?)\n(.*?)\n```'
    file_matches = re.findall(file_pattern, response_text, re.DOTALL)
    for path, content in file_matches:
        operations.append({"action": "write_file", "path": path.strip(), "content": content})

    return operations


# ─── System prompt ─────────────────────────────────────────────────────────────

def build_system_prompt(skill: str) -> str:
    return f"""You are an autonomous software engineer building SentinelMCP.

PROJECT CONTEXT:
{skill}

YOUR JOB:
Build production-ready code that matches the architecture, coding standards, and constraints
in the SKILL.md above. Write complete, working implementations — not stubs or placeholders.

OUTPUT FORMAT:
When you need to create or modify files, output them as JSON blocks:

```json
[
  {{
    "action": "write_file",
    "path": "app/gateway/schema_layer.py",
    "content": "# complete file content here"
  }},
  {{
    "action": "write_file", 
    "path": "tests/test_schema_layer.py",
    "content": "# complete test file content"
  }}
]
```

RULES:
1. Always write the complete file — never partial snippets
2. Always write tests alongside implementation
3. Follow the coding standards exactly (async, type hints, structlog, no secrets)
4. If tests fail, analyze the failure and fix — don't ask the human
5. When all tests pass, output: COMMIT: <commit message following the format in SKILL.md>
6. If you're blocked and need human input, output: HUMAN_NEEDED: <specific question>
7. Never modify SKILL.md, .env, agent.py, or any protected paths
8. Keep latency constraints in mind — Layer 2 must never call external APIs
"""


# ─── Main agent loop ───────────────────────────────────────────────────────────

def run_agent(goal: str):
    console.print(Panel(f"[bold green]SentinelMCP Builder Agent[/bold green]\nGoal: {goal}", border_style="green"))

    client   = anthropic.Anthropic()
    skill    = load_skill()
    messages = []

    # Build initial context
    relevant_files = get_relevant_files(goal)
    file_context   = "\n\n".join(
        f"=== {path} ===\n{content}"
        for path, content in relevant_files.items()
    ) if relevant_files else "No existing files yet — starting fresh."

    initial_message = f"""Goal: {goal}

Current codebase state:
{file_context}

Build this feature completely. Write implementation + tests. Follow SKILL.md standards.
After writing files, I will run the tests and report results back to you."""

    messages.append({"role": "user", "content": initial_message})

    for iteration in range(MAX_ITERATIONS):
        console.print(f"\n[blue]── Iteration {iteration + 1}/{MAX_ITERATIONS} ──[/blue]")

        # Call Claude
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Claude is building...", total=None)
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=build_system_prompt(skill),
                messages=messages,
            )
            progress.remove_task(task)

        response_text = response.content[0].text
        messages.append({"role": "assistant", "content": response_text})

        # Check for human needed
        if "HUMAN_NEEDED:" in response_text:
            question = response_text.split("HUMAN_NEEDED:")[1].split("\n")[0].strip()
            console.print(f"\n[yellow]⚠ Agent needs input:[/yellow] {question}")
            human_input = input("Your answer: ").strip()
            messages.append({"role": "user", "content": f"Human answer: {human_input}\nContinue building."})
            continue

        # Parse and execute file operations
        operations = parse_agent_response(response_text)
        files_written = 0

        if operations:
            console.print(f"\n[cyan]Writing {len(operations)} files...[/cyan]")
            for op in operations:
                if op.get("action") == "write_file":
                    if write_file(op["path"], op["content"]):
                        files_written += 1
        else:
            # Show Claude's response if no file operations
            console.print(Panel(response_text[:1000] + ("..." if len(response_text) > 1000 else ""), title="Claude response"))

        # Run tests
        if files_written > 0:
            console.print("\n[cyan]Running tests...[/cyan]")
            passed, test_output = run_tests()

            if passed:
                console.print("[green]✓ All tests passing![/green]")

                # Check for commit instruction
                if "COMMIT:" in response_text:
                    commit_msg = response_text.split("COMMIT:")[1].split("\n")[0].strip()
                    git_commit(commit_msg)

                console.print(Panel("[bold green]✓ Feature complete![/bold green]", border_style="green"))
                return True

            else:
                console.print(f"[red]✗ Tests failed[/red]")
                console.print(Syntax(test_output[-2000:], "text", theme="monokai"))

                # Feed failure back to Claude
                messages.append({
                    "role": "user",
                    "content": f"Tests failed. Here's the output:\n\n{test_output}\n\nAnalyze the failures and fix the code."
                })
        else:
            if iteration == 0:
                messages.append({"role": "user", "content": "I don't see any file operations in your response. Please output the complete files in the JSON format specified."})

    console.print("[yellow]Max iterations reached. Review the output above and continue manually.[/yellow]")
    return False


# ─── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python agent.py 'Build Layer 1: schema cache and rug pull detection'[/red]")
        sys.exit(1)

    goal = " ".join(sys.argv[1:])

    if not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[red]Set ANTHROPIC_API_KEY environment variable first[/red]")
        sys.exit(1)

    run_agent(goal)
