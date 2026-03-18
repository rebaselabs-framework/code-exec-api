#!/usr/bin/env python3
"""
CodeExec CLI — Command-line interface for the CodeExec API.

Sandboxed code execution from the terminal — run Python and JavaScript safely.

Usage:
    codeexec python "<code>"                   # Run Python snippet
    codeexec python --file script.py           # Run a Python file
    codeexec js "<code>"                       # Run JavaScript snippet
    codeexec js --file script.js               # Run a JavaScript file
    codeexec run <language> "<code>"           # Generic run (python|javascript)
    codeexec batch --file snippets.json        # Batch-run multiple snippets
    codeexec session create                    # Create a persistent Python session
    codeexec session run <session_id> "<code>" # Run code in session
    codeexec session delete <session_id>       # Delete a session
    codeexec api <METHOD> <path> [--body ...]  # Raw API call

Configuration:
    CODEEXEC_API_KEY   — API key (or pass --key)
    CODEEXEC_BASE_URL  — API base URL (default: https://code-exec-api.rebaselabs.online)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import click

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

DEFAULT_BASE_URL = "https://code-exec-api.rebaselabs.online"
VERSION = "1.0.0"


def _get_client(base_url: str, api_key: Optional[str]) -> "httpx.Client":
    if not _HTTPX_AVAILABLE:
        click.echo("Error: httpx is required. Install: pip install httpx", err=True)
        sys.exit(1)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    return httpx.Client(base_url=base_url, headers=headers, timeout=60.0)


def _resolve_config(ctx_obj: dict) -> tuple[str, Optional[str]]:
    base_url = ctx_obj.get("base_url") or os.environ.get("CODEEXEC_BASE_URL") or DEFAULT_BASE_URL
    api_key = ctx_obj.get("api_key") or os.environ.get("CODEEXEC_API_KEY")
    return base_url.rstrip("/"), api_key


def _handle_error(resp: "httpx.Response") -> None:
    try:
        err = resp.json()
        msg = err.get("detail") or err.get("error") or json.dumps(err)
    except Exception:
        msg = resp.text
    click.echo(f"Error {resp.status_code}: {msg}", err=True)
    sys.exit(1)


def _print_exec_result(data: dict, output: str = "pretty") -> None:
    """Print execution result in a readable format."""
    if output == "json":
        click.echo(json.dumps(data))
        return

    success = data.get("success", False)
    stdout = data.get("stdout", "")
    stderr = data.get("stderr", "")
    result = data.get("result")
    runtime = data.get("runtime_ms")
    language = data.get("language", "")

    status_icon = "✓" if success else "✗"
    status_label = "OK" if success else "FAILED"
    click.echo(f"{status_icon} [{language}] {status_label}", err=False)

    if stdout:
        click.echo(stdout)
    if result is not None and not stdout:
        click.echo(repr(result))
    if stderr:
        click.echo(click.style(f"STDERR:\n{stderr}", fg="red"), err=True)
    if runtime is not None:
        click.echo(click.style(f"  runtime: {runtime}ms", dim=True), err=True)


# ──────────────────────────────────────────────
# Root CLI
# ──────────────────────────────────────────────

@click.group()
@click.version_option(VERSION, prog_name="codeexec")
@click.option("--key", envvar="CODEEXEC_API_KEY", default=None, help="API key")
@click.option("--base-url", envvar="CODEEXEC_BASE_URL", default=None, help="API base URL")
@click.option("--output", "-o", type=click.Choice(["pretty", "json"]), default="pretty", help="Output format")
@click.pass_context
def cli(ctx: click.Context, key: Optional[str], base_url: Optional[str], output: str) -> None:
    """CodeExec CLI — sandboxed code execution for AI agents.

    Docs: https://code-exec-api.rebaselabs.online
    """
    ctx.ensure_object(dict)
    ctx.obj["api_key"] = key
    ctx.obj["base_url"] = base_url
    ctx.obj["output"] = output


# ──────────────────────────────────────────────
# python
# ──────────────────────────────────────────────

@cli.command("python")
@click.argument("code", required=False)
@click.option("--file", "-f", "code_file", type=click.Path(exists=True), default=None, help="Python file to run")
@click.option("--timeout", default=30, help="Execution timeout in seconds (max 30)")
@click.pass_context
def cmd_python(ctx: click.Context, code: Optional[str], code_file: Optional[str], timeout: int) -> None:
    """Run a Python snippet or file in the sandbox.

    Examples:\n
      codeexec python "print(2 + 2)"\n
      codeexec python --file analysis.py\n
      echo "import math; print(math.pi)" | codeexec python -
    """
    if code_file:
        code = Path(code_file).read_text()
    elif code == "-" or (not code and not sys.stdin.isatty()):
        code = sys.stdin.read()
    elif not code:
        click.echo("Error: provide CODE argument, --file, or pipe code via stdin", err=True)
        sys.exit(1)

    base_url, api_key = _resolve_config(ctx.obj)
    output = ctx.obj.get("output", "pretty")

    with _get_client(base_url, api_key) as client:
        resp = client.post("/api/execute/python", json={"code": code, "timeout": timeout})
        if resp.status_code not in (200, 201):
            _handle_error(resp)
        _print_exec_result(resp.json(), output)


# ──────────────────────────────────────────────
# js
# ──────────────────────────────────────────────

@cli.command("js")
@click.argument("code", required=False)
@click.option("--file", "-f", "code_file", type=click.Path(exists=True), default=None, help="JavaScript file to run")
@click.option("--timeout", default=30, help="Execution timeout in seconds (max 30)")
@click.pass_context
def cmd_js(ctx: click.Context, code: Optional[str], code_file: Optional[str], timeout: int) -> None:
    """Run a JavaScript snippet or file in the Node.js sandbox.

    Examples:\n
      codeexec js "console.log(Math.PI)"\n
      codeexec js --file transform.js\n
      echo "console.log(JSON.stringify({a:1}))" | codeexec js -
    """
    if code_file:
        code = Path(code_file).read_text()
    elif code == "-" or (not code and not sys.stdin.isatty()):
        code = sys.stdin.read()
    elif not code:
        click.echo("Error: provide CODE argument, --file, or pipe code via stdin", err=True)
        sys.exit(1)

    base_url, api_key = _resolve_config(ctx.obj)
    output = ctx.obj.get("output", "pretty")

    with _get_client(base_url, api_key) as client:
        resp = client.post("/api/execute/js", json={"code": code, "timeout": timeout})
        if resp.status_code not in (200, 201):
            _handle_error(resp)
        _print_exec_result(resp.json(), output)


# ──────────────────────────────────────────────
# run (generic)
# ──────────────────────────────────────────────

@cli.command("run")
@click.argument("language", type=click.Choice(["python", "javascript", "js"]))
@click.argument("code", required=False)
@click.option("--file", "-f", "code_file", type=click.Path(exists=True), default=None, help="Code file to run")
@click.option("--timeout", default=30, help="Execution timeout in seconds")
@click.pass_context
def cmd_run(ctx: click.Context, language: str, code: Optional[str], code_file: Optional[str], timeout: int) -> None:
    """Run code in any supported language.

    Examples:\n
      codeexec run python "sum([1,2,3])"\n
      codeexec run javascript "Math.random()"
    """
    if language == "js":
        language = "javascript"

    if code_file:
        code = Path(code_file).read_text()
    elif code == "-" or (not code and not sys.stdin.isatty()):
        code = sys.stdin.read()
    elif not code:
        click.echo("Error: provide CODE argument, --file, or pipe via stdin", err=True)
        sys.exit(1)

    base_url, api_key = _resolve_config(ctx.obj)
    output = ctx.obj.get("output", "pretty")

    with _get_client(base_url, api_key) as client:
        resp = client.post("/api/execute", json={"language": language, "code": code, "timeout": timeout})
        if resp.status_code not in (200, 201):
            _handle_error(resp)
        _print_exec_result(resp.json(), output)


# ──────────────────────────────────────────────
# batch
# ──────────────────────────────────────────────

@cli.command("batch")
@click.option("--file", "-f", "snippets_file", type=click.Path(exists=True), required=True,
              help="JSON file with list of {language, code} objects (max 10)")
@click.pass_context
def cmd_batch(ctx: click.Context, snippets_file: str) -> None:
    """Run up to 10 code snippets concurrently.

    The input file must be a JSON array like:\n
      [\n
        {"language": "python", "code": "print(1+1)"},\n
        {"language": "javascript", "code": "console.log('hi')"}\n
      ]
    """
    try:
        snippets = json.loads(Path(snippets_file).read_text())
    except Exception as e:
        click.echo(f"Error reading snippets file: {e}", err=True)
        sys.exit(1)

    if not isinstance(snippets, list):
        click.echo("Error: snippets file must contain a JSON array", err=True)
        sys.exit(1)

    base_url, api_key = _resolve_config(ctx.obj)
    output = ctx.obj.get("output", "pretty")

    with _get_client(base_url, api_key) as client:
        resp = client.post("/api/execute/batch", json={"snippets": snippets})
        if resp.status_code not in (200, 201):
            _handle_error(resp)
        data = resp.json()

    if output == "json":
        click.echo(json.dumps(data))
        return

    results = data.get("results", [])
    for i, r in enumerate(results):
        click.echo(f"\n── Snippet {i+1} ──────────────")
        _print_exec_result(r, "pretty")

    total = data.get("total", len(results))
    succeeded = data.get("succeeded", sum(1 for r in results if r.get("success")))
    click.echo(f"\nBatch: {succeeded}/{total} succeeded")


# ──────────────────────────────────────────────
# session
# ──────────────────────────────────────────────

@cli.group("session")
@click.pass_context
def session_group(ctx: click.Context) -> None:
    """Manage persistent Python execution sessions."""
    ctx.ensure_object(dict)


@session_group.command("create")
@click.pass_context
def session_create(ctx: click.Context) -> None:
    """Create a new persistent Python session.

    Sessions maintain variable state between calls.
    They auto-expire after 10 minutes of inactivity.
    """
    base_url, api_key = _resolve_config(ctx.obj)
    output = ctx.obj.get("output", "pretty")

    with _get_client(base_url, api_key) as client:
        resp = client.post("/api/session/create")
        if resp.status_code not in (200, 201):
            _handle_error(resp)
        data = resp.json()

    if output == "json":
        click.echo(json.dumps(data))
        return

    session_id = data.get("session_id") or data.get("id")
    click.echo(f"Session created: {session_id}")
    click.echo(click.style(f"  Export: export CODEEXEC_SESSION={session_id}", dim=True))


@session_group.command("run")
@click.argument("session_id")
@click.argument("code", required=False)
@click.option("--file", "-f", "code_file", type=click.Path(exists=True), default=None)
@click.pass_context
def session_run(ctx: click.Context, session_id: str, code: Optional[str], code_file: Optional[str]) -> None:
    """Run code within an existing session (state persists).

    Examples:\n
      codeexec session run abc123 "x = 42"\n
      codeexec session run abc123 "print(x)"  # prints 42
    """
    if code_file:
        code = Path(code_file).read_text()
    elif code == "-" or (not code and not sys.stdin.isatty()):
        code = sys.stdin.read()
    elif not code:
        click.echo("Error: provide CODE argument, --file, or pipe via stdin", err=True)
        sys.exit(1)

    base_url, api_key = _resolve_config(ctx.obj)
    output = ctx.obj.get("output", "pretty")

    with _get_client(base_url, api_key) as client:
        resp = client.post("/api/session/execute", json={"session_id": session_id, "code": code})
        if resp.status_code not in (200, 201):
            _handle_error(resp)
        _print_exec_result(resp.json(), output)


@session_group.command("delete")
@click.argument("session_id")
@click.pass_context
def session_delete(ctx: click.Context, session_id: str) -> None:
    """Delete a session and free its resources."""
    base_url, api_key = _resolve_config(ctx.obj)

    with _get_client(base_url, api_key) as client:
        resp = client.delete(f"/api/session/{session_id}")
        if resp.status_code not in (200, 204):
            _handle_error(resp)
        click.echo(f"Session {session_id} deleted.")


# ──────────────────────────────────────────────
# api (raw passthrough)
# ──────────────────────────────────────────────

@cli.command("api")
@click.argument("method", type=click.Choice(["GET", "POST", "DELETE", "PATCH"], case_sensitive=False))
@click.argument("path")
@click.option("--body", "-b", default=None, help="JSON request body string")
@click.pass_context
def cmd_api(ctx: click.Context, method: str, path: str, body: Optional[str]) -> None:
    """Make a raw API call.

    Examples:\n
      codeexec api GET /health\n
      codeexec api GET /\n
      codeexec api POST /api/execute --body '{"language":"python","code":"print(1)"}'\n
      codeexec api DELETE /api/session/abc123
    """
    base_url, api_key = _resolve_config(ctx.obj)

    parsed_body = None
    if body:
        try:
            parsed_body = json.loads(body)
        except json.JSONDecodeError as e:
            click.echo(f"Error: invalid JSON body — {e}", err=True)
            sys.exit(1)

    path = path if path.startswith("/") else f"/{path}"

    with _get_client(base_url, api_key) as client:
        req_kwargs: dict = {}
        if parsed_body is not None:
            req_kwargs["json"] = parsed_body
        resp = client.request(method.upper(), path, **req_kwargs)
        try:
            data = resp.json()
            click.echo(json.dumps(data, indent=2))
        except Exception:
            click.echo(resp.text)
        if resp.status_code >= 400:
            sys.exit(1)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
