"""Post the report as a single, self-updating pull request comment.

SAFECODE keeps exactly one comment per PR. The comment starts with a hidden
HTML marker; on each run we look for a comment starting with that marker and
edit it, or create one if none exists. This avoids a new comment on every push.

Common failure: on pull requests from forks, GitHub gives the workflow a
read-only token, so commenting returns 403. That is reported as a note in
the job summary rather than failing the job.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from safecode.github import NETWORK_ERROR, GitHubClient

MARKER = "<!-- safecode-report -->"
# GitHub rejects comment bodies over 65,536 characters; leave headroom for the marker.
MAX_BODY_CHARS = 65_000
_MAX_PAGES = 10  # 1,000 comments is plenty to find our own


def pull_request_number(event: dict[str, Any]) -> int | None:
    """The PR number for pull_request / pull_request_target events, else None."""
    number = (event.get("pull_request") or {}).get("number")
    return number if isinstance(number, int) else None


def fit_report(render: Callable[[int], str]) -> str:
    """Render the report with as many full findings as fit in one comment.

    render(max_findings) returns the Markdown. We try progressively smaller
    limits; the summary, grade, and checklist are always kept.
    """
    for limit in (60, 30, 15, 5, 0):
        body = f"{MARKER}\n{render(limit)}"
        if len(body) <= MAX_BODY_CHARS:
            return body
    note = "\n\n*Report truncated to fit GitHub's comment size limit.*\n"
    return body[: MAX_BODY_CHARS - len(note)] + note


def upsert_comment(gh: GitHubClient, number: int, body: str) -> tuple[bool, str]:
    """Create or update SAFECODE's comment on PR `number`. Returns (ok, human-readable outcome)."""
    existing = _find_existing(gh, number)
    status, action = 0, "posted"
    if existing is not None:
        status, _ = gh.request("PATCH", f"/repos/{gh.repo}/issues/comments/{existing}", {"body": body})
        action = "updated"
    if existing is None or status == 403:
        # 403 on PATCH: the marked comment belongs to someone else (e.g. a copy-paste); post our own.
        status, _ = gh.request("POST", f"/repos/{gh.repo}/issues/{number}/comments", {"body": body})
        action = "posted"

    if status in (200, 201):
        return True, f"Report {action} on pull request #{number}."
    if status in (401, 403, 404):
        return False, (
            f"Couldn't comment on pull request #{number} (HTTP {status}). Pull requests from forks get a "
            "read-only token; otherwise grant `pull-requests: write` in the workflow's permissions."
        )
    if status == NETWORK_ERROR:
        return False, f"Couldn't comment on pull request #{number}: network error."
    return False, f"Couldn't comment on pull request #{number} (HTTP {status})."


def _find_existing(gh: GitHubClient, number: int) -> int | None:
    """ID of a previous SAFECODE comment on this PR, if any."""
    for page in range(1, _MAX_PAGES + 1):
        status, comments = gh.get(f"/repos/{gh.repo}/issues/{number}/comments?per_page=100&page={page}")
        if status != 200 or not isinstance(comments, list):
            return None
        for comment in comments:
            # startswith (not "in"): a human quoting our comment in a reply must not be overwritten.
            if isinstance(comment, dict) and str(comment.get("body", "")).startswith(MARKER):
                return comment.get("id")
        if len(comments) < 100:
            return None
    return None
