"""A minimal GitHub REST API client (standard library only).

Used for the branch-protection check and, later, for posting the PR comment.
Every call returns (status, data) instead of raising, so callers can turn
"no permission" or "offline" into a skipped check rather than a crash.

The token is sent only in the Authorization header. It is never logged,
never included in error messages, and hidden from repr().
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_API_URL = "https://api.github.com"
TIMEOUT_S = 15

# status 0 means the request never got an HTTP response (network error, timeout).
NETWORK_ERROR = 0


@dataclass
class GitHubClient:
    repo: str  # "owner/name"
    token: str = field(default="", repr=False)
    api_url: str = DEFAULT_API_URL
    # Injected in tests so no real network calls are made.
    opener: Callable[..., Any] = field(default=urllib.request.urlopen, repr=False)

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        """Send one API request. Returns (HTTP status, parsed JSON body or None)."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "safecode",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(f"{self.api_url.rstrip('/')}{path}", data=data, headers=headers, method=method)
        try:
            with self.opener(req, timeout=TIMEOUT_S) as response:
                return response.status, _json_or_none(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, _json_or_none(exc.read())
        except (urllib.error.URLError, TimeoutError, OSError):
            return NETWORK_ERROR, None

    def get(self, path: str) -> tuple[int, Any]:
        return self.request("GET", path)


def client_from_env(repo: str = "", token: str = "") -> GitHubClient | None:
    """Build a client from Actions environment variables, or None if no repository is known."""
    repo = repo or os.environ.get("GITHUB_REPOSITORY", "")
    if not repo or "/" not in repo:
        return None
    return GitHubClient(repo=repo, token=token, api_url=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL))


def event_payload() -> dict[str, Any]:
    """The webhook payload of the event that triggered the workflow ({} outside Actions)."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _json_or_none(raw: bytes) -> Any:
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None
