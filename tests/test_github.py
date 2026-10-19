"""Tests for the GitHub API client, with the network replaced by a fake opener."""

import io
import json
import urllib.error

from safecode.github import NETWORK_ERROR, GitHubClient, client_from_env

TOKEN = "ghs_faketoken1234567890"


class FakeResponse(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(json.dumps(body).encode())
        self.status = status


def recording_opener(status=200, body=None, error=None):
    seen = []

    def opener(request, timeout):
        seen.append(request)
        if error:
            raise error
        return FakeResponse(status, body)

    return opener, seen


def test_sends_token_and_api_version_headers():
    opener, seen = recording_opener(body={"ok": True})
    client = GitHubClient("octo/app", token=TOKEN, opener=opener)
    assert client.get("/repos/octo/app") == (200, {"ok": True})
    request = seen[0]
    assert request.full_url == "https://api.github.com/repos/octo/app"
    assert request.get_header("Authorization") == f"Bearer {TOKEN}"
    assert request.get_header("X-github-api-version") == "2022-11-28"


def test_anonymous_requests_have_no_auth_header():
    opener, seen = recording_opener(body={})
    GitHubClient("octo/app", opener=opener).get("/x")
    assert seen[0].get_header("Authorization") is None


def test_token_hidden_from_repr():
    assert TOKEN not in repr(GitHubClient("octo/app", token=TOKEN))


def test_http_error_returns_status():
    error = urllib.error.HTTPError("u", 403, "Forbidden", {}, io.BytesIO(b'{"message": "nope"}'))
    opener, _ = recording_opener(error=error)
    assert GitHubClient("octo/app", opener=opener).get("/x") == (403, {"message": "nope"})


def test_network_error_returns_zero():
    opener, _ = recording_opener(error=urllib.error.URLError("offline"))
    assert GitHubClient("octo/app", opener=opener).get("/x") == (NETWORK_ERROR, None)


def test_post_sends_json_body():
    opener, seen = recording_opener(status=201, body={"id": 1})
    assert GitHubClient("octo/app", opener=opener).request("POST", "/x", {"body": "hi"}) == (201, {"id": 1})
    assert json.loads(seen[0].data) == {"body": "hi"}
    assert seen[0].get_method() == "POST"


def test_client_from_env(monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    assert client_from_env() is None
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/app")
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3")
    client = client_from_env(token=TOKEN)
    assert (client.repo, client.api_url, client.token) == ("octo/app", "https://ghe.example.com/api/v3", TOKEN)
