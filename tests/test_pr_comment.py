"""Tests for posting and updating the single SAFECODE PR comment."""

from safecode import pr_comment
from safecode.pr_comment import MARKER

COMMENTS = "/repos/octo/app/issues/7/comments?per_page=100&page=1"


class FakeGitHub:
    def __init__(self, gets=None, writes=None):
        self.repo = "octo/app"
        self.gets = gets or {}
        self.writes = writes or {}
        self.calls = []

    def get(self, path):
        self.calls.append(("GET", path))
        return self.gets.get(path, (200, []))

    def request(self, method, path, body=None):
        if method == "GET":
            return self.get(path)
        self.calls.append((method, path))
        return self.writes.get((method, path), (200 if method == "PATCH" else 201, {}))


def test_pull_request_number():
    assert pr_comment.pull_request_number({"pull_request": {"number": 7}}) == 7
    assert pr_comment.pull_request_number({"ref": "refs/heads/main"}) is None


def test_creates_comment_when_none_exists():
    gh = FakeGitHub()
    ok, message = pr_comment.upsert_comment(gh, 7, f"{MARKER}\nreport")
    assert ok and message == "Report posted on pull request #7."
    assert gh.calls[-1] == ("POST", "/repos/octo/app/issues/7/comments")


def test_updates_existing_comment():
    gh = FakeGitHub(gets={COMMENTS: (200, [{"id": 1, "body": "LGTM"}, {"id": 42, "body": f"{MARKER}\nold"}])})
    ok, message = pr_comment.upsert_comment(gh, 7, f"{MARKER}\nnew")
    assert ok and "updated" in message
    assert gh.calls[-1] == ("PATCH", "/repos/octo/app/issues/comments/42")


def test_quoted_marker_in_human_reply_is_not_overwritten():
    gh = FakeGitHub(gets={COMMENTS: (200, [{"id": 5, "body": f"> {MARKER}\n> quoted report\nthoughts?"}])})
    pr_comment.upsert_comment(gh, 7, f"{MARKER}\nnew")
    assert ("PATCH", "/repos/octo/app/issues/comments/5") not in gh.calls
    assert gh.calls[-1][0] == "POST"


def test_falls_back_to_new_comment_if_marked_comment_is_not_ours():
    gh = FakeGitHub(gets={COMMENTS: (200, [{"id": 9, "body": f"{MARKER}\nfake"}])},
                    writes={("PATCH", "/repos/octo/app/issues/comments/9"): (403, None)})
    ok, _ = pr_comment.upsert_comment(gh, 7, f"{MARKER}\nnew")
    assert ok
    assert gh.calls[-1] == ("POST", "/repos/octo/app/issues/7/comments")


def test_searches_later_pages():
    page1 = [{"id": n, "body": "chatter"} for n in range(100)]
    gh = FakeGitHub(gets={COMMENTS: (200, page1),
                          "/repos/octo/app/issues/7/comments?per_page=100&page=2": (200, [{"id": 777, "body": f"{MARKER}\nold"}])})
    pr_comment.upsert_comment(gh, 7, f"{MARKER}\nnew")
    assert gh.calls[-1] == ("PATCH", "/repos/octo/app/issues/comments/777")


def test_read_only_fork_token_gives_helpful_message():
    gh = FakeGitHub(writes={("POST", "/repos/octo/app/issues/7/comments"): (403, {"message": "forbidden"})})
    ok, message = pr_comment.upsert_comment(gh, 7, "body")
    assert not ok
    assert "forks" in message and "pull-requests: write" in message


def test_fit_report_shrinks_until_it_fits():
    limits = []

    def render(max_findings):
        limits.append(max_findings)
        return "x" * (max_findings * 2000)

    body = pr_comment.fit_report(render)
    assert body.startswith(MARKER)
    assert len(body) <= pr_comment.MAX_BODY_CHARS
    assert limits == [60, 30]


def test_fit_report_hard_truncates_as_last_resort():
    body = pr_comment.fit_report(lambda _: "y" * 100_000)
    assert len(body) <= pr_comment.MAX_BODY_CHARS
    assert body.rstrip().endswith("comment size limit.*")
