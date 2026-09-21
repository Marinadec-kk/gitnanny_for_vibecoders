from __future__ import annotations

import pytest

from gitnanny.diff import (
    collect_raw_diff,
    get_diff,
    parse_added_lines,
    resolve_base,
    run_git,
)

SAMPLE_DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,4 +1,7 @@
 import os
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
 def run():
-    pass
+    return "ok"
@@ -10,3 +13,4 @@
 # tail
+password = "hunter2hunter2"
diff --git a/binary.bin b/binary.bin
Binary files differ
"""


def test_parse_added_lines_numbers_across_hunks():
    files = parse_added_lines(SAMPLE_DIFF)
    assert [f.path for f in files] == ["app.py"]

    lines = {ln.lineno: ln.text for ln in files[0].added_lines}
    assert lines == {
        2: 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        4: '    return "ok"',
        14: 'password = "hunter2hunter2"',
    }


def test_resolve_base_maps_zero_sha_to_empty_tree():
    zero = "0" * 40
    assert resolve_base(zero) != zero
    assert resolve_base("f" * 40) == "f" * 40


@pytest.fixture()
def repo(tmp_path):
    def git(*args):
        return run_git(*args, cwd=tmp_path)

    git("init", "-q")
    git("config", "user.email", "t@t.t")
    git("config", "user.name", "t")
    return tmp_path


def test_collect_staged(repo):
    (repo / "app.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"\n')
    run_git("add", "app.py", cwd=repo)
    raw = collect_raw_diff("staged", cwd=repo)
    assert "AKIAIOSFODNN7EXAMPLE" in raw


def test_collect_last_falls_back_to_empty_tree_on_first_commit(repo):
    (repo / "a.txt").write_text("hello\n")
    run_git("add", ".", cwd=repo)
    run_git("commit", "-qm", "init", cwd=repo)
    raw = collect_raw_diff("last", cwd=repo)
    assert "hello" in raw


def test_collect_unpushed_without_upstream_is_empty(repo):
    (repo / "a.txt").write_text("hello\n")
    run_git("add", ".", cwd=repo)
    run_git("commit", "-qm", "init", cwd=repo)
    assert collect_raw_diff("unpushed", cwd=repo) == ""


def test_get_diff_base_range(repo):
    run_git("commit", "-q", "--allow-empty", "-m", "base", cwd=repo)
    base = run_git("rev-parse", "HEAD", cwd=repo).strip()
    (repo / "app.py").write_text('t = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n')
    run_git("add", ".", cwd=repo)
    run_git("commit", "-qm", "leak", cwd=repo)

    diff = get_diff(base=base, cwd=repo)
    assert not diff.is_empty
    assert diff.files[0].path == "app.py"
    assert diff.files[0].added_lines[0].lineno == 1


def test_unknown_target_rejected():
    with pytest.raises(ValueError, match="unknown target"):
        collect_raw_diff("bogus")
