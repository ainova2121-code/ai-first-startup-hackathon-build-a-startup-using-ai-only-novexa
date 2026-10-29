"""One-shot restore: every file the platform edited goes back to its exact original bytes, and a
file someone changed by hand since is never overwritten."""

from purpleteam.codemods.restore import SourceSnapshots


def _repo(tmp_path, **files):
    repo = tmp_path / "repo"
    repo.mkdir()
    for name, text in files.items():
        (repo / name).write_bytes(text.encode())  # exact bytes, as the platform writes them (no newline translation)
    return repo


def test_restore_puts_every_edited_file_back_and_forgets_it(tmp_path):
    repo = _repo(tmp_path, **{"a.py": "patched a\n", "b.py": "patched b\n"})
    snapshots = SourceSnapshots(tmp_path / "store.json")
    snapshots.record("a.py", "original a\n", "patched a\n")
    snapshots.record("b.py", "original b\n", "patched b\n")
    assert snapshots.modified() == ["a.py", "b.py"]

    results = snapshots.restore_all(repo)

    assert [r["status"] for r in results] == ["restored", "restored"]
    assert (repo / "a.py").read_text() == "original a\n" and (repo / "b.py").read_text() == "original b\n"
    assert snapshots.modified() == [] and not (tmp_path / "store.json").exists()


def test_a_file_patched_twice_is_restored_to_its_first_original(tmp_path):
    repo = _repo(tmp_path, **{"a.py": "second patch\n"})
    snapshots = SourceSnapshots(tmp_path / "store.json")
    snapshots.record("a.py", "original\n", "first patch\n")
    snapshots.record("a.py", "first patch\n", "second patch\n")
    snapshots.restore_all(repo)
    assert (repo / "a.py").read_text() == "original\n"


def test_a_file_edited_by_hand_since_the_patch_is_left_alone(tmp_path):
    repo = _repo(tmp_path, **{"a.py": "someone else's later edit\n"})
    snapshots = SourceSnapshots(tmp_path / "store.json")
    snapshots.record("a.py", "original\n", "patched\n")

    (result,) = snapshots.restore_all(repo)

    assert result["status"] == "skipped" and "edited since" in result["reason"]
    assert (repo / "a.py").read_text() == "someone else's later edit\n"
    assert snapshots.modified() == ["a.py"]  # still tracked, so nothing is silently lost


def test_a_recorded_path_outside_the_repo_is_never_written(tmp_path):
    repo = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("patched\n")
    snapshots = SourceSnapshots(tmp_path / "store.json")
    snapshots.record("../outside.py", "original\n", "patched\n")
    (result,) = snapshots.restore_all(repo)
    assert result["status"] == "skipped" and outside.read_text() == "patched\n"


def test_nothing_recorded_means_nothing_to_restore(tmp_path):
    assert SourceSnapshots(tmp_path / "store.json").restore_all(_repo(tmp_path)) == []
