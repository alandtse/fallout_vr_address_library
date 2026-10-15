import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_database as v

FO4 = {1: 0x140001000, 2: 0x140002000}


def test_clean_rows_pass():
    rows = [
        ["1", "0x140001000", "0x140009000", "4", "a"],
        ["2", "0x140002000", "0x14000a000", "3", "b"],
    ]
    assert v.check_database(rows, [], FO4) == []


def test_each_database_defect_is_reported():
    rows = [
        ["2", "0x140002000", "0x14000a000", "9", "bad status"],
        ["1", "0x140001111", "0x14000a000", "4", "wrong fo4 and shared vr"],
        ["1", "0x140001000", "0x1", "4", "dup id"],
    ]
    text = " | ".join(v.check_database(rows, [], FO4))
    for needle in ("not ascending", "bad status", "FO4 address", "also used by id"):
        assert needle in text


def test_unchanged_rows_are_skipped_against_a_base():
    row = ["1", "0x140001111", "0x1", "4", "legacy"]
    assert v.check_database([row], [row], FO4) == []


def test_load_offsets_adds_image_base():
    assert v.load_offsets("id,fo4_addr\n2,10d0\n") == {2: 0x1400010D0}


def test_legacy_ordering_is_ignored_against_a_base():
    legacy = [
        ["5", "0x1", "0x10", "4", "a"],
        ["3", "0x2", "0x20", "4", "b"],
    ]
    se = {5: 1, 3: 2}
    assert v.check_database(legacy, legacy, se) == []
    changed = legacy + [["9", "0x3", "0x30", "4", "new"]]
    assert v.check_database(changed, legacy, {**se, 9: 3}) == []


def test_bad_base_ref_is_an_error_not_an_empty_base():
    with pytest.raises(RuntimeError, match="git show"):
        v._git_show("no-such-ref-for-verifier-test", "database.csv")
    assert v.main(["--base", "no-such-ref-for-verifier-test"]) == 2
