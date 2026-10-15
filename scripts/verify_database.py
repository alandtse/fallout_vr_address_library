"""Static consistency checks for fo4_database.csv.

Checks, on the rows that differ from --base (every row when --base is omitted):
  fo4_database.csv  5 columns, status 0-4, ids ascending and unique, FO4 address equal to
                    offsets-1-10-163-0.csv, VR address not already used by another id

Usage: python scripts/verify_database.py [--base REF]
Exits 1 when any problem is found, 2 when --base cannot be read. Ghidra-backed checks (status 4 byte equality) are out of scope.
"""

import argparse
import csv
import io
import subprocess
import sys
from collections import Counter, defaultdict

IMAGE_BASE = 0x140000000
DATABASE = "fo4_database.csv"
OFFSETS = "offsets-1-10-163-0.csv"


def _is_number(text):
    return text.isascii() and text.isdigit()


def parse_rows(text):
    return [
        r
        for r in list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))[1:]
        if r and r[0].strip()
    ]


def load_offsets(text):
    return {
        int(r[0]): int(r[1], 16) + IMAGE_BASE
        for r in parse_rows(text)
        if _is_number(r[0]) and len(r) >= 2 and r[1]
    }


def _changed_flags(rows, base_rows):
    """True for rows not matched by a base row; each base row matches one copy."""
    remaining = Counter(tuple(r) for r in base_rows)
    flags = []
    for r in rows:
        key = tuple(r)
        if remaining[key] > 0:
            remaining[key] -= 1
            flags.append(False)
        else:
            flags.append(True)
    return flags


def _numeric_id_rows(rows, changed, problems):
    """Rows with a numeric id and their changed flags; changed others are reported."""
    kept, kept_changed = [], []
    for r, c in zip(rows, changed, strict=True):
        if _is_number(r[0]):
            kept.append(r)
            kept_changed.append(c)
        elif c:
            problems.append(f"malformed id {r[0]!r}")
    return kept, kept_changed


def _order_problem(ids, changed):
    """Duplicate ids and out-of-order neighbours that involve a changed row."""
    counts = Counter(ids)
    dups = sorted({i for i, c in zip(ids, changed, strict=True) if c and counts[i] > 1})
    misordered = any(
        c and ((k > 0 and ids[k - 1] >= i) or (k + 1 < len(ids) and i >= ids[k + 1]))
        for k, (i, c) in enumerate(zip(ids, changed, strict=True))
    )
    return dups, misordered


def check_database(rows, base_rows, fo4_offsets):
    """Problems in `rows`; only rows that differ from `base_rows` get per-row checks."""
    problems = []
    rows, changed = _numeric_id_rows(rows, _changed_flags(rows, base_rows), problems)
    ids = [int(r[0]) for r in rows]
    dups, misordered = _order_problem(ids, changed)
    if dups or misordered:
        problems.append(
            "ids not ascending and unique" + (f" (duplicates {dups})" if dups else "")
        )
    by_vr = defaultdict(list)
    for r in rows:
        if len(r) == 5:
            try:
                by_vr[int(r[2], 16)].append(int(r[0]))
            except ValueError:
                pass
    for r, is_changed in zip(rows, changed, strict=True):
        if not is_changed:
            continue
        i = int(r[0])
        if len(r) != 5:
            problems.append(f"{i}: {len(r)} columns, expected 5")
            continue
        try:
            fo4, vr = int(r[1], 16), int(r[2], 16)
        except ValueError:
            problems.append(f"{i}: address is not hex ({r[1]}, {r[2]})")
            continue
        if r[3] not in ("0", "1", "2", "3", "4"):
            problems.append(f"{i}: bad status {r[3]!r}")
        want = fo4_offsets.get(i)
        if want is not None and want != fo4:
            problems.append(f"{i}: FO4 address {fo4:#x} != offsets table {want:#x}")
        clash = [j for j in by_vr[vr] if j != i]
        if clash:
            problems.append(f"{i}: VR address {vr:#x} also used by id {clash}")
    return problems


def _git_show(ref, path):
    p = subprocess.run(
        ["git", "show", f"{ref}:{path}"], check=False, capture_output=True
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"git show {ref}:{path} failed: {p.stderr.decode('utf-8', 'replace').strip()}"
        )
    return p.stdout.decode("utf-8")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", help="git ref; only rows that differ from it are checked")
    args = ap.parse_args(argv)
    try:
        base_db = parse_rows(_git_show(args.base, DATABASE)) if args.base else []
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return 2
    problems = [
        (DATABASE, p)
        for p in check_database(
            parse_rows(_read(DATABASE)), base_db, load_offsets(_read(OFFSETS))
        )
    ]
    for f, p in problems:
        print(f"{f}: {p}")
    print(f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
