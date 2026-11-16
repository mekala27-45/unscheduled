"""A work database in the shape the lake build leaves (scripts/build_lake.py --keep-work), with a few
CVEs, advisories, KEV texts and CWE texts whose dates make every rule of the corpus visible.

- CVE-2024-0001, development, published 1 March 2024: a GitHub advisory known the same day and
  modified again in 2025, a PyPI advisory known the same day, filed under CWE-22.
- CVE-2024-0002, development: its first record version is dated 2025, so no description at day 0.
- CVE-2024-0003, development: its only advisory is known in 2025, after day 0.
- CVE-2026-1000, shadow: no advisory, listed in KEV on its publication day.
- KEV texts: CVE-2026-1000 captured an hour after its listing; CVE-2021-44228 listed in 2021 and
  first captured by the kev-data history on 27 January 2025; CVE-2020-9999 never in a lake catalog.
- CWE-22 in catalog 4.13, the same text in 4.14, and a new text in 5.0.
- An OSV copy of the GitHub advisory, and a PyPI version whose text was never captured.

The words count as tokens, so no tokenizer is needed; the build counts with the pinned one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import duckdb
import polars as pl

ROOT = Path(__file__).resolve().parents[2]


def words(text: str) -> int:
    return len(text.split())


AFFECTED = json.dumps(
    [
        {
            "package": {"ecosystem": "PyPI", "name": "example-lib"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.1"}]}],
        }
    ]
)
REFS = json.dumps([{"type": "ADVISORY", "url": "https://example.test/advisory"}])
QUERY_1 = "Path traversal in example-lib lets a crafted archive write files outside the target folder."


def build(path: Path) -> Path:
    if path.exists():
        path.unlink()
    con = duckdb.connect(str(path))
    con.execute("set TimeZone = 'UTC'")
    for schema in ("intermediate", "silver", "bronze", "config"):
        con.execute(f"create schema {schema}")
    con.execute(
        """
        create table intermediate.int_cve_spine as select * from (values
            ('CVE-2024-0001', 'PUBLISHED', 'development', timestamptz '2024-03-01 10:00:00+00'),
            ('CVE-2024-0002', 'PUBLISHED', 'development', timestamptz '2024-05-01 10:00:00+00'),
            ('CVE-2024-0003', 'PUBLISHED', 'development', timestamptz '2024-06-01 10:00:00+00'),
            ('CVE-2026-1000', 'PUBLISHED', 'shadow', timestamptz '2026-05-01 09:00:00+00'),
            ('CVE-2023-7777', 'PUBLISHED', 'train', timestamptz '2023-02-01 09:00:00+00')
        ) as t(cve_id, state, split_window, published)
        """
    )
    con.execute(
        f"""
        create table intermediate.int_cve_versions as select * from (values
            ('CVE-2024-0001', 'PUBLISHED', 1, timestamptz '2024-03-01 10:00:00+00', 'record_updated',
             '{QUERY_1}', ['CWE-22']),
            ('CVE-2024-0001', 'PUBLISHED', 2, timestamptz '2025-04-01 10:00:00+00', 'record_updated',
             'Path traversal in example-lib before 2.4.1 lets a crafted archive write outside.', ['CWE-22']),
            ('CVE-2024-0002', 'PUBLISHED', 1, timestamptz '2025-02-01 10:00:00+00', 'record_updated',
             'Cross site scripting in example-web.', ['CWE-79']),
            ('CVE-2024-0003', 'PUBLISHED', 1, timestamptz '2024-06-01 10:00:00+00', 'record_updated',
             'Denial of service in example-net through a crafted header.', []::varchar[]),
            ('CVE-2026-1000', 'PUBLISHED', 1, timestamptz '2026-05-01 09:00:00+00', 'record_updated',
             'Example Gateway lets an unauthenticated caller run commands.', ['CWE-77'])
        ) as t(cve_id, state, version_no, dated_at, dated_by, description, problem_cwes)
        """
    )
    con.execute(
        f"""
        create table silver.advisory_versions as select * from (values
            ('ghsa', 'GHSA-aaaa-bbbb-cccc', null, ['CVE-2024-0001'], ['CVE-2024-0001'],
             timestamptz '2024-03-01 11:00:00+00', timestamptz '2024-03-01 12:00:00+00', null::timestamptz,
             'GHSA', '{AFFECTED}', timestamptz '2024-03-01 12:00:00+00', timestamptz '2025-06-01 00:00:00+00'),
            ('ghsa', 'GHSA-aaaa-bbbb-cccc', null, ['CVE-2024-0001'], ['CVE-2024-0001'],
             timestamptz '2024-03-01 11:00:00+00', timestamptz '2025-06-01 00:00:00+00', null::timestamptz,
             'GHSA', '{AFFECTED}', timestamptz '2025-06-01 00:00:00+00', null::timestamptz),
            ('osv', 'GHSA-aaaa-bbbb-cccc', 'PyPI', ['CVE-2024-0001'], ['CVE-2024-0001'],
             timestamptz '2024-03-01 11:00:00+00', timestamptz '2025-06-01 00:00:00+00', null::timestamptz,
             'GHSA', '{AFFECTED}', timestamptz '2025-06-01 00:00:00+00', null::timestamptz),
            ('osv', 'PYSEC-2024-1', 'PyPI', ['CVE-2024-0001', 'GHSA-aaaa-bbbb-cccc'], ['CVE-2024-0001'],
             timestamptz '2024-03-01 15:00:00+00', timestamptz '2024-03-01 15:00:00+00', null::timestamptz,
             'PYSEC', '{AFFECTED}', timestamptz '2024-03-01 15:00:00+00', null::timestamptz),
            ('osv', 'PYSEC-2024-9', 'PyPI', ['CVE-2024-0003'], ['CVE-2024-0003'],
             timestamptz '2025-01-10 00:00:00+00', timestamptz '2025-01-10 00:00:00+00', null::timestamptz,
             'PYSEC', '{AFFECTED}', timestamptz '2025-01-10 00:00:00+00', null::timestamptz),
            ('osv', 'PYSEC-2023-5', 'PyPI', ['CVE-2023-7777'], ['CVE-2023-7777'],
             timestamptz '2023-02-01 10:00:00+00', timestamptz '2023-02-01 10:00:00+00', null::timestamptz,
             'PYSEC', '{AFFECTED}', timestamptz '2023-02-01 10:00:00+00', null::timestamptz),
            ('osv', 'PYSEC-2024-7', 'PyPI', ['CVE-2024-0001'], ['CVE-2024-0001'],
             timestamptz '2024-03-02 00:00:00+00', timestamptz '2024-03-02 00:00:00+00', null::timestamptz,
             'PYSEC', '{AFFECTED}', timestamptz '2024-03-02 00:00:00+00', null::timestamptz)
        ) as t(database, advisory_id, ecosystem, aliases, cve_ids, published, modified, withdrawn,
               source_db, affected_json, known_from, known_to)
        """
    )
    con.execute(
        """
        create table bronze.osv_advisories as select * from (values
            ('PYSEC-2024-1', 'PyPI', timestamptz '2024-03-01 15:00:00+00', 'example-lib path traversal'),
            ('PYSEC-2024-9', 'PyPI', timestamptz '2025-01-10 00:00:00+00', 'example-net denial of service'),
            ('PYSEC-2024-7', 'PyPI', timestamptz '2024-03-02 00:00:00+00', 'never captured'),
            ('PYSEC-2023-5', 'PyPI', timestamptz '2023-02-01 10:00:00+00', 'a product CVE of 2023'),
            ('GHSA-aaaa-bbbb-cccc', 'PyPI', timestamptz '2025-06-01 00:00:00+00', 'the OSV copy')
        ) as t(id, ecosystem, modified, summary)
        """
    )
    con.execute(
        f"""
        create table bronze.osv_text as select * from (values
            ('PYSEC-2024-1', 'PyPI', timestamptz '2024-03-01 15:00:00+00', timestamptz '2024-03-01 15:00:00+00',
             'The archive extractor trusts member names.', '{REFS}'),
            ('PYSEC-2024-9', 'PyPI', timestamptz '2025-01-10 00:00:00+00', timestamptz '2025-01-10 00:00:00+00',
             'A crafted header exhausts memory.', null),
            ('PYSEC-2023-5', 'PyPI', timestamptz '2023-02-01 10:00:00+00', timestamptz '2023-02-01 10:00:00+00',
             'A 2023 advisory that a stand in product carries.', null),
            ('GHSA-aaaa-bbbb-cccc', 'PyPI', timestamptz '2025-06-01 00:00:00+00',
             timestamptz '2024-03-01 11:00:00+00', 'The OSV copy of the GitHub advisory.', null)
        ) as t(id, ecosystem, modified, published, details, references_json)
        """
    )
    con.execute(
        f"""
        create table bronze.ghsa_text as select * from (values
            ('GHSA-aaaa-bbbb-cccc', timestamptz '2024-03-01 12:00:00+00', 'Path traversal in example-lib',
             'The extractor of example-lib joins member names to the target folder.', '{REFS}'),
            ('GHSA-aaaa-bbbb-cccc', timestamptz '2025-06-01 00:00:00+00', 'Path traversal in example-lib',
             'The extractor of example-lib joins member names to the target folder. Fixed in 2.4.1.', '{REFS}')
        ) as t(ghsa_id, modified, summary, details, references_json)
        """
    )
    con.execute(
        """
        create table silver.kev_events as select * from (values
            ('CVE-2026-1000', timestamptz '2026-05-01 12:00:00+00', 'Example', 'Gateway'),
            ('CVE-2021-44228', timestamptz '2021-12-10 00:00:00+00', 'Apache', 'Log4j2')
        ) as t(cve_id, listed_at, vendor_project, product)
        """
    )
    con.execute(
        """
        create table bronze.kev_text as select * from (values
            ('CVE-2026-1000', 'd1', '2026.05.01', date '2026-05-01', 'Example Gateway Command Injection',
             'Example Gateway lets an unauthenticated caller run commands.', 'Apply the vendor fix.',
             'https://example.test/gw', timestamptz '2026-05-01 13:00:00+00'),
            ('CVE-2021-44228', 'd2', '2025.01.27', date '2021-12-10', 'Apache Log4j2 Remote Code Execution',
             'Apache Log4j2 lets a crafted lookup load remote code.', 'Apply updates.',
             'https://example.test/log4j', timestamptz '2025-01-27 22:38:50+00'),
            ('CVE-2021-44228', 'd3', '2026.02.01', date '2021-12-10', 'Apache Log4j2 Remote Code Execution',
             'Apache Log4j2 lets a crafted lookup load remote code from a server the attacker runs.',
             'Apply updates.', 'https://example.test/log4j', timestamptz '2026-02-01 00:00:00+00'),
            ('CVE-2020-9999', 'd4', '2025.01.27', date '2020-01-01', 'Removed entry', 'Removed.', 'None.',
             null, timestamptz '2025-01-27 22:38:50+00')
        ) as t(cve_id, text_digest, catalog_version, date_added, vulnerability_name, short_description,
               required_action, notes, captured_at)
        """
    )
    con.execute(
        """
        create table bronze.cwe_text as select * from (values
            ('CWE-22', '4.13', date '2023-10-26', 'Path Traversal', 'The software uses input to build a path.',
             null, 'scope: Integrity; impact: Modify Files', 'phase: Implementation; description: Canonicalize.'),
            ('CWE-22', '4.14', date '2024-02-29', 'Path Traversal', 'The software uses input to build a path.',
             null, 'scope: Integrity; impact: Modify Files', 'phase: Implementation; description: Canonicalize.'),
            ('CWE-22', '5.0', date '2026-10-28', 'Path Traversal', 'The product uses input to build a path.',
             null, 'scope: Integrity; impact: Modify Files', 'phase: Implementation; description: Canonicalize.'),
            ('CWE-77', '4.13', date '2023-10-26', 'Command Injection', 'The product builds a command from input.',
             null, null, null)
        ) as t(cwe_id, catalog_version, catalog_date, name, description, extended_description, consequences,
               mitigations)
        """
    )
    con.execute(
        """
        create table silver.exploit_first_seen as select * from (values
            ('CVE-2026-1000', timestamptz '2026-05-03 00:00:00+00', timestamptz '2026-05-03 00:00:00+00', null::timestamptz)
        ) as t(cve_id, first_seen, metasploit_first_seen, nuclei_first_seen)
        """
    )
    con.execute(
        """
        create table silver.cve_fact as select * from (values
            ('CVE-2026-1000', 'epss', 'epss', '0.01', timestamptz '2026-05-01 00:00:00+00', timestamptz '2026-05-02 00:00:00+00', 'epss_score_date', false),
            ('CVE-2026-1000', 'epss', 'epss', '0.42', timestamptz '2026-05-02 00:00:00+00', null::timestamptz, 'epss_score_date', false)
        ) as t(cve_id, field, source, value, known_from, known_to, dated_by, pre_history)
        """
    )
    con.execute("create table config.lake_build as select timestamptz '2026-11-16 03:00:00+00' as data_cut")
    con.execute(
        """
        create table config.bronze_tables as select * from (values
            ('osv_text', 1, 3, true), ('ghsa_text', 1, 2, true), ('kev_text', 1, 4, true), ('cwe_text', 1, 4, true)
        ) as t(name, files, rows, present)
        """
    )
    con.close()
    return path


def findings(path: Path) -> Path:
    pl.DataFrame(
        {"cve_aliases": [["CVE-2023-7777"]], "upstream_cves": [[]]},
        schema={"cve_aliases": pl.List(pl.String), "upstream_cves": pl.List(pl.String)},
    ).write_parquet(path)
    return path


def digests(folder: Path) -> dict[str, Any]:
    """Build the corpus from the fixture into a folder and return its digests."""
    sys.path.insert(0, str(ROOT))
    from scripts.build_corpus import build as build_corpus

    work = build(folder / "work.duckdb")
    manifest = build_corpus(
        work, findings(folder / "finding.parquet"), folder / "corpus", words, {"model": "words"}
    )
    return {
        "content": manifest["content_digest"],
        "files": {name: entry["sha256"] for name, entry in manifest["files"].items()},
    }


if __name__ == "__main__":
    print(json.dumps(digests(Path(sys.argv[1]))))
