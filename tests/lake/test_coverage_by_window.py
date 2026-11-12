"""The label coverage by window counts bands on published CVEs only, window by window."""

from __future__ import annotations

import duckdb
from unscheduled_lake.build import coverage_by_window


def test_coverage_counts_bands_on_published_cves_by_window() -> None:
    con = duckdb.connect()
    con.execute("create schema gold")
    con.execute(
        "create table gold.cve_current (cve_id varchar, published timestamptz, split_window varchar, "
        "state varchar, nvd_cvss31_band varchar, filer_cvss31_band varchar, filer_cvss30_band varchar, "
        "filer_cvss40_band varchar, adp_cvss31_band varchar)"
    )
    con.execute(
        """
        insert into gold.cve_current values
          ('CVE-2020-0001', '2020-01-01', 'train', 'PUBLISHED', 'HIGH', null, null, null, null),
          ('CVE-2020-0002', '2020-02-01', 'train', 'PUBLISHED', null, null, 'LOW', null, 'LOW'),
          ('CVE-2020-0003', '2020-03-01', 'train', 'REJECTED', 'HIGH', 'HIGH', null, null, null),
          ('CVE-2026-0001', '2026-05-01', 'shadow', 'PUBLISHED', 'MEDIUM', null, null, 'MEDIUM', null)
        """
    )
    assert coverage_by_window(con) == [
        {
            "window": "train",
            "cves": 3,
            "published": 2,
            "nvd_band": 1,
            "filer_band": 1,
            "adp_band": 1,
            "nvd_and_filer_band": 0,
        },
        {
            "window": "shadow",
            "cves": 1,
            "published": 1,
            "nvd_band": 1,
            "filer_band": 1,
            "adp_band": 0,
            "nvd_and_filer_band": 1,
        },
    ]
