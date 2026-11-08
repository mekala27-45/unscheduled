"""The bronze writer: typed Parquet per table, partitioned by year, upserts keyed, reruns inert.

A batch is checked against the contract, sorted by its key, and split by partition. For an upsert
table only the rows whose key bronze has not seen are written, to a part file named by the batch,
so writing the same batch twice writes nothing the second time and the files are byte for byte the
same. A replace table is rewritten whole. Parts are compacted per partition at the end of a run into
one file named by the digest of its content; compaction of a compacted partition changes nothing.

Writes go to a temporary name and are renamed into place, so a crash never leaves half a file.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path

import polars as pl

from unscheduled_sources.contract import Table, conform, table

PART_SUFFIX = ".parquet"


@dataclass(frozen=True)
class WriteResult:
    table: str
    rows_in: int
    rows_changed: int
    files: tuple[str, ...]


def _partition_values(spec: Table, df: pl.DataFrame) -> pl.Series:
    if spec.partition == "cve_year":
        return df.get_column("cve_id").str.slice(4, 4).alias("_part")
    if spec.partition == "created_year":
        return df.get_column("created").dt.year().cast(pl.String).fill_null("unknown").alias("_part")
    if spec.partition == "published_year":
        published = df.get_column("published").dt.year()
        modified = df.get_column("modified").dt.year()
        return published.fill_null(modified).cast(pl.String).fill_null("unknown").alias("_part")
    return pl.Series("_part", [""] * df.height, dtype=pl.String)


def _safe(batch_id: str) -> str:
    keep = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in batch_id)
    return keep.strip("-.") or "batch"


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_parquet(df: pl.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    df.write_parquet(tmp, compression="zstd", compression_level=6, statistics=True, row_group_size=65536)
    tmp.replace(path)


class Bronze:
    """Bronze under one root. Key indexes are cached per partition for the life of the writer."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._keys: dict[tuple[str, str], pl.DataFrame] = {}

    def table_dir(self, name: str) -> Path:
        return self.root / name

    def partition_dir(self, spec: Table, part: str) -> Path:
        base = self.table_dir(spec.name)
        return base / f"year={part}" if spec.partition else base

    def parts(self, name: str) -> list[Path]:
        base = self.table_dir(name)
        if not base.exists():
            return []
        return sorted(p for p in base.rglob(f"*{PART_SUFFIX}") if p.is_file())

    def read(self, name: str) -> pl.DataFrame:
        spec = table(name)
        files = self.parts(name)
        if not files:
            return pl.DataFrame(schema=spec.schema)
        frames = [pl.read_parquet(f) for f in files]
        return pl.concat(frames, how="vertical").select(list(spec.columns))

    def _existing_keys(self, spec: Table, part: str) -> pl.DataFrame:
        cache_key = (spec.name, part)
        if cache_key in self._keys:
            return self._keys[cache_key]
        folder = self.partition_dir(spec, part)
        files = sorted(folder.glob(f"*{PART_SUFFIX}")) if folder.exists() else []
        if files:
            keys = pl.concat([pl.read_parquet(f, columns=list(spec.key)) for f in files], how="vertical")
        else:
            keys = pl.DataFrame(schema={k: spec.columns[k] for k in spec.key})
        self._keys[cache_key] = keys
        return keys

    def write(self, name: str, df: pl.DataFrame, batch_id: str) -> WriteResult:
        spec = table(name)
        df = conform(name, df)
        if spec.mode == "replace":
            return self._replace(spec, df, batch_id)
        return self._upsert(spec, df, batch_id)

    def _upsert(self, spec: Table, df: pl.DataFrame, batch_id: str) -> WriteResult:
        rows_in = df.height
        if rows_in == 0:
            return WriteResult(spec.name, 0, 0, ())
        ordered = df.sort(spec.sort_by, nulls_last=True, maintain_order=True)
        ordered = ordered.unique(subset=list(spec.key), keep="first", maintain_order=True)
        tagged = ordered.with_columns(_partition_values(spec, ordered))
        written: list[str] = []
        changed = 0
        for part in sorted(tagged.get_column("_part").unique().to_list()):
            chunk = tagged.filter(pl.col("_part") == part).drop("_part")
            existing = self._existing_keys(spec, part)
            fresh = chunk.join(existing, on=list(spec.key), how="anti", nulls_equal=True)
            if fresh.height == 0:
                continue
            target = self.partition_dir(spec, part) / f"{_safe(batch_id)}{PART_SUFFIX}"
            to_write = fresh
            if target.exists():
                # The same batch met again with rows it did not hold: one file keeps both.
                to_write = pl.concat([pl.read_parquet(target), fresh], how="vertical")
                to_write = to_write.sort(spec.sort_by, nulls_last=True, maintain_order=True)
            write_parquet(to_write, target)
            changed += fresh.height
            self._keys[(spec.name, part)] = pl.concat(
                [existing, fresh.select(list(spec.key))], how="vertical"
            )
            written.append(str(target))
        return WriteResult(spec.name, rows_in, changed, tuple(written))

    def _replace(self, spec: Table, df: pl.DataFrame, batch_id: str) -> WriteResult:
        ordered = df.sort(spec.sort_by, nulls_last=True, maintain_order=True)
        ordered = ordered.unique(subset=list(spec.key), keep="first", maintain_order=True)
        target = self.table_dir(spec.name) / f"{_safe(batch_id)}{PART_SUFFIX}"
        previous = pl.read_parquet(target) if target.exists() else pl.DataFrame(schema=spec.schema)
        changed = _changed_rows(previous, ordered)
        if changed == 0 and target.exists():
            return WriteResult(spec.name, df.height, 0, (str(target),))
        write_parquet(ordered, target)
        return WriteResult(spec.name, df.height, changed, (str(target),))

    def compact(self, name: str) -> list[Path]:
        """Merge the parts of each partition into one file named by its content digest."""
        spec = table(name)
        base = self.table_dir(name)
        if not base.exists():
            return []
        folders = sorted({p.parent for p in base.rglob(f"*{PART_SUFFIX}")})
        out: list[Path] = []
        for folder in folders:
            files = sorted(folder.glob(f"*{PART_SUFFIX}"))
            if spec.mode == "replace" or not files:
                out.extend(files)
                continue
            if len(files) == 1 and files[0].name.startswith("part-"):
                out.append(files[0])
                continue
            merged = pl.concat([pl.read_parquet(f) for f in files], how="vertical")
            merged = merged.sort(spec.sort_by, nulls_last=True, maintain_order=True)
            merged = merged.unique(subset=list(spec.key), keep="first", maintain_order=True)
            staging = folder / "compact.parquet.staging"
            write_parquet(merged, staging)
            final = folder / f"part-{file_digest(staging)[:16]}{PART_SUFFIX}"
            staging.replace(final)
            for f in files:
                if f != final:
                    f.unlink()
            out.append(final)
        self._keys = {k: v for k, v in self._keys.items() if k[0] != name}
        return out

    def drop(self, name: str) -> None:
        shutil.rmtree(self.table_dir(name), ignore_errors=True)
        self._keys = {k: v for k, v in self._keys.items() if k[0] != name}


def _changed_rows(previous: pl.DataFrame, current: pl.DataFrame) -> int:
    """Rows in either frame without an identical row in the other: what a replace changed."""
    if previous.height == 0:
        return current.height
    old = set(previous.hash_rows(seed=0).to_list())
    new = set(current.hash_rows(seed=0).to_list())
    return len(old ^ new)
