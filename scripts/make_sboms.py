"""The customer's SBOMs: the pinned tools, the stand ins chosen by rule, and Syft over each of them.

uv run python scripts/make_sboms.py tools    # Syft, osv-scanner, Grype into tools/bin, checksums verified
uv run python scripts/make_sboms.py select   # apply the rule in config/products.yaml, rewrite stand_ins
uv run python scripts/make_sboms.py sboms    # CycloneDX 1.6 JSON into customer/sboms/, with digests
uv run python scripts/make_sboms.py lock     # rewrite sboms.lock.json from the SBOMs on disk
uv run python scripts/make_sboms.py all      # tools, select and sboms in order

Each repository stand in is read at its pinned commit through raw.githubusercontent.com: the root
lockfiles and manifests the rule names (for Maven the root pom.xml and the module poms it declares).
The image is pulled by its platform digest from Docker Hub, or from a listed mirror that serves the
same digest when Docker Hub refuses an anonymous pull. Every SBOM is validated against the
CycloneDX 1.6 schema and its SHA-256 is written to customer/sboms/sboms.lock.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import httpx
from unscheduled_match import products, tools
from unscheduled_match.github import USER_AGENT, GitHub
from unscheduled_match.products import EcosystemRule, ProductsConfig, StandIn
from unscheduled_match.sbom import read as read_sbom
from unscheduled_match.sbom import validate_cyclonedx_16

PRODUCTS = ROOT / "config" / "products.yaml"
SBOM_DIR = ROOT / "customer" / "sboms"
LOCK = SBOM_DIR / "sboms.lock.json"
BIN = ROOT / "tools" / "bin"
MAX_MODULES = 400


def client(timeout: float = 120.0) -> httpx.Client:
    return httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


def cmd_tools() -> None:
    with client() as http:
        installed = tools.install_all(BIN, http)
    for name, path in installed.items():
        print(f"tools: {name} verified and installed at {path.relative_to(ROOT)}")


def cmd_select() -> None:
    config = products.load_config(PRODUCTS)
    cutoff = products.parse_github_time(config.rule.cutoff)
    chosen: list[StandIn] = []
    with client() as http:
        osi = products.read_osi(http)
        gh = GitHub(http)
        for rule in config.ecosystems:
            stand_in = products.select(rule, cutoff, config.rule.min_stars, osi, gh)
            print(
                f"select: {rule.ecosystem}: {stand_in.repository} at {stand_in.commit} "
                f"({stand_in.stars} stars, {stand_in.licence}, {len(stand_in.passed_over)} passed over)"
            )
            chosen.append(stand_in)
        image = products.select_image(config.image, cutoff, http)
        print(f"select: image {image.image}:{image.tag} {image.platform} {image.digest}")
        chosen.append(image)
    updated = config.model_copy(
        update={
            "osi_list": {"source": products.SPDX_LICENSES, "version": osi.version, "read_at": osi.read_at},
            "stand_ins": tuple(chosen),
        }
    )
    PRODUCTS.write_text(products.dump_config(updated), encoding="utf-8")
    print(f"select: wrote {PRODUCTS.relative_to(ROOT)} ({gh.calls['search']} search calls)")


def maven_modules(pom: bytes) -> list[str]:
    tree = ET.fromstring(pom)
    return sorted(
        {(m.text or "").strip() for m in tree.iter() if m.tag.endswith("}module") or m.tag == "module"}
    )


def fetch_inputs(stand_in: StandIn, rule: EcosystemRule, gh: GitHub, work: Path) -> list[dict[str, Any]]:
    assert stand_in.repository and stand_in.commit
    wanted = [*stand_in.lockfiles, *(m for m in rule.manifests if m not in stand_in.lockfiles)]
    queue = list(wanted)
    fetched: list[dict[str, Any]] = []
    seen: set[str] = set()
    while queue:
        rel = queue.pop(0)
        if rel in seen:
            continue
        seen.add(rel)
        body = gh.raw(stand_in.repository, stand_in.commit, rel)
        if body is None:
            continue
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        fetched.append({"path": rel, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)})
        if rel.endswith("pom.xml") and len(seen) < MAX_MODULES:
            base = rel[: -len("pom.xml")]
            for module in maven_modules(body):
                queue.append(f"{base}{module}/pom.xml".replace("//", "/"))
    return sorted(fetched, key=lambda f: str(f["path"]))


def syft(args: list[str]) -> None:
    env = {**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"}
    subprocess.run([str(BIN / "syft"), "scan", *args, "-q"], check=True, env=env)


def sbom_path(product: str) -> Path:
    return SBOM_DIR / f"{product}.cdx.json"


def make_repository_sbom(stand_in: StandIn, rule: EcosystemRule, gh: GitHub) -> dict[str, Any]:
    assert stand_in.repository and stand_in.commit
    with tempfile.TemporaryDirectory(prefix="unsched-src-") as tmp:
        work = Path(tmp) / stand_in.repository.replace("/", "__")
        work.mkdir()
        inputs = fetch_inputs(stand_in, rule, gh, work)
        out = sbom_path(stand_in.product)
        syft(
            [
                f"dir:{work}",
                "--source-name",
                stand_in.repository,
                "--source-version",
                stand_in.commit,
                "-o",
                f"cyclonedx-json@1.6={out}",
            ]
        )
    return {
        "source": {"repository": stand_in.repository, "commit": stand_in.commit, "scope": stand_in.scope},
        "inputs": inputs,
    }


def make_image_sbom(stand_in: StandIn) -> dict[str, Any]:
    assert stand_in.image and stand_in.digest
    out = sbom_path(stand_in.product)
    name = stand_in.image.split("/", 1)[1]
    registries = [stand_in.image, *stand_in.mirrors]
    refusals: list[str] = []
    for ref in registries:
        reference = f"{ref}@{stand_in.digest}"
        try:
            syft(
                [
                    f"registry:{reference}",
                    "--source-name",
                    f"{stand_in.image}:{stand_in.tag}",
                    "--source-version",
                    stand_in.digest,
                    "-o",
                    f"cyclonedx-json@1.6={out}",
                ]
            )
        except subprocess.CalledProcessError as err:
            refusals.append(f"{ref}: syft exited {err.returncode}")
            continue
        return {
            "source": {
                "image": f"{stand_in.image}:{stand_in.tag}",
                "digest": stand_in.digest,
                "platform": stand_in.platform,
                "pulled_from": ref,
                "name": name,
            },
            "inputs": [],
            "refusals": refusals,
        }
    raise RuntimeError("no registry served the pinned image: " + "; ".join(refusals))


def describe(path: Path) -> dict[str, Any]:
    error = validate_cyclonedx_16(path)
    if error is not None:
        raise RuntimeError(f"{path.name} is not valid CycloneDX 1.6: {error[:500]}")
    data = path.read_bytes()
    sbom = read_sbom(path)
    return {
        "file": str(path.relative_to(ROOT)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "spec_version": sbom.spec_version,
        "components_with_purl": len(sbom.components),
        "components_without_version": sum(
            1 for c in sbom.components if not c.version or c.version == "UNKNOWN"
        ),
        "quarantined_q07": len(sbom.quarantined),
        "not_packages": sbom.non_package,
        "validated": "CycloneDX 1.6 JSON schema (cyclonedx-python-lib 11.12.0)",
    }


def cmd_sboms(only: str | None = None) -> None:
    config: ProductsConfig = products.load_config(PRODUCTS)
    if not config.stand_ins:
        raise SystemExit("config/products.yaml has no stand_ins; run `make_sboms.py select` first")
    if not (BIN / "syft").exists():
        cmd_tools()
    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    previous: dict[str, Any] = json.loads(LOCK.read_text(encoding="utf-8")) if LOCK.exists() else {}
    entries: dict[str, Any] = {e["product"]: e for e in previous.get("sboms", [])}
    rules = {r.product: r for r in config.ecosystems}
    with client() as http:
        gh = GitHub(http)
        for stand_in in config.stand_ins:
            if only and stand_in.product != only:
                continue
            if stand_in.kind == "image":
                made = make_image_sbom(stand_in)
            else:
                made = make_repository_sbom(stand_in, rules[stand_in.product], gh)
            entry = {
                "product": stand_in.product,
                "ecosystem": stand_in.ecosystem,
                **describe(sbom_path(stand_in.product)),
                **made,
                "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            entries[stand_in.product] = entry
            print(
                f"sboms: {stand_in.product}: {entry['components_with_purl']} components with a purl, "
                f"{entry['quarantined_q07']} to Q07, sha256 {entry['sha256'][:12]}"
            )
    syft_pin = tools.SYFT.asset(tools.current_platform())
    lock = {
        "tool": {"name": "syft", "version": tools.SYFT.version, "asset": syft_pin[0], "sha256": syft_pin[1]},
        "format": "CycloneDX 1.6 JSON",
        "sboms": [entries[k] for k in sorted(entries)],
    }
    LOCK.write_text(json.dumps(lock, indent=1) + "\n", encoding="utf-8")
    print(f"sboms: wrote {LOCK.relative_to(ROOT)}")


def cmd_lock() -> None:
    """Rewrite the lock from the SBOMs on disk, with each stand in's scope as products.yaml states it."""
    config = products.load_config(PRODUCTS)
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    scopes = {s.product: s.scope for s in config.stand_ins}
    for entry in lock["sboms"]:
        entry.update(describe(ROOT / entry["file"]))
        if "scope" in entry["source"]:
            entry["source"]["scope"] = scopes[entry["product"]]
    LOCK.write_text(json.dumps(lock, indent=1) + "\n", encoding="utf-8")
    print(f"sboms: relocked {len(lock['sboms'])} SBOMs in {LOCK.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=["tools", "select", "sboms", "lock", "all"])
    parser.add_argument("--product", help="only this product, for sboms")
    args = parser.parse_args()
    if args.command in ("tools", "all"):
        cmd_tools()
    if args.command in ("select", "all"):
        cmd_select()
    if args.command in ("sboms", "all"):
        cmd_sboms(args.product)
    if args.command == "lock":
        cmd_lock()
    return 0


if __name__ == "__main__":
    sys.exit(main())
