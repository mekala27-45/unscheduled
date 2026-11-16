"""The no model floor: the patch plan and the early warning written from the typed state with
templates, each claim citing the source that holds its fact.

It is always available, costs nothing and takes no time worth counting, so the router ends with it
and every model configuration is compared with it. It never reads the text of a retrieved chunk as
an instruction: the only text it copies is a value the graph put in the typed state by code (a
version from an advisory's affected section, a name from the KEV entry), and every such value keeps
the citation of where it came from.
"""

from __future__ import annotations

from unscheduled_agent.schemas import STATE, Citation, Claim, EarlyWarning, Facts, PatchPlan

NOT_KNOWN = "not known"


def _state(field: str) -> list[Citation]:
    return [Citation(source=STATE, section=field)]


def plan(facts: Facts) -> PatchPlan:
    claims: list[Claim] = []
    component = facts.component
    installed = facts.installed_version
    if component:
        claims.append(
            Claim(
                field="component",
                value=component,
                text=f"The affected component is {component}.",
                citations=_state("component"),
            )
        )
    if installed:
        claims.append(
            Claim(
                field="installed_version",
                value=installed,
                text=f"The product runs {component or 'the component'} {installed}.",
                citations=_state("installed_version"),
            )
        )
    fixed = facts.fixed_versions[0] if facts.fixed_versions else None
    steps: list[str] = []
    if fixed is not None:
        cite = [Citation(source=fixed.source, section=fixed.section, version=fixed.doc_version)]
        claims.append(
            Claim(
                field="fixed_version",
                value=fixed.version,
                text=f"The advisory states that {fixed.version} fixes {facts.cve_id}.",
                citations=cite,
            )
        )
        action = f"Upgrade {component or 'the component'} from {installed or 'the installed version'} to {fixed.version} or later."
        claims.append(Claim(field="action", value=fixed.version, text=action, citations=cite))
        steps.append(action)
    else:
        claims.append(
            Claim(
                field="no_fixed_version",
                value="none",
                text=f"No source known on {facts.as_of.date().isoformat()} gives a fixed version for {facts.cve_id}.",
                citations=_state("fixed_versions"),
            )
        )
        steps.append(
            f"Hold {component or 'the component'} at {installed or 'its version'}, limit its exposure, and watch the advisories for a fix."
        )
    steps.append(f"Rebuild and redeploy {facts.product or 'the product'} with the change.")
    steps.append(f"Run the scanner again and confirm that it no longer reports {facts.cve_id}.")
    return PatchPlan(
        cve_id=facts.cve_id,
        component=component,
        installed_version=installed,
        fixed_version=fixed.version if fixed else None,
        steps=steps,
        claims=claims,
    )


def warning(facts: Facts) -> EarlyWarning:
    claims: list[Claim] = []
    kev = facts.kev
    product = facts.product
    if product:
        claims.append(
            Claim(
                field="product", value=product, text=f"The product is {product}.", citations=_state("product")
            )
        )
    elif kev and kev.product:
        product = " ".join(p for p in (kev.vendor_project, kev.product) if p)
        claims.append(
            Claim(
                field="product",
                value=kev.product,
                text=f"The product is {product}.",
                citations=[Citation(source=kev.source, section="entry", version=kev.doc_version)],
            )
        )
    if kev and kev.vulnerability_name:
        vulnerability = f"{facts.cve_id}, {kev.vulnerability_name}"
        claims.append(
            Claim(
                field="vulnerability",
                value=kev.vulnerability_name,
                text=f"The vulnerability is {vulnerability}.",
                citations=[Citation(source=kev.source, section="entry", version=kev.doc_version)],
            )
        )
    else:
        vulnerability = facts.cve_id
        claims.append(
            Claim(
                field="vulnerability",
                value=facts.cve_id,
                text=f"The vulnerability is {facts.cve_id}.",
                citations=_state("cve_id"),
            )
        )
    evidence: list[str] = []
    if kev:
        day = (kev.date_added or kev.listed_at.date()).isoformat()
        evidence.append(f"CISA added it to the Known Exploited Vulnerabilities catalog on {day}")
        claims.append(
            Claim(
                field="exploitation_evidence",
                value=day,
                text=f"CISA added {facts.cve_id} to the Known Exploited Vulnerabilities catalog on {day}.",
                citations=[Citation(source=kev.source, section="entry", version=kev.doc_version)],
            )
        )
    for signal in facts.exploits[:3]:
        day = signal.first_seen.date().isoformat()
        evidence.append(f"exploit code was first seen in {signal.source} on {day}")
        claims.append(
            Claim(
                field="exploitation_evidence",
                value=day,
                text=f"Exploit code for {facts.cve_id} was first seen in {signal.source} on {day}.",
                citations=_state("exploits"),
            )
        )
    exploited = bool(kev or facts.exploits)
    claims.append(
        Claim(
            field="exploitation",
            value="actively exploited" if exploited else "no evidence of exploitation",
            text=f"{facts.cve_id} is {'actively exploited' if exploited else 'not known to be exploited'}.",
            citations=claims[-1].citations if exploited else _state("exploits"),
        )
    )
    claims.append(
        Claim(
            field="member_states",
            value=NOT_KNOWN,
            text="No source names the member states concerned.",
            citations=_state("member_states"),
        )
    )
    return EarlyWarning(
        cve_id=facts.cve_id,
        product=product,
        vulnerability=vulnerability,
        actively_exploited=exploited,
        evidence="; ".join(evidence) + "." if evidence else "No exploitation evidence is known.",
        member_states=NOT_KNOWN,
        claims=claims,
    )
