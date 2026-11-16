/**
 * FIXTURE. Cut from real answers of the API in process over its own fixture bundle and corpus
 * (tests/api/fixtures) by scripts/cut_run_fixtures.py, with the fixture CVE renamed CVE-2099-0001
 * and the data version set to "fixture". Every value is what the API answered for invented data:
 * nothing here is data.
 */
import type { components } from "../api/openapi";
import { STATEMENT } from "../statement";

type S = components["schemas"];
type Problem = { type: string; title: string; status: number; detail: string; instance: string; statement: string; data_version: string };

/** A run at its first interrupt: the plan waits for a person. */
export const API_RUN_WAITING: S["RunView"] = {
  "statement": STATEMENT,
  "data_version": "fixture",
  "run_id": "3b4b263ad2a84712bbd485f5b32a73ca",
  "cve_id": "CVE-2099-0001",
  "as_of": "2022-01-15T23:59:59.999999+00:00",
  "parent_run_id": null,
  "status": "waiting",
  "waiting_for": [
    {
      "kind": "patch_plan",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023"
    }
  ],
  "drafts": {
    "plan": {
      "status": "waiting",
      "by": "floor",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "check": {
        "claims_drafted": 4,
        "claims_verified": 4,
        "claims_removed": 0,
        "citations_checked": 4,
        "citations_failed": 0,
        "failures": [],
        "blocked": false,
        "reasons": [],
        "draft": {
          "kind": "patch_plan",
          "cve_id": "CVE-2099-0001",
          "component": "example.org/fixture/logkit",
          "installed_version": "1.2.0",
          "fixed_version": "1.2.1",
          "steps": [
            "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
            "Rebuild and redeploy go-edge-service with the change.",
            "Run the scanner again and confirm that it no longer reports CVE-2099-0001."
          ],
          "claims": [
            {
              "field": "component",
              "value": "example.org/fixture/logkit",
              "text": "The affected component is example.org/fixture/logkit.",
              "citations": [
                {
                  "source": "state",
                  "section": "component",
                  "version": null
                }
              ]
            },
            {
              "field": "installed_version",
              "value": "1.2.0",
              "text": "The product runs example.org/fixture/logkit 1.2.0.",
              "citations": [
                {
                  "source": "state",
                  "section": "installed_version",
                  "version": null
                }
              ]
            },
            {
              "field": "fixed_version",
              "value": "1.2.1",
              "text": "The advisory states that 1.2.1 fixes CVE-2099-0001.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            },
            {
              "field": "action",
              "value": "1.2.1",
              "text": "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            }
          ]
        },
        "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
        "replaced": null,
        "by": "floor"
      }
    }
  },
  "approvals": [],
  "facts": {
    "description": "Fixture record. A deserialization flaw in an invented logging library lets a remote attacker run code.",
    "match": {
      "product": "go-edge-service",
      "component": "example.org/fixture/logkit",
      "ecosystem": "Go",
      "installed_version": "1.2.0"
    },
    "fixed_versions": [
      {
        "version": "1.2.1",
        "source": "ghsa:GHSA-fx01-0001-aaaa",
        "section": "affected",
        "doc_version": "2021-03-02T00:00:00Z"
      }
    ],
    "kev": {
      "source": "kev:CVE-2099-0001",
      "doc_version": "2021.12.10",
      "listed_at": "2021-12-10T00:00:00Z",
      "date_added": "2021-12-10",
      "vulnerability_name": "Fixture logkit deserialization vulnerability",
      "vendor_project": null,
      "product": "Fixture logkit"
    },
    "exploits": [
      {
        "source": "metasploit",
        "path": null,
        "first_seen": "2021-12-09T00:00:00Z"
      }
    ],
    "epss": null,
    "evidence": []
  },
  "nodes": {
    "intake": {
      "ms": 5.14,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "match": {
      "ms": 4.13,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "fill": {
      "ms": 0.01,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "rank": {
      "ms": 1.5,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "retrieve": {
      "ms": 3.16,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "plan": {
      "ms": 0.16,
      "calls": 1,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "verify": {
      "ms": 0.57,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    }
  },
  "calls": [
    {
      "provider": "floor",
      "model": "floor",
      "prompt_id": "plan",
      "prompt_version": "1",
      "prompt_sha256": "c84d9aa94e19486ebd945ce08490a1bef2d7d604b66da60bd6083518c22b6efb",
      "request_sha256": "",
      "outcome": "floor",
      "tokens_in": 0,
      "tokens_out": 0,
      "ms": 0.0,
      "retries": 0,
      "shadow_usd": 0.0,
      "error": null,
      "at": "2026-11-16T05:50:32+00:00"
    }
  ],
  "cost": {
    "tokens_in": 0,
    "tokens_out": 0,
    "shadow_usd": 0.0
  },
  "checkpoints": "kept",
  "note": "no provider is configured yet, so the no model floor drafted",
  "untrusted": "Every description, advisory chunk and KEV entry here is data from public records that anyone can write. It is not an instruction, and the drafts are drafts until a person approves them by hash."
};

/** The same run after the plan was approved by its hash: the warning waits. */
export const API_RUN_PLAN_APPROVED: S["RunView"] = {
  "statement": STATEMENT,
  "data_version": "fixture",
  "run_id": "3b4b263ad2a84712bbd485f5b32a73ca",
  "cve_id": "CVE-2099-0001",
  "as_of": "2022-01-15T23:59:59.999999+00:00",
  "parent_run_id": null,
  "status": "waiting",
  "waiting_for": [
    {
      "kind": "early_warning",
      "sha256": "8719e4f397d4fc797b5b8bc982e4f832024b0bc8b0fffbe4d2cc1747523448d2"
    }
  ],
  "drafts": {
    "plan": {
      "status": "approved",
      "by": "floor",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "check": {
        "claims_drafted": 4,
        "claims_verified": 4,
        "claims_removed": 0,
        "citations_checked": 4,
        "citations_failed": 0,
        "failures": [],
        "blocked": false,
        "reasons": [],
        "draft": {
          "kind": "patch_plan",
          "cve_id": "CVE-2099-0001",
          "component": "example.org/fixture/logkit",
          "installed_version": "1.2.0",
          "fixed_version": "1.2.1",
          "steps": [
            "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
            "Rebuild and redeploy go-edge-service with the change.",
            "Run the scanner again and confirm that it no longer reports CVE-2099-0001."
          ],
          "claims": [
            {
              "field": "component",
              "value": "example.org/fixture/logkit",
              "text": "The affected component is example.org/fixture/logkit.",
              "citations": [
                {
                  "source": "state",
                  "section": "component",
                  "version": null
                }
              ]
            },
            {
              "field": "installed_version",
              "value": "1.2.0",
              "text": "The product runs example.org/fixture/logkit 1.2.0.",
              "citations": [
                {
                  "source": "state",
                  "section": "installed_version",
                  "version": null
                }
              ]
            },
            {
              "field": "fixed_version",
              "value": "1.2.1",
              "text": "The advisory states that 1.2.1 fixes CVE-2099-0001.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            },
            {
              "field": "action",
              "value": "1.2.1",
              "text": "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            }
          ]
        },
        "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
        "replaced": null,
        "by": "floor"
      }
    },
    "warning": {
      "status": "waiting",
      "by": "floor",
      "sha256": "8719e4f397d4fc797b5b8bc982e4f832024b0bc8b0fffbe4d2cc1747523448d2",
      "check": {
        "claims_drafted": 6,
        "claims_verified": 6,
        "claims_removed": 0,
        "citations_checked": 6,
        "citations_failed": 0,
        "failures": [],
        "blocked": false,
        "reasons": [],
        "draft": {
          "kind": "early_warning",
          "cve_id": "CVE-2099-0001",
          "product": "go-edge-service",
          "vulnerability": "CVE-2099-0001, Fixture logkit deserialization vulnerability",
          "actively_exploited": true,
          "evidence": "CISA added it to the Known Exploited Vulnerabilities catalog on 2021-12-10; exploit code was first seen in metasploit on 2021-12-09.",
          "member_states": "not known",
          "claims": [
            {
              "field": "product",
              "value": "go-edge-service",
              "text": "The product is go-edge-service.",
              "citations": [
                {
                  "source": "state",
                  "section": "product",
                  "version": null
                }
              ]
            },
            {
              "field": "vulnerability",
              "value": "Fixture logkit deserialization vulnerability",
              "text": "The vulnerability is CVE-2099-0001, Fixture logkit deserialization vulnerability.",
              "citations": [
                {
                  "source": "kev:CVE-2099-0001",
                  "section": "entry",
                  "version": "2021.12.10"
                }
              ]
            },
            {
              "field": "exploitation_evidence",
              "value": "2021-12-10",
              "text": "CISA added CVE-2099-0001 to the Known Exploited Vulnerabilities catalog on 2021-12-10.",
              "citations": [
                {
                  "source": "kev:CVE-2099-0001",
                  "section": "entry",
                  "version": "2021.12.10"
                }
              ]
            },
            {
              "field": "exploitation_evidence",
              "value": "2021-12-09",
              "text": "Exploit code for CVE-2099-0001 was first seen in metasploit on 2021-12-09.",
              "citations": [
                {
                  "source": "state",
                  "section": "exploits",
                  "version": null
                }
              ]
            },
            {
              "field": "exploitation",
              "value": "actively exploited",
              "text": "CVE-2099-0001 is actively exploited.",
              "citations": [
                {
                  "source": "state",
                  "section": "exploits",
                  "version": null
                }
              ]
            },
            {
              "field": "member_states",
              "value": "not known",
              "text": "No source names the member states concerned.",
              "citations": [
                {
                  "source": "state",
                  "section": "member_states",
                  "version": null
                }
              ]
            }
          ]
        },
        "sha256": "8719e4f397d4fc797b5b8bc982e4f832024b0bc8b0fffbe4d2cc1747523448d2",
        "replaced": null,
        "by": "floor"
      }
    }
  },
  "approvals": [
    {
      "run_id": "3b4b263ad2a84712bbd485f5b32a73ca",
      "kind": "plan",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "decision": "approve",
      "by": "ajay",
      "at": "2026-11-16T05:50:32+00:00",
      "token_ok": true
    }
  ],
  "facts": {
    "description": "Fixture record. A deserialization flaw in an invented logging library lets a remote attacker run code.",
    "match": {
      "product": "go-edge-service",
      "component": "example.org/fixture/logkit",
      "ecosystem": "Go",
      "installed_version": "1.2.0"
    },
    "fixed_versions": [
      {
        "version": "1.2.1",
        "source": "ghsa:GHSA-fx01-0001-aaaa",
        "section": "affected",
        "doc_version": "2021-03-02T00:00:00Z"
      }
    ],
    "kev": {
      "source": "kev:CVE-2099-0001",
      "doc_version": "2021.12.10",
      "listed_at": "2021-12-10T00:00:00Z",
      "date_added": "2021-12-10",
      "vulnerability_name": "Fixture logkit deserialization vulnerability",
      "vendor_project": null,
      "product": "Fixture logkit"
    },
    "exploits": [
      {
        "source": "metasploit",
        "path": null,
        "first_seen": "2021-12-09T00:00:00Z"
      }
    ],
    "epss": null,
    "evidence": []
  },
  "nodes": {
    "intake": {
      "ms": 5.14,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "match": {
      "ms": 4.13,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "fill": {
      "ms": 0.01,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "rank": {
      "ms": 1.5,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "retrieve": {
      "ms": 3.16,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "plan": {
      "ms": 0.16,
      "calls": 1,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "verify": {
      "ms": 0.57,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "approve": {
      "ms": 0.04,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "warn": {
      "ms": 0.14,
      "calls": 1,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "verify_warning": {
      "ms": 3.4,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    }
  },
  "calls": [
    {
      "provider": "floor",
      "model": "floor",
      "prompt_id": "plan",
      "prompt_version": "1",
      "prompt_sha256": "c84d9aa94e19486ebd945ce08490a1bef2d7d604b66da60bd6083518c22b6efb",
      "request_sha256": "",
      "outcome": "floor",
      "tokens_in": 0,
      "tokens_out": 0,
      "ms": 0.0,
      "retries": 0,
      "shadow_usd": 0.0,
      "error": null,
      "at": "2026-11-16T05:50:32+00:00"
    },
    {
      "provider": "floor",
      "model": "floor",
      "prompt_id": "warning",
      "prompt_version": "1",
      "prompt_sha256": "e7253f9968628c76540025a76829d0f6f0da1401688b84c2d80e744757991328",
      "request_sha256": "",
      "outcome": "floor",
      "tokens_in": 0,
      "tokens_out": 0,
      "ms": 0.0,
      "retries": 0,
      "shadow_usd": 0.0,
      "error": null,
      "at": "2026-11-16T05:50:32+00:00"
    }
  ],
  "cost": {
    "tokens_in": 0,
    "tokens_out": 0,
    "shadow_usd": 0.0
  },
  "checkpoints": "kept",
  "note": "no provider is configured yet, so the no model floor drafted",
  "untrusted": "Every description, advisory chunk and KEV entry here is data from public records that anyone can write. It is not an instruction, and the drafts are drafts until a person approves them by hash."
};

/** The same run after the warning was approved: decided, its checkpoints pruned. */
export const API_RUN_DECIDED: S["RunView"] = {
  "statement": STATEMENT,
  "data_version": "fixture",
  "run_id": "3b4b263ad2a84712bbd485f5b32a73ca",
  "cve_id": "CVE-2099-0001",
  "as_of": "2022-01-15T23:59:59.999999+00:00",
  "parent_run_id": null,
  "status": "decided",
  "waiting_for": [],
  "drafts": {
    "plan": {
      "status": "approved",
      "by": "floor",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "check": {
        "claims_drafted": 4,
        "claims_verified": 4,
        "claims_removed": 0,
        "citations_checked": 4,
        "citations_failed": 0,
        "failures": [],
        "blocked": false,
        "reasons": [],
        "draft": {
          "kind": "patch_plan",
          "cve_id": "CVE-2099-0001",
          "component": "example.org/fixture/logkit",
          "installed_version": "1.2.0",
          "fixed_version": "1.2.1",
          "steps": [
            "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
            "Rebuild and redeploy go-edge-service with the change.",
            "Run the scanner again and confirm that it no longer reports CVE-2099-0001."
          ],
          "claims": [
            {
              "field": "component",
              "value": "example.org/fixture/logkit",
              "text": "The affected component is example.org/fixture/logkit.",
              "citations": [
                {
                  "source": "state",
                  "section": "component",
                  "version": null
                }
              ]
            },
            {
              "field": "installed_version",
              "value": "1.2.0",
              "text": "The product runs example.org/fixture/logkit 1.2.0.",
              "citations": [
                {
                  "source": "state",
                  "section": "installed_version",
                  "version": null
                }
              ]
            },
            {
              "field": "fixed_version",
              "value": "1.2.1",
              "text": "The advisory states that 1.2.1 fixes CVE-2099-0001.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            },
            {
              "field": "action",
              "value": "1.2.1",
              "text": "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            }
          ]
        },
        "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
        "replaced": null,
        "by": "floor"
      }
    },
    "warning": {
      "status": "ready",
      "by": "floor",
      "sha256": "8719e4f397d4fc797b5b8bc982e4f832024b0bc8b0fffbe4d2cc1747523448d2",
      "check": {
        "claims_drafted": 6,
        "claims_verified": 6,
        "claims_removed": 0,
        "citations_checked": 6,
        "citations_failed": 0,
        "failures": [],
        "blocked": false,
        "reasons": [],
        "draft": {
          "kind": "early_warning",
          "cve_id": "CVE-2099-0001",
          "product": "go-edge-service",
          "vulnerability": "CVE-2099-0001, Fixture logkit deserialization vulnerability",
          "actively_exploited": true,
          "evidence": "CISA added it to the Known Exploited Vulnerabilities catalog on 2021-12-10; exploit code was first seen in metasploit on 2021-12-09.",
          "member_states": "not known",
          "claims": [
            {
              "field": "product",
              "value": "go-edge-service",
              "text": "The product is go-edge-service.",
              "citations": [
                {
                  "source": "state",
                  "section": "product",
                  "version": null
                }
              ]
            },
            {
              "field": "vulnerability",
              "value": "Fixture logkit deserialization vulnerability",
              "text": "The vulnerability is CVE-2099-0001, Fixture logkit deserialization vulnerability.",
              "citations": [
                {
                  "source": "kev:CVE-2099-0001",
                  "section": "entry",
                  "version": "2021.12.10"
                }
              ]
            },
            {
              "field": "exploitation_evidence",
              "value": "2021-12-10",
              "text": "CISA added CVE-2099-0001 to the Known Exploited Vulnerabilities catalog on 2021-12-10.",
              "citations": [
                {
                  "source": "kev:CVE-2099-0001",
                  "section": "entry",
                  "version": "2021.12.10"
                }
              ]
            },
            {
              "field": "exploitation_evidence",
              "value": "2021-12-09",
              "text": "Exploit code for CVE-2099-0001 was first seen in metasploit on 2021-12-09.",
              "citations": [
                {
                  "source": "state",
                  "section": "exploits",
                  "version": null
                }
              ]
            },
            {
              "field": "exploitation",
              "value": "actively exploited",
              "text": "CVE-2099-0001 is actively exploited.",
              "citations": [
                {
                  "source": "state",
                  "section": "exploits",
                  "version": null
                }
              ]
            },
            {
              "field": "member_states",
              "value": "not known",
              "text": "No source names the member states concerned.",
              "citations": [
                {
                  "source": "state",
                  "section": "member_states",
                  "version": null
                }
              ]
            }
          ]
        },
        "sha256": "8719e4f397d4fc797b5b8bc982e4f832024b0bc8b0fffbe4d2cc1747523448d2",
        "replaced": null,
        "by": "floor"
      }
    }
  },
  "approvals": [
    {
      "run_id": "3b4b263ad2a84712bbd485f5b32a73ca",
      "kind": "plan",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "decision": "approve",
      "by": "ajay",
      "at": "2026-11-16T05:50:32+00:00",
      "token_ok": true
    },
    {
      "run_id": "3b4b263ad2a84712bbd485f5b32a73ca",
      "kind": "warning",
      "sha256": "8719e4f397d4fc797b5b8bc982e4f832024b0bc8b0fffbe4d2cc1747523448d2",
      "decision": "approve",
      "by": "ajay",
      "at": "2026-11-16T05:50:32+00:00",
      "token_ok": true
    }
  ],
  "facts": {
    "description": "Fixture record. A deserialization flaw in an invented logging library lets a remote attacker run code.",
    "match": {
      "product": "go-edge-service",
      "component": "example.org/fixture/logkit",
      "ecosystem": "Go",
      "installed_version": "1.2.0"
    },
    "fixed_versions": [
      {
        "version": "1.2.1",
        "source": "ghsa:GHSA-fx01-0001-aaaa",
        "section": "affected",
        "doc_version": "2021-03-02T00:00:00Z"
      }
    ],
    "kev": {
      "source": "kev:CVE-2099-0001",
      "doc_version": "2021.12.10",
      "listed_at": "2021-12-10T00:00:00Z",
      "date_added": "2021-12-10",
      "vulnerability_name": "Fixture logkit deserialization vulnerability",
      "vendor_project": null,
      "product": "Fixture logkit"
    },
    "exploits": [
      {
        "source": "metasploit",
        "path": null,
        "first_seen": "2021-12-09T00:00:00Z"
      }
    ],
    "epss": null,
    "evidence": []
  },
  "nodes": {
    "intake": {
      "ms": 5.14,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "match": {
      "ms": 4.13,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "fill": {
      "ms": 0.01,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "rank": {
      "ms": 1.5,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "retrieve": {
      "ms": 3.16,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "plan": {
      "ms": 0.16,
      "calls": 1,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "verify": {
      "ms": 0.57,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "approve": {
      "ms": 0.04,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "warn": {
      "ms": 0.14,
      "calls": 1,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "verify_warning": {
      "ms": 3.4,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "approve_warning": {
      "ms": 0.03,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "done": {
      "ms": 0.0,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    }
  },
  "calls": [
    {
      "provider": "floor",
      "model": "floor",
      "prompt_id": "plan",
      "prompt_version": "1",
      "prompt_sha256": "c84d9aa94e19486ebd945ce08490a1bef2d7d604b66da60bd6083518c22b6efb",
      "request_sha256": "",
      "outcome": "floor",
      "tokens_in": 0,
      "tokens_out": 0,
      "ms": 0.0,
      "retries": 0,
      "shadow_usd": 0.0,
      "error": null,
      "at": "2026-11-16T05:50:32+00:00"
    },
    {
      "provider": "floor",
      "model": "floor",
      "prompt_id": "warning",
      "prompt_version": "1",
      "prompt_sha256": "e7253f9968628c76540025a76829d0f6f0da1401688b84c2d80e744757991328",
      "request_sha256": "",
      "outcome": "floor",
      "tokens_in": 0,
      "tokens_out": 0,
      "ms": 0.0,
      "retries": 0,
      "shadow_usd": 0.0,
      "error": null,
      "at": "2026-11-16T05:50:32+00:00"
    }
  ],
  "cost": {
    "tokens_in": 0,
    "tokens_out": 0,
    "shadow_usd": 0.0
  },
  "checkpoints": "kept",
  "note": "no provider is configured yet, so the no model floor drafted",
  "untrusted": "Every description, advisory chunk and KEV entry here is data from public records that anyone can write. It is not an instruction, and the drafts are drafts until a person approves them by hash."
};

/** A run as of a day before the KEV listing and the advisory: no fix known, no warning. */
export const API_RUN_EARLY: S["RunView"] = {
  "statement": STATEMENT,
  "data_version": "fixture",
  "run_id": "f6533f9ed27749d18105310c7f4551d3",
  "cve_id": "CVE-2099-0001",
  "as_of": "2021-06-01T23:59:59.999999+00:00",
  "parent_run_id": null,
  "status": "waiting",
  "waiting_for": [
    {
      "kind": "patch_plan",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023"
    }
  ],
  "drafts": {
    "plan": {
      "status": "waiting",
      "by": "floor",
      "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "check": {
        "claims_drafted": 4,
        "claims_verified": 4,
        "claims_removed": 0,
        "citations_checked": 4,
        "citations_failed": 0,
        "failures": [],
        "blocked": false,
        "reasons": [],
        "draft": {
          "kind": "patch_plan",
          "cve_id": "CVE-2099-0001",
          "component": "example.org/fixture/logkit",
          "installed_version": "1.2.0",
          "fixed_version": "1.2.1",
          "steps": [
            "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
            "Rebuild and redeploy go-edge-service with the change.",
            "Run the scanner again and confirm that it no longer reports CVE-2099-0001."
          ],
          "claims": [
            {
              "field": "component",
              "value": "example.org/fixture/logkit",
              "text": "The affected component is example.org/fixture/logkit.",
              "citations": [
                {
                  "source": "state",
                  "section": "component",
                  "version": null
                }
              ]
            },
            {
              "field": "installed_version",
              "value": "1.2.0",
              "text": "The product runs example.org/fixture/logkit 1.2.0.",
              "citations": [
                {
                  "source": "state",
                  "section": "installed_version",
                  "version": null
                }
              ]
            },
            {
              "field": "fixed_version",
              "value": "1.2.1",
              "text": "The advisory states that 1.2.1 fixes CVE-2099-0001.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            },
            {
              "field": "action",
              "value": "1.2.1",
              "text": "Upgrade example.org/fixture/logkit from 1.2.0 to 1.2.1 or later.",
              "citations": [
                {
                  "source": "ghsa:GHSA-fx01-0001-aaaa",
                  "section": "affected",
                  "version": "2021-03-02T00:00:00Z"
                }
              ]
            }
          ]
        },
        "sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
        "replaced": null,
        "by": "floor"
      }
    }
  },
  "approvals": [],
  "facts": {
    "description": "Fixture record. A deserialization flaw in an invented logging library lets a remote attacker run code.",
    "match": {
      "product": "go-edge-service",
      "component": "example.org/fixture/logkit",
      "ecosystem": "Go",
      "installed_version": "1.2.0"
    },
    "fixed_versions": [
      {
        "version": "1.2.1",
        "source": "ghsa:GHSA-fx01-0001-aaaa",
        "section": "affected",
        "doc_version": "2021-03-02T00:00:00Z"
      }
    ],
    "kev": null,
    "exploits": [],
    "epss": null,
    "evidence": []
  },
  "nodes": {
    "intake": {
      "ms": 3.46,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "match": {
      "ms": 2.9,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "fill": {
      "ms": 0.01,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "rank": {
      "ms": 0.01,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "retrieve": {
      "ms": 3.23,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "plan": {
      "ms": 0.11,
      "calls": 1,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    },
    "verify": {
      "ms": 0.28,
      "calls": 0,
      "tokens_in": 0,
      "tokens_out": 0,
      "shadow_usd": 0.0
    }
  },
  "calls": [
    {
      "provider": "floor",
      "model": "floor",
      "prompt_id": "plan",
      "prompt_version": "1",
      "prompt_sha256": "c84d9aa94e19486ebd945ce08490a1bef2d7d604b66da60bd6083518c22b6efb",
      "request_sha256": "",
      "outcome": "floor",
      "tokens_in": 0,
      "tokens_out": 0,
      "ms": 0.0,
      "retries": 0,
      "shadow_usd": 0.0,
      "error": null,
      "at": "2026-11-16T05:50:32+00:00"
    }
  ],
  "cost": {
    "tokens_in": 0,
    "tokens_out": 0,
    "shadow_usd": 0.0
  },
  "checkpoints": "kept",
  "note": "no provider is configured yet, so the no model floor drafted",
  "untrusted": "Every description, advisory chunk and KEV entry here is data from public records that anyone can write. It is not an instruction, and the drafts are drafts until a person approves them by hash."
};

/** The runs, newest first. */
export const API_RUNS: S["RunList"] = {
  "statement": STATEMENT,
  "data_version": "fixture",
  "runs": [
    {
      "run_id": "f6533f9ed27749d18105310c7f4551d3",
      "cve_id": "CVE-2099-0001",
      "as_of": "2021-06-01T23:59:59.999999Z",
      "status": "waiting",
      "created_at": "2026-11-16T05:50:32.371790Z",
      "plan_sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "warning_sha256": null
    },
    {
      "run_id": "3b4b263ad2a84712bbd485f5b32a73ca",
      "cve_id": "CVE-2099-0001",
      "as_of": "2022-01-15T23:59:59.999999Z",
      "status": "decided",
      "created_at": "2026-11-16T05:50:32.228390Z",
      "plan_sha256": "bf61a0ca523740b166a4039b8bb94d459bb79cac2342f4126f5c0bbff65a1023",
      "warning_sha256": "8719e4f397d4fc797b5b8bc982e4f832024b0bc8b0fffbe4d2cc1747523448d2"
    }
  ]
};

/** A search as of a day after the advisory was published. */
export const API_SEARCH: S["SearchResults"] = {
  "statement": STATEMENT,
  "data_version": "fixture",
  "query": "logkit deserialization",
  "as_of": "2022-01-01",
  "configuration": "floor",
  "results": [
    {
      "chunk_id": "kev:CVE-2099-0001@2021.12.10#0",
      "doc_id": "kev:CVE-2099-0001",
      "version": "2021.12.10",
      "sections": [
        "entry"
      ],
      "known_from": "2021-12-10T00:00:00Z",
      "text": "Fixture logkit deserialization vulnerability\nProduct: Fixture logkit\nAdded to KEV on 2021-12-10",
      "score": 0.125,
      "untrusted": true
    },
    {
      "chunk_id": "ghsa:GHSA-fx01-0001-aaaa@2021-03-02T00:00:00Z#1",
      "doc_id": "ghsa:GHSA-fx01-0001-aaaa",
      "version": "2021-03-02T00:00:00Z",
      "sections": [
        "details"
      ],
      "known_from": "2021-03-02T00:00:00Z",
      "text": "Fixture advisory. logkit deserializes log records from the network without checks.",
      "score": 0.1,
      "untrusted": true
    },
    {
      "chunk_id": "ghsa:GHSA-fx01-0001-aaaa@2021-03-02T00:00:00Z#0",
      "doc_id": "ghsa:GHSA-fx01-0001-aaaa",
      "version": "2021-03-02T00:00:00Z",
      "sections": [
        "summary"
      ],
      "known_from": "2021-03-02T00:00:00Z",
      "text": "Remote code execution in logkit through unsafe deserialization",
      "score": 0.033333335,
      "untrusted": true
    },
    {
      "chunk_id": "kev:CVE-2099-0001@2021.12.10#1",
      "doc_id": "kev:CVE-2099-0001",
      "version": "2021.12.10",
      "sections": [
        "description"
      ],
      "known_from": "2021-12-10T00:00:00Z",
      "text": "Fixture logkit contains a deserialization flaw that allows remote code execution.",
      "score": 0.033333335,
      "untrusted": true
    }
  ]
};

/** A decision sent without the token: refused, nothing recorded. */
export const API_APPROVAL_REFUSED: Problem = {
  "type": "https://github.com/mekala27-45/unscheduled/blob/main/docs/SPEC.md#problem-approval-refused",
  "title": "The decision was refused and nothing was recorded",
  "status": 403,
  "detail": "a decision needs the approver's token; nothing was recorded",
  "instance": "/v1/approvals",
  "statement": STATEMENT,
  "data_version": "fixture"
};
