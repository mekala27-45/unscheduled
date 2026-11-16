# 0013. The agent cannot act alone

Status: accepted, 16 November 2026

## Context

The triage agent drafts a patch plan and, for a listed or exploited CVE, an early warning. It drafts
from text anyone can write: CVE descriptions, advisories, KEV notes, CWE entries. It drafts with free
models that follow instructions well, including instructions planted in that text. A plan applied,
a warning filed or a severity changed on the model's word would let the author of an advisory act
through the agent. The same holds for anyone who can reach the API, the command line or the MCP
server.

## Decision

Nothing the agent writes takes effect without a person, and the person is named by a hash.

- **The graph stops.** The approve nodes are LangGraph interrupts. A run waits at the first one,
  with every checkpoint in Postgres, until a decision resumes it; the warning is drafted only after
  the plan is decided.
- **A decision names a draft.** It carries the SHA-256 of the exact verified draft it was shown.
  The status of a draft is computed every time it is read, from the draft as it stands and the
  decisions recorded for its hash, never stored as a flag. A draft changed after a decision has a
  new hash and no decision; a decision on a hash nobody was shown counts for nothing.
- **Only the approver decides.** POST /v1/approvals takes the approver's token as a Bearer
  credential. The API holds only its SHA-256 (APPROVER_TOKEN_SHA256, a Vercel variable Ajay sets),
  hashes what it receives, compares the two in constant time and logs neither. Without the token, or
  on another hash, nothing is recorded and the run does not move. The build never sees the token.
- **No path acts.** No route, command or MCP tool applies a plan, files a warning or changes a
  recorded value. The MCP dispatcher refuses such tools by name, and no command takes the token.
  Phase 3 has no code that applies, merges, sends or files anything; the approved and ready states
  exist so the property tests cover them before a later phase adds such a path.
- **A draft must hold before a person sees it.** The verifier checks every claim against the
  section of the source it cites, as that source was known at the run time. A claim that does not
  hold is removed; a draft whose required claims do not hold is blocked, and a blocked draft cannot
  become approved.
- **Text from outside stays data.** Retrieved text is normalized (hidden characters, comments,
  links), fenced as untrusted with its id and known_from, and every node may call only the sources
  its allowlist names. Every API answer and MCP result says which fields hold such text.

## Evidence

- C7 (results/agent/c7.json): a state machine over the graph through runs, decisions on the shown
  hash, on another hash and on none, with the token, a wrong token and none, edits of a draft,
  crashes, retries and forks; and over every served path, every route with every method, every
  command and every MCP tool, with a machine that starts runs through the API, the command line and
  MCP and decides through the one route that records decisions. No draft became approved or ready
  without a decision that counts.
- C6 (results/agent/c6.json, once the held out half is scored): the registered red team set, with
  planted instructions in every carrier the corpus has and requests for the tools that would act.

## Consequences

- Every plan and every warning waits for Ajay. The run store keeps at most the waiting runs ADR 0011
  allows, and past that a new run is refused until some are decided.
- An approved plan and a ready warning are records a person acts on, outside the system.
- A stolen token can record decisions, not apply anything; rotating it is a new hash in Vercel.

## Alternatives

- **Approval by confidence**, a model's score above a threshold. Rejected: the model is the part an
  advisory can steer.
- **A stored approver secret**, compared as text. Rejected: the API would hold the credential it
  checks, and a log line or a dump could leak it.
- **An MCP tool that approves with the token as an argument.** Rejected: the token would pass
  through a model's context and its transcript.
