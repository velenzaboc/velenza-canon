# Node Quality Discipline

Apply this checklist to every node before locking and saving. The passes catch misses, oversteps, and incorrectly-bundled concepts that would otherwise force a re-admission later.

The discipline exists because the recurring failure modes during corpus authoring have been: (1) claiming too little (missed first-principles defenses, missed observability claims, missed concept coverage), (2) claiming too much (overstepping into other axioms' territory, importing existing-spec vocabulary, encoding implementation), and (3) bundling concepts that should be their own nodes.

---

## Pass 1 — Misses (what should be claimed but isn't)

- [ ] Every load-bearing assert has a corresponding `why_*` rationale defending it on first principles
- [ ] Every concept referenced in the asserts is either defined in THIS node, defined in an earlier node, or listed in `out_of_scope` as deferred
- [ ] Observability of outcome is claimed where the node's behavior could otherwise be silent or indeterminate
- [ ] Self-application proof is present where the axiom's claims apply to itself
- [ ] Audit traceability — if the node claims a state-changing operation, the trace claim is present (or correctly deferred)
- [ ] First-principles defense in rationale: every `why_*` stands on its own without citing existing on-disk specs
- [ ] Coverage check: list every assert key + every rationale key and verify each load-bearing assert has a paired rationale

## Pass 2 — Oversteps (what's claimed but shouldn't be)

- [ ] No claim reaches into another axiom's owned territory (audit_axiom owns audit record content; reference_axiom owns edge semantics; the kind's declaration owns its validation rules)
- [ ] No implementation-mechanism specifics inside asserts (steps, algorithms, protocols, key resource names, table column names)
- [ ] No vocabulary borrowed from existing on-disk specs (VOLT terms like "ceremony", "signature_chain" as a noun, "opcode"; DocObject Lifecycle terms; LOEF terms) — every term defended on its own
- [ ] No "v2 will fix" hooks or transitional framings — if a claim isn't right NOW, it isn't right
- [ ] No "side log", "old spec", or other comparison framing that anchors the new corpus to existing specs
- [ ] No forward references that should be a separate node (see Pass 3)
- [ ] No "step" or "ceremony" language that imposes a specific procedure shape
- [ ] Statement and self_application_proof do not include anything the asserts don't claim

## Pass 3 — Is it its own node? (Decomposition test)

For every CONCEPT introduced in the node, ask whether it should be its own node. A concept should be factored out if ALL the following are true:

- [ ] Could later be improved upon (independent evolution path)
- [ ] Multiple things will reference it (centralized update propagates)
- [ ] Strong enough to stand on its own (atomic, defensible, has its own contract surface)
- [ ] Not a primitive (atomicity, timestamps, hashes, math operations, generic CS terms) — these are mechanism, not corpus concepts
- [ ] Not a per-instance property of another concept (a node_kind's validation rules belong to the kind, not their own thing)
- [ ] Has a unique answer to "what IS this?" that isn't bundled into another axiom's answer
- [ ] An auditor verifying the corpus benefits from one canonical site to verify this concept
- [ ] Subject to refinement by future requirements that the corpus would need to surface as a versioned thing

If ALL criteria pass: factor out into its own node.
If ANY criterion fails: keep bundled where it is.

Common decomposition catches (places to look hard):
- Concepts introduced in provenance fields (principal, attestation mechanisms, signing authorities)
- Concepts in cross-references that get reused (audit, registries, lifecycle states)
- Concepts that several future nodes will reference (authority, namespace, retention policy)
- Concepts that the node claims a property OF without defining (a claim about "X" without saying what X is)

## Pass 4 — Naming hygiene

- [ ] `canonical_name` describes the claim, not the implementation
- [ ] No VOLT-flavored terminology (`ceremony`, `lattice`, `opcode`, `circuit`, `signature_chain`-as-noun) in the canonical_name or assert keys
- [ ] Assert keys describe WHAT is asserted, not HOW
- [ ] `out_of_scope` items describe what is deferred (the concern), not where it's deferred TO (don't name future nodes; describe the deferred concern)
- [ ] Rationale keys named to make the connection to their assert clear (loose pattern: `why_<concept>`; exact matches not required, but the link should be readable)

## Pass 5 — Self-test

- [ ] Self-application: does this node satisfy its own asserts when applied to its own row?
- [ ] Contract monotonicity rule present and final ("the asserts block IS the contract and is final")
- [ ] The contract_monotonicity_rule explicitly forecloses weakening every load-bearing assert
- [ ] `out_of_scope` list complete enough that another author drafting an adjacent axiom knows what's deferred

## Pass 6 — Decision framework (apply at every fork during authoring)

When a design question arises during drafting, run the framework BEFORE asking the user:

1. **Origin** — does the founder's story decide this? (origin is the absolute terminus)
2. **Customer-long-term** — which choice serves security, durability, consistency, reliability, trust?
3. **First principles** — what does the claim itself require to be coherent?

If all three converge: lock and move on.
If they genuinely diverge (rare): surface as a real question.

**NEVER ask back what the framework already decides.** Listing "things to verify" back to the user when first principles + origin + customer-long-term already answer is the failure mode this discipline exists to eliminate.

## After every node is locked

Briefly note in the conversation:
- Which Pass 1 misses were caught and fixed
- Which Pass 2 oversteps were caught and fixed
- Which Pass 3 decomposition candidates were considered, and what was decided (factor out vs keep bundled)
- Any concept reference that depends on a future axiom (so the dependency order is tracked)

## End-of-turn "What's next" reporting

End-of-turn reports MAY include a brief "What's next" section listing logical follow-on phases or work items — but ONLY as informational status, never as a request to continue.

The distinction is **declarative vs interrogative**:

- ✓ **Informational** (welcome): "Next phases are X, Y, Z." / "The remaining axioms in the layer are A and B." / "After this layer, the corpus has its registry populated."
- ✗ **Interrogative / soliciting** (not welcome): "Should I proceed with X?" / "Want me to start Y?" / "Ready when you are." / "Lock this and I draft Z next?"

The user directs pacing; the report observes the landscape. A "What's next" section describes the terrain — it does not ask permission to walk it.

When uncertain whether a phrasing crosses the line, drop the phrasing entirely. The work-as-done report stands on its own.

## Failure-mode catalog (patterns to recognize)

Recurring patterns from prior authoring that this discipline catches:

- **Audit-record overstep** — admission_axiom claimed audit record commits atomically with admission; that's audit_axiom's territory.
- **"Step" language** — uniformity claim used "validation step, atomic-commit step, provenance step" which implied an N-step procedure (VOLT-shape leak).
- **"Side log" framing** — provenance rationale used "not in a side log" which conflicts with the audit chain audit_axiom will establish.
- **Missing observability** — admission_axiom claimed validation + atomicity but not that the outcome was observable to the submitter; trust requires verifiability requires observability.
- **Missing rationale pairing** — added a new assert (determinate_outcome) without adding its `why_*` defense.
- **Forward-reference-as-bundled** — admission_axiom referenced "the principal" without defining what a principal is; should have been its own axiom.
- **Asking what the framework decides** — listing "things to verify before locking" when origin + customer-long-term + first principles converge.
