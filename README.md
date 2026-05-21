# aps-x402-composition

Reference composition: how an **APS delegation**, an **x402 settlement**,
and a **mock AgentCore-style action** combine into a bilateral receipt
chain that a third party can verify end-to-end.

Phase 1 ships a one-command demo, an importable verifier, and the four
artifacts (`payment_hash`, `action_ref`, permit receipt, completion
receipt) the chain produces.

## Status

- **Phase 1, single-hop.** Mock facilitator. Mock action backend.
- Not a production deployment. Not a launch announcement. Not a pitch
  for any vendor — the AgentCore-shape action is a generic typed
  shape, not a callout to a specific runtime.
- License: Apache-2.0.

## What each layer proves (and what it doesn't)

| Layer | Proves | Does **not** prove |
| --- | --- | --- |
| APS delegation | A principal authorized this agent inside this scope, with this spend cap, with this expiry, signed. | That the agent will not exceed the cap. (Enforcement is a separate gateway concern.) |
| x402 settlement | A facilitator verified an EIP-3009 transfer authorization and the recipient was paid `tx_proof`. | That the funds correspond to the right action. (The binding is established off-rail, in the receipt.) |
| Mock action | An action executed against a target with a content-addressed `action_ref` and a hashed output payload. | That the action's *semantics* were correct. (Semantic correctness needs a domain-specific check; the receipt only commits the inputs and the output digest.) |
| Permit receipt (APS `ActionReceipt`) | The agent claims it executed this action, under this delegation, spending this much, with this outcome — signed by the agent. | Anything about the gateway's view. The permit is the agent's half of the bilateral pair. |
| Payment receipt (x402 `PaymentReceipt`) | The gateway observed `(delegation_ref, action_ref, tx_proof)` and signed the binding. | That the agent agrees with the binding. (Bilateral pairs require both halves.) |
| Completion receipt | The gateway records the execution result and pins itself to `SHA-256(canonicalize(permit \ signature))`. | Anything not in the permit's pre-image. |

The bilateral pair is what closes the loop: the permit and the
completion together commit both parties to the same execution. A
single-sided receipt is impeachable; a paired receipt is not.

## Composition pattern

```
Principal ──(signed delegation)──▶ Agent
                                   │
                                   ▼
                            x402 facilitator
                          (verify + settle ⇒ tx_proof)
                                   │
                                   ▼
                          Mock AgentCore-shape action
                          (action_ref = SHA-256(...))
                                   │
                                   ▼
            ┌─────────── Gateway ───────────┐
            │                               │
   permit receipt                  payment receipt
   (agent-signed,                 (gateway-signed,
    APS ActionReceipt)             x402 PaymentReceipt)
            │                               │
            └────────────┬──────────────────┘
                         ▼
                completion receipt
              (gateway-signed; pins
               unsigned permit hash)
```

## Run it

```bash
npm install
npm run demo      # emits fixtures/run.*.json, exits 0 on success
npm run verify    # reads the four artifacts, prints a PASS/FAIL block
```

Expected output: an 11-check `OVERALL: PASS` from the verifier. A full
captured trace lives at [`examples/run-trace.txt`](examples/run-trace.txt).

## What's in `fixtures/`

The demo regenerates these on every run (timestamps and UUIDs vary; the
canonical *substrate* is byte-deterministic, but the wall-clock fields
are not). Re-running the demo and then the verifier is the smoke test
the CI workflow runs.

| File | Source | Content |
| --- | --- | --- |
| `run.delegation.json` | principal-signed | `Delegation` (APS) |
| `run.action.json` | mock action runtime | action id, `action_ref`, `payload_hash`, status |
| `run.permit-receipt.json` | agent-signed | `ActionReceipt` (APS) |
| `run.payment-receipt.json` | gateway-signed | `PaymentReceipt` (APS x402 rail) |
| `run.completion-receipt.json` | gateway-signed | `CompletionReceipt` (APS) |
| `run.summary.json` | demo | substrate versions, identities, the four artifact hashes |

## The verifier

`src/verifier.ts` is importable. The full API:

```ts
import { verify, type Artifacts, type Report } from './src/verifier.js'

const report: Report = verify(artifacts)
//   report.pass — overall boolean
//   report.checks — { id, description, pass, detail? }[]
```

The 11 checks it runs:

1. `permit_signature` — the permit's agent signature verifies.
2. `completion_pins_permit` — the completion receipt's `permitReceiptHash` equals `SHA-256(canonicalize(permit \ signature))`.
3. `permit_completion_link` — APS's `linkPermitAndCompletion()` reports linked.
4. `completion_signature` — the gateway signature on the completion receipt verifies (gateway pubkey resolved from the payment receipt's `signer_did`).
5. `payment_signature` — the gateway signature + canonical-hash on the payment receipt verifies.
6. `action_ref_match` — payment receipt and action artifact carry the same `action_ref`.
7. `delegation_ref_match` — payment receipt's `delegation_ref` equals the permit's `delegationId`.
8. `payment_hash_shape` — `tx_proof` is `0x` + 64 lowercase-hex.
9. `payload_hash_shape` — action `payload_hash` is bare 64 lowercase-hex.
10. `spend_amount_match` — permit's recorded spend equals payment's `amount_base_units`.
11. `completion_status_match` — completion's `executionResult` equals action's `status`.

Exit code: `0` on PASS, `1` on FAIL, `2` on argument/load error.

## Hashing substrate

The `action_ref` (the cross-engine correlation anchor under
draft-pidlisnyi-aps-00 §4.1) is computed as **SHA-256(strict RFC 8785
JCS) in lowercase hex**, via APS's `canonicalizeJCS()` (re-exported from
`src/core/canonical-jcs.ts`). This matches the `rfc8785@0.1.4` +
lowercase-hex SHA-256 substrate used across the x402 ecosystem
(giskard09's `argentum-core`, andysalvo's verifier, and the AgentGraph
CTEF byte-match harness). The SDK's own `computeActionRef` switched to
the same path in 2.6.0-alpha.4; this demo wires the local helper
directly to `canonicalizeJCS` for forward compatibility on any
published 2.6.0-alpha SDK.

The **permit↔completion link binding** (the canonical hash the
completion receipt pins to the permit receipt) still rides APS's
legacy canonical-JSON variant — sorted keys, null-stripped — because
that is what `linkPermitAndCompletion()` expects internally. The two
streams agree byte-for-byte on every null-free input, which is every
production input the demo emits, so the chain verifies under both
canonicalization profiles.

The x402 wire-level envelopes (PaymentRequirements, PaymentPayload,
EIP-3009 authorization) follow upstream x402 v1 unchanged.

## Known divergence (Phase 1)

- **`mimeType` on `PaymentRequirements`.** Upstream x402@1.2.0 makes
  `mimeType` mandatory; APS@2.6.0-alpha.3's bundled rail leaves it
  optional and does not default it. The demo enriches with
  `application/json` before validating against the upstream zod schema.
  Tracking as an APS wire-conformance ticket; not affecting payments,
  only schema strictness.

## Out of scope (Phase 2+)

- TEE-attested execution composition (Phala or similar) for the action
  layer.
- Multi-hop delegation chains. Single hop is enough to demonstrate the
  receipt-chain pattern; multi-hop adds cascade revocation and chain
  validation that this demo doesn't exercise.
- Real x402 ecosystem integration beyond the upstream zod schemas. The
  demo cross-validates wire shapes only; the facilitator is mocked.
- Conformance cosignatures from independent implementations.
- Production-grade key management. The demo uses pinned test keys.

## Honest limits

- The receipt chain proves *what was committed*, not *what was true*. A
  hostile agent that signs an `ActionReceipt` claiming `result.status =
  'success'` for an action that actually failed will produce a chain
  that the verifier accepts. Result-quality is upstream of receipts.
- The mock facilitator never rejects a payment, so the demo's
  `payment_hash` is a placeholder, not an on-chain transaction. Real
  x402 deployments delegate this to the Coinbase CDP facilitator or a
  self-hosted equivalent.
- `action_ref` is content-addressed but only over `(agentId, type,
  scopeRequired, createdAt)`. Two semantically distinct actions that
  collide on those four fields will collide on `action_ref`. The
  receipt's `payload_hash` is the tiebreaker.

## Layout

```
.
├── README.md
├── LICENSE                 # Apache-2.0
├── package.json            # APS@2.6.0-alpha.3, x402@1.2.0, tsx, typescript
├── tsconfig.json
├── src/
│   ├── demo.ts             # end-to-end composition runner
│   └── verifier.ts         # importable + CLI verifier
├── fixtures/
│   └── run.*.json          # regenerated on every demo run
├── examples/
│   └── run-trace.txt       # captured demo + verifier output
└── .github/workflows/
    └── ci.yml              # runs demo + verifier on every push
```
