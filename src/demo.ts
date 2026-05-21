// Phase 1 end-to-end composition demo.
//
//   APS delegation (scoped, spend-limited, signed)
//     → x402 settlement (payment_hash)
//        → mock AgentCore-style action executes
//           → APS gateway emits permit receipt (action_ref bound)
//              → APS gateway emits completion receipt
//                 (links permit_receipt_hash + execution result)
//                 → four artifacts written to fixtures/
//
// Run:    npm run demo
// Emit:   npm run regen-fixtures   (writes fixtures/run.*.json)

import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash, randomBytes } from 'node:crypto'

import {
  // identity + crypto
  generateKeyPair,
  publicKeyFromPrivate,
  // delegation primitives
  createDelegation,
  verifyDelegation,
  createReceipt,
  verifyReceipt,
  // completion receipt (bilateral half #2)
  createCompletionReceipt,
  linkPermitAndCompletion,
  // canonical hashing
  canonicalize,
  canonicalizeJCS,
  // x402 rail + payment receipt
  createX402Rail,
  USDC_BASE_SEPOLIA,
  emitReceipt,
  preAuthorize,
  verifyPaymentReceipt,
  X402_VERSION,
} from 'agent-passport-system'
import type {
  DelegationView,
  PaymentReceipt,
  X402PaymentPayload,
  X402SettleResponse,
  X402VerifyResponse,
} from 'agent-passport-system'
import type { ActionReceipt, Delegation } from 'agent-passport-system'
import type { CompletionReceipt } from 'agent-passport-system'

// Cross-validate the x402 wire shape against the upstream zod schemas.
import {
  PaymentRequirementsSchema,
  PaymentPayloadSchema,
} from 'x402/types'

// ── Demo configuration ───────────────────────────────────────────────

const PRINCIPAL_PRIV = 'a1'.repeat(32)
const AGENT_PRIV = 'b2'.repeat(32)
const ISSUER_PRIV = 'c3'.repeat(32)

const PRINCIPAL_PUB = publicKeyFromPrivate(PRINCIPAL_PRIV)
const AGENT_PUB = publicKeyFromPrivate(AGENT_PRIV)
const ISSUER_PUB = publicKeyFromPrivate(ISSUER_PRIV)

// Wallets are arbitrary 20-byte addresses for the demo. base-sepolia.
const PAYER_WALLET = '0x' + 'a'.repeat(40)
const PAYEE_WALLET = '0x' + 'b'.repeat(40)
const FACILITATOR_TX_HASH = '0x' + 'f'.repeat(64)

// Single-shot purchase: 1.50 USDC (six decimals → 1_500_000 base units).
const AMOUNT_BASE_UNITS = '1500000'
const SPEND_LIMIT_BASE_UNITS = '5000000'

// ── Step 1: Principal → Agent delegation ─────────────────────────────

function step1_delegation(): Delegation {
  // The principal mints a scoped, spend-limited, signed delegation that
  // authorizes the agent to act inside `commerce.purchase` up to the
  // configured budget. This is the APS half of the composition: the
  // ed25519 signature commits the principal to the scope + spend limit.
  const delegation = createDelegation({
    delegatedBy: PRINCIPAL_PUB,
    delegatedTo: AGENT_PUB,
    scope: ['commerce.purchase'],
    // APS spendLimit is a number; the rail tracks base units as string.
    // We keep the rail's base-unit string as the source of truth and
    // mirror it into the delegation's numeric spendLimit.
    spendLimit: Number(SPEND_LIMIT_BASE_UNITS),
    spendLimitUnit: 'currency',
    expiresInHours: 24,
    privateKey: PRINCIPAL_PRIV,
  })

  const status = verifyDelegation(delegation)
  if (!status.valid) {
    throw new Error(`delegation invalid: ${status.errors.join(', ')}`)
  }

  return delegation
}

// ── Step 2: x402 settlement on a mock facilitator ────────────────────

type SubmitOutcome = {
  invoiceId: string
  txHash: string
  payer: string
  amountBaseUnits: string
  paymentRequirements: unknown
  paymentPayload: X402PaymentPayload
}

async function step2_settle(delegation: Delegation): Promise<SubmitOutcome> {
  // Mock facilitator: always verifies, always settles. In production this
  // would be the Coinbase CDP facilitator or self-hosted alternative.
  // The rail object owns the wire-level x402 protocol; APS does not
  // intercept the payment — it observes the outcome and binds it into
  // the permit receipt below.
  const verifyFacilitator =
    async (): Promise<X402VerifyResponse> => ({
      isValid: true,
      payer: PAYER_WALLET,
    })

  const settleFacilitator =
    async (): Promise<X402SettleResponse> => ({
      success: true,
      payer: PAYER_WALLET,
      transaction: FACILITATOR_TX_HASH,
      network: 'base-sepolia',
    })

  const rail = createX402Rail({
    payTo: PAYEE_WALLET,
    asset: USDC_BASE_SEPOLIA,
    network: 'base-sepolia',
    resource: 'https://example.invalid/api/premium-feed',
    description: 'Demo composition — premium feed access',
    facilitatorVerify: verifyFacilitator,
    facilitatorSettle: settleFacilitator,
  })

  const invoice = await rail.createInvoice({
    amount_base_units: AMOUNT_BASE_UNITS,
  })

  // Governance gate: APS preAuthorize checks the delegation against the
  // pending invoice before any facilitator call is made.
  const delegationView: DelegationView = {
    receipt_id: delegation.delegationId,
    scope: delegation.scope,
    spend_limit_base_units: SPEND_LIMIT_BASE_UNITS,
    wallet_id: PAYER_WALLET,
    currency: 'USDC',
  }
  const preAuth = preAuthorize(
    {
      delegation: delegationView,
      required_scope: 'commerce.purchase',
      amount_base_units: AMOUNT_BASE_UNITS,
      currency: 'USDC',
    },
    rail,
  )
  if (!preAuth.ok) {
    throw new Error(
      `preAuthorize denied: ${preAuth.denial_reason} (${preAuth.reason_detail ?? 'no detail'})`,
    )
  }

  // EIP-3009 authorization (would be signed by the payer wallet in
  // production; for the demo we pass through fixed bytes — the facilitator
  // is mocked and does not actually validate the signature).
  const payload: X402PaymentPayload = {
    x402Version: X402_VERSION,
    scheme: 'exact',
    network: 'base-sepolia',
    payload: {
      signature: '0x' + 'd'.repeat(130),
      authorization: {
        from: PAYER_WALLET,
        to: PAYEE_WALLET,
        value: AMOUNT_BASE_UNITS,
        validAfter: '0',
        validBefore: '1893456000',
        nonce: '0x' + '0'.repeat(64),
      },
    },
  }

  // Wire-shape cross-check against upstream x402 schemas. If APS's rail
  // ever diverges from the upstream protocol on the request/response
  // envelopes, this will throw at the boundary.
  //
  // KNOWN-DIVERGENCE (TODO upstream): x402@1.2.0 made `mimeType` mandatory
  // on PaymentRequirements; APS's rail (2.6.0-alpha.3) leaves it optional
  // and does not default it. The demo enriches with a JSON default before
  // schema-parsing so the round-trip succeeds. File this against APS as a
  // wire-conformance ticket once we move beyond Phase 1.
  const requirements = rail.getRequirements(invoice.invoice_id)
  if (!requirements) {
    throw new Error('rail.getRequirements returned undefined')
  }
  const enrichedRequirements = {
    ...requirements,
    mimeType: requirements.mimeType ?? 'application/json',
  }
  PaymentRequirementsSchema.parse(enrichedRequirements)
  PaymentPayloadSchema.parse(payload)

  const outcome = await rail.submitPayment(invoice.invoice_id, payload)
  if (!outcome.verified || !outcome.settled || !outcome.transaction) {
    throw new Error(
      `submitPayment failed: verified=${outcome.verified} settled=${outcome.settled} ` +
        `invalidReason=${outcome.invalidReason ?? '-'} ` +
        `settleErrorReason=${outcome.settleErrorReason ?? '-'}`,
    )
  }

  return {
    invoiceId: invoice.invoice_id,
    txHash: outcome.transaction,
    payer: outcome.payer ?? PAYER_WALLET,
    amountBaseUnits: invoice.amount_base_units,
    paymentRequirements: requirements,
    paymentPayload: payload,
  }
}

// ── Step 3: Mock AgentCore-style action ──────────────────────────────

type ActionResult = {
  action_id: string
  action_ref: string
  action_type: string
  action_target: string
  payload_hash: string
  status: 'success' | 'failure'
  output_summary: string
  executed_at: string
  duration_ms: number
}

function step3_action(
  agentId: string,
  settlement: SubmitOutcome,
): ActionResult {
  // The "AgentCore-style action" is intentionally a small typed shape:
  // an action id, a content-addressed action_ref, and a hashed output.
  // No vendor-specific runtime is named; the composition pattern is
  // identical whether the backend is Bedrock, a local LLM, or a Lambda.
  const startedAt = Date.now()
  const action_type = 'http_get'
  const action_target = 'https://example.invalid/api/premium-feed'
  const scope_required = 'commerce.purchase'
  const created_at = new Date(startedAt).toISOString()

  // Use the APS-canonical action_ref: lowercase-hex SHA-256 over
  // (agentId, action.type, action.scopeRequired, normalized timestamp).
  const action_ref = canonicalActionRef({
    agentId,
    action: { type: action_type, scopeRequired: scope_required },
    createdAt: created_at,
  })

  const responseBody = JSON.stringify({
    feed: 'premium',
    items: 3,
    settlement_proof: settlement.txHash,
  })
  const payload_hash = lowercaseHexSha256(responseBody)

  return {
    action_id: `act-${randomBytes(6).toString('hex')}`,
    action_ref,
    action_type,
    action_target,
    payload_hash,
    status: 'success',
    output_summary: 'fetched 3 items from premium feed',
    executed_at: created_at,
    duration_ms: 12,
  }
}

// ── Step 4: APS permit receipt (action_ref + delegation bound) ───────

function step4_permitReceipt(
  delegation: Delegation,
  settlement: SubmitOutcome,
  action: ActionResult,
): { permit: ActionReceipt; paymentReceipt: PaymentReceipt } {
  // The permit receipt is the APS ActionReceipt: a record signed by the
  // executing agent that says "I executed THIS action, under THIS
  // delegation, spending THIS much, and here is the result".
  const permit = createReceipt({
    agentId: AGENT_PUB,
    delegationId: delegation.delegationId,
    delegation,
    action: {
      type: action.action_type,
      target: action.action_target,
      method: 'GET',
      scopeUsed: 'commerce.purchase',
      spend: {
        amount: Number(settlement.amountBaseUnits),
        currency: 'USDC',
      },
    },
    result: {
      status: action.status,
      summary: action.output_summary,
    },
    delegationChain: [delegation.delegationId],
    privateKey: AGENT_PRIV,
  })

  const ok = verifyReceipt(permit, AGENT_PUB)
  if (!ok.valid) {
    throw new Error(`permit receipt invalid: ${ok.errors.join(', ')}`)
  }

  // The signed x402 PaymentReceipt: gateway-issued, binds delegation_ref +
  // action_ref + tx hash. This is the artifact a regulator would chase
  // when reconciling the on-chain transaction against the agent identity.
  const paymentReceipt = emitReceipt(
    {
      delegation_ref: delegation.delegationId,
      action_ref: action.action_ref,
      rail_name: 'x402-base-sepolia-USDC',
      amount_base_units: settlement.amountBaseUnits,
      currency: 'USDC',
      tx_proof: settlement.txHash,
      invoice_id: settlement.invoiceId,
    },
    ISSUER_PRIV,
  )

  const pmtOk = verifyPaymentReceipt(paymentReceipt)
  if (!pmtOk.valid) {
    throw new Error(`payment receipt invalid: ${pmtOk.reason ?? '?'}`)
  }

  return { permit, paymentReceipt }
}

// ── Step 5: completion receipt (links permit hash + result) ──────────

function step5_completionReceipt(
  permit: ActionReceipt,
  action: ActionResult,
): CompletionReceipt {
  // The completion receipt closes the bilateral pair. It commits the
  // gateway's view of the execution outcome and pins itself to the
  // permit via permitReceiptHash = SHA-256(canonicalize(permit \ signature)).
  // This matches APS's linkPermitAndCompletion(): the signature field is
  // stripped before hashing so re-signing the permit (e.g. rotation)
  // would produce a different chain.
  const permitHash = unsignedPermitHash(permit)
  return createCompletionReceipt({
    permitReceiptHash: permitHash,
    executionResult: action.status,
    resultSummary: action.output_summary,
    resultHash: action.payload_hash,
    executedAt: action.executed_at,
    durationMs: action.duration_ms,
    privateKey: ISSUER_PRIV,
  })
}

// ── Step 6: bind it all and write the artifacts ──────────────────────

function step6_write(
  delegation: Delegation,
  settlement: SubmitOutcome,
  action: ActionResult,
  permit: ActionReceipt,
  paymentReceipt: PaymentReceipt,
  completion: CompletionReceipt,
): string[] {
  const link = linkPermitAndCompletion(
    permit as unknown as Record<string, unknown>,
    completion,
  )
  if (!link.linked) {
    throw new Error(
      `permit↔completion link broken: ${link.errors.join(', ')}`,
    )
  }

  const here = dirname(fileURLToPath(import.meta.url))
  const fixturesDir = resolve(here, '..', 'fixtures')
  mkdirSync(fixturesDir, { recursive: true })

  const writes: Array<[string, unknown]> = [
    ['run.delegation.json', delegation],
    ['run.action.json', action],
    ['run.permit-receipt.json', permit],
    ['run.payment-receipt.json', paymentReceipt],
    ['run.completion-receipt.json', completion],
    [
      'run.summary.json',
      {
        protocol_substrate: {
          // action_ref uses strict RFC 8785 JCS via APS canonical-jcs.ts —
          // matches rfc8785@0.1.4 + lowercase-hex SHA-256, the substrate
          // used across the x402 ecosystem (giskard09's argentum-core,
          // andysalvo's verifier, AgentGraph CTEF byte-match).
          //
          // The permit↔completion link binding still rides APS's legacy
          // canonical-JSON (sorted keys, null-stripped) because that is
          // what linkPermitAndCompletion expects internally; the two
          // streams agree on every null-free input, which is every
          // production input.
          action_ref_canonicalization: 'strict RFC 8785 JCS (via APS canonical-jcs.ts)',
          permit_link_canonicalization: 'APS canonical-JSON (sorted-keys, null-stripped)',
          hash: 'SHA-256, lowercase hex',
          aps_sdk_version: '2.6.0-alpha.3',
          x402_sdk_version: '1.2.0',
          x402_wire_version: X402_VERSION,
        },
        identities: {
          principal_pubkey: PRINCIPAL_PUB,
          agent_pubkey: AGENT_PUB,
          gateway_issuer_pubkey: ISSUER_PUB,
        },
        artifacts: {
          payment_hash: settlement.txHash,
          action_ref: action.action_ref,
          permit_receipt_hash: link.permitHash,
          completion_id: completion.completionId,
        },
        composition_proven: [
          'delegation signed by principal',
          'preAuthorize gated spend before facilitator call',
          'x402 wire shapes parsed against upstream zod schemas',
          'permit receipt signed by agent, references delegationId + spend',
          'payment receipt signed by gateway, binds (delegation, action_ref, tx)',
          'completion receipt signed by gateway, pins permit_receipt_hash',
          'linkPermitAndCompletion confirmed permit↔completion linkage',
        ],
      },
    ],
  ]

  const paths: string[] = []
  for (const [name, body] of writes) {
    const file = resolve(fixturesDir, name)
    writeFileSync(file, canonicalize(body) + '\n', 'utf8')
    paths.push(file)
  }
  return paths
}

// ── Small helpers ────────────────────────────────────────────────────

function lowercaseHexSha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

function unsignedPermitHash(permit: ActionReceipt): string {
  // Strip the agent signature, then SHA-256(canonicalize(rest)). Matches
  // the substrate used inside APS's linkPermitAndCompletion.
  const { signature: _sig, ...unsigned } = permit
  return lowercaseHexSha256(canonicalize(unsigned))
}

function canonicalActionRef(intent: {
  agentId: string
  action: { type: string; scopeRequired: string }
  createdAt: string
}): string {
  // Strict RFC 8785 JCS via APS canonicalize-jcs.ts. Matches the
  // rfc8785@0.1.4 + lowercase-hex substrate used across the x402
  // ecosystem (giskard09's argentum-core, andysalvo's verifier,
  // AgentGraph CTEF byte-match). Mirrors the wire layout of the SDK's
  // computeActionRef (post-2.6.0-alpha.4 I-D §4.1 fix) without taking
  // a hard dependency on its ActionIntent shape.
  const material = {
    agentId: intent.agentId,
    type: intent.action.type,
    scopeRequired: intent.action.scopeRequired,
    createdAt: intent.createdAt,
  }
  return lowercaseHexSha256(canonicalizeJCS(material))
}

// ── Main ─────────────────────────────────────────────────────────────

async function main() {
  const log = (msg: string) => console.log(msg)

  log('aps-x402-composition: Phase 1 demo')
  log('================================================')
  log(`APS SDK:    agent-passport-system @ 2.6.0-alpha.3`)
  log(`x402 SDK:   x402 @ 1.2.0 (wire-shape cross-check only)`)
  log(`Substrate:  action_ref = strict RFC 8785 JCS + SHA-256 (lowercase hex)`)
  log('')

  log('[1/6] minting principal → agent delegation …')
  const delegation = step1_delegation()
  log(`      delegationId  = ${delegation.delegationId}`)
  log(`      scope         = ${delegation.scope.join(', ')}`)
  log(`      spendLimit    = ${delegation.spendLimit} base units (USDC, 6dp)`)
  log('')

  log('[2/6] driving x402 settlement (mock facilitator) …')
  const settlement = await step2_settle(delegation)
  log(`      invoiceId     = ${settlement.invoiceId}`)
  log(`      payment_hash  = ${settlement.txHash}`)
  log(`      amount        = ${settlement.amountBaseUnits} base units`)
  log('')

  log('[3/6] executing mock AgentCore-style action …')
  const action = step3_action(AGENT_PUB, settlement)
  log(`      action_id     = ${action.action_id}`)
  log(`      action_ref    = ${action.action_ref}`)
  log(`      payload_hash  = ${action.payload_hash}`)
  log('')

  log('[4/6] emitting APS permit receipt + x402 payment receipt …')
  const { permit, paymentReceipt } = step4_permitReceipt(
    delegation,
    settlement,
    action,
  )
  log(`      permit.receiptId = ${permit.receiptId}`)
  log(`      paymentReceipt.tx_proof = ${paymentReceipt.tx_proof}`)
  log('')

  log('[5/6] emitting completion receipt (links permit hash) …')
  const completion = step5_completionReceipt(permit, action)
  log(`      completionId        = ${completion.completionId}`)
  log(`      permitReceiptHash   = ${completion.permitReceiptHash}`)
  log('')

  log('[6/6] writing artifacts to fixtures/ …')
  const paths = step6_write(
    delegation,
    settlement,
    action,
    permit,
    paymentReceipt,
    completion,
  )
  for (const p of paths) {
    log(`      ${p.replace(process.cwd() + '/', '')}`)
  }
  log('')
  log('DEMO OK — receipt chain end-to-end verifiable.')
  log('Next:  npm run verify')
}

main().catch((err) => {
  console.error('\nDEMO FAILED:')
  if (err && typeof err === 'object' && 'message' in err) {
    console.error(String((err as { message?: unknown }).message))
  }
  if (err && typeof err === 'object' && 'issues' in err) {
    // zod-style aggregate error
    try {
      console.error(JSON.stringify((err as { issues: unknown }).issues, null, 2))
    } catch {
      /* ignore */
    }
  }
  if (err instanceof Error && err.stack) {
    console.error(err.stack)
  }
  process.exit(1)
})
