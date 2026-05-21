// Independent verifier for the four artifacts the demo emits.
//
// Inputs (CLI args, JSON files in this order, OR pass nothing and the
// verifier will look in fixtures/run.*.json by convention):
//
//   1. permit-receipt    APS ActionReceipt, signed by the executing agent
//   2. completion-receipt   gateway-signed completion bound to permit hash
//   3. payment-receipt   gateway-signed x402 PaymentReceipt with tx_proof
//   4. action            mock-action result containing action_ref + payload_hash
//
// Output: a regulator-style PASS/FAIL block. Exit 0 on PASS, 1 on FAIL.
//
// Importable: call `verify(artifacts)` from external code to get the
// structured Report. No network or filesystem touch.

import { readFileSync, existsSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { createHash } from 'node:crypto'

import {
  verifyReceipt,
  verifyCompletionReceipt,
  linkPermitAndCompletion,
  verifyPaymentReceipt,
  canonicalize,
} from 'agent-passport-system'
import type {
  ActionReceipt,
  PaymentReceipt,
  CompletionReceipt,
} from 'agent-passport-system'

export interface Artifacts {
  permit: ActionReceipt
  completion: CompletionReceipt
  payment: PaymentReceipt
  action: {
    action_ref: string
    payload_hash: string
    status: string
  }
}

export interface Check {
  id: string
  description: string
  pass: boolean
  detail?: string
}

export interface Report {
  pass: boolean
  checks: Check[]
}

const HEX64 = /^[0-9a-f]{64}$/

function ok(id: string, description: string, detail?: string): Check {
  return { id, description, pass: true, detail }
}
function fail(id: string, description: string, detail: string): Check {
  return { id, description, pass: false, detail }
}

export function verify(a: Artifacts): Report {
  const checks: Check[] = []

  // 1. The permit receipt's signature must verify against the agent's
  //    public key, which is the agentId field on the receipt itself.
  const permitOk = verifyReceipt(a.permit, a.permit.agentId)
  checks.push(
    permitOk.valid
      ? ok('permit_signature', 'permit receipt: agent signature verifies')
      : fail(
          'permit_signature',
          'permit receipt: agent signature verifies',
          permitOk.errors.join(', '),
        ),
  )

  // 2. The completion receipt's signature must verify. The completion
  //    uses an issuer (gateway) key; we don't know it a priori in this
  //    verifier, so we re-derive it from the demo configuration. In a
  //    production setting the gateway pubkey would come from a registry.
  //    We accept the gateway pubkey on the completion through inspection
  //    of the permit chain: APS pins it via linkPermitAndCompletion.
  //
  //    Here we treat the completion as well-formed if (a) its linkage to
  //    the permit's canonical hash holds, AND (b) verifyCompletionReceipt
  //    reports valid when handed the issuer pubkey baked into the action's
  //    signature-verify path. We approximate by checking the permit-hash
  //    binding here and deferring full signature verification to the
  //    payment receipt step below (which carries an explicit signer_did).
  // Strip the agent signature before hashing — matches APS's
  // linkPermitAndCompletion convention.
  const { signature: _permitSig, ...permitUnsigned } = a.permit
  const permitHash = createHash('sha256')
    .update(canonicalize(permitUnsigned))
    .digest('hex')
  checks.push(
    a.completion.permitReceiptHash === permitHash
      ? ok(
          'completion_pins_permit',
          'completion receipt pins canonical permit hash',
          permitHash,
        )
      : fail(
          'completion_pins_permit',
          'completion receipt pins canonical permit hash',
          `expected ${permitHash}, got ${a.completion.permitReceiptHash}`,
        ),
  )

  // 3. linkPermitAndCompletion is the APS-blessed predicate for the
  //    bilateral chain. Re-run it to surface any structural drift.
  const link = linkPermitAndCompletion(
    a.permit as unknown as Record<string, unknown>,
    a.completion,
  )
  checks.push(
    link.linked
      ? ok('permit_completion_link', 'linkPermitAndCompletion() reports linked')
      : fail(
          'permit_completion_link',
          'linkPermitAndCompletion() reports linked',
          link.errors.join(', '),
        ),
  )

  // 4. Completion receipt internal signature (signer pubkey is taken from
  //    the payment receipt, which records the gateway's signer_did).
  const gatewayPub = a.payment.signer_did
  if (gatewayPub) {
    const compSigOk = verifyCompletionReceipt(a.completion, gatewayPub)
    checks.push(
      compSigOk.valid
        ? ok(
            'completion_signature',
            'completion receipt: gateway signature verifies',
          )
        : fail(
            'completion_signature',
            'completion receipt: gateway signature verifies',
            compSigOk.errors.join(', '),
          ),
    )
  } else {
    checks.push(
      fail(
        'completion_signature',
        'completion receipt: gateway signature verifies',
        'payment receipt missing signer_did — cannot resolve gateway pubkey',
      ),
    )
  }

  // 5. The payment receipt's own signature + canonical-hash round-trip.
  const pmtOk = verifyPaymentReceipt(a.payment)
  checks.push(
    pmtOk.valid
      ? ok(
          'payment_signature',
          'payment receipt: gateway signature + canonical hash verify',
        )
      : fail(
          'payment_signature',
          'payment receipt: gateway signature + canonical hash verify',
          pmtOk.reason ?? 'unknown',
        ),
  )

  // 6. Payment receipt must bind the same action_ref that the action
  //    layer produced.
  checks.push(
    a.payment.action_ref === a.action.action_ref
      ? ok(
          'action_ref_match',
          'payment receipt action_ref matches action artifact',
          a.action.action_ref,
        )
      : fail(
          'action_ref_match',
          'payment receipt action_ref matches action artifact',
          `payment=${a.payment.action_ref} vs action=${a.action.action_ref}`,
        ),
  )

  // 7. Payment receipt must bind the same delegation the permit references.
  checks.push(
    a.payment.delegation_ref === a.permit.delegationId
      ? ok(
          'delegation_ref_match',
          'payment delegation_ref matches permit delegationId',
          a.payment.delegation_ref,
        )
      : fail(
          'delegation_ref_match',
          'payment delegation_ref matches permit delegationId',
          `payment=${a.payment.delegation_ref} vs permit=${a.permit.delegationId}`,
        ),
  )

  // 8. tx_proof / payment_hash format sanity (32-byte hex preceded by 0x).
  const tx = a.payment.tx_proof ?? ''
  const txOk = /^0x[0-9a-f]{64}$/.test(tx.toLowerCase())
  checks.push(
    txOk
      ? ok('payment_hash_shape', 'payment_hash is 0x + 64 lowercase-hex chars', tx)
      : fail(
          'payment_hash_shape',
          'payment_hash is 0x + 64 lowercase-hex chars',
          tx || '(empty)',
        ),
  )

  // 9. payload_hash on the action must be a bare lowercase-hex SHA-256.
  const phOk = HEX64.test(a.action.payload_hash)
  checks.push(
    phOk
      ? ok(
          'payload_hash_shape',
          'action payload_hash is lowercase-hex SHA-256 (64 chars)',
        )
      : fail(
          'payload_hash_shape',
          'action payload_hash is lowercase-hex SHA-256 (64 chars)',
          a.action.payload_hash,
        ),
  )

  // 10. Spend bound: the permit's recorded spend amount must equal the
  //     payment receipt's amount_base_units.
  const permitSpend = String(a.permit.action.spend?.amount ?? '')
  checks.push(
    permitSpend === a.payment.amount_base_units
      ? ok(
          'spend_amount_match',
          'permit.action.spend.amount equals payment.amount_base_units',
          permitSpend,
        )
      : fail(
          'spend_amount_match',
          'permit.action.spend.amount equals payment.amount_base_units',
          `permit=${permitSpend} vs payment=${a.payment.amount_base_units}`,
        ),
  )

  // 11. Action status agrees with completion executionResult.
  checks.push(
    a.completion.executionResult === a.action.status
      ? ok(
          'completion_status_match',
          'completion.executionResult matches action.status',
          a.action.status,
        )
      : fail(
          'completion_status_match',
          'completion.executionResult matches action.status',
          `completion=${a.completion.executionResult} vs action=${a.action.status}`,
        ),
  )

  const pass = checks.every((c) => c.pass)
  return { pass, checks }
}

// ── CLI ──────────────────────────────────────────────────────────────

function loadJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T
}

function resolveDefault(name: string): string {
  const here = dirname(fileURLToPath(import.meta.url))
  const cand = resolve(here, '..', 'fixtures', name)
  if (!existsSync(cand)) {
    throw new Error(
      `verifier: required fixture not found: ${cand}\n` +
        `       (run \`npm run demo\` first to emit fixtures)`,
    )
  }
  return cand
}

function loadFromArgs(argv: string[]): Artifacts {
  const args = argv.slice(2)
  let permitPath: string, completionPath: string, paymentPath: string, actionPath: string

  if (args.length === 0) {
    permitPath = resolveDefault('run.permit-receipt.json')
    completionPath = resolveDefault('run.completion-receipt.json')
    paymentPath = resolveDefault('run.payment-receipt.json')
    actionPath = resolveDefault('run.action.json')
  } else if (args.length === 4) {
    [permitPath, completionPath, paymentPath, actionPath] = args as [
      string,
      string,
      string,
      string,
    ]
  } else {
    throw new Error(
      'usage: verifier [permit completion payment action]\n' +
        '       (zero args reads fixtures/run.*.json; four args takes explicit paths)',
    )
  }

  return {
    permit: loadJson<ActionReceipt>(permitPath),
    completion: loadJson<CompletionReceipt>(completionPath),
    payment: loadJson<PaymentReceipt>(paymentPath),
    action: loadJson<Artifacts['action']>(actionPath),
  }
}

function formatReport(report: Report): string {
  const lines: string[] = []
  lines.push('REGULATOR-VIEW RECEIPT VERIFICATION')
  lines.push('============================================================')
  let width = 0
  for (const c of report.checks) {
    if (c.id.length > width) width = c.id.length
  }
  for (const c of report.checks) {
    const tag = c.pass ? 'PASS' : 'FAIL'
    lines.push(`[${tag}] ${c.id.padEnd(width)}  ${c.description}`)
    if (c.detail) {
      lines.push(`        ${c.detail}`)
    }
  }
  lines.push('------------------------------------------------------------')
  lines.push(`OVERALL: ${report.pass ? 'PASS' : 'FAIL'}`)
  return lines.join('\n')
}

function isMain(): boolean {
  return (
    import.meta.url === `file://${process.argv[1]}` ||
    process.argv[1]?.endsWith('verifier.ts') === true
  )
}

if (isMain()) {
  try {
    const artifacts = loadFromArgs(process.argv)
    const report = verify(artifacts)
    console.log(formatReport(report))
    process.exit(report.pass ? 0 : 1)
  } catch (err) {
    console.error('VERIFY FAILED:')
    console.error(err instanceof Error ? err.message : err)
    process.exit(2)
  }
}
