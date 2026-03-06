import { useState } from 'react'
import { useAccount } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { formatUnits } from 'viem'
import { getDepositMemo, getConfig } from '../api/bridge'
import StatusTracker from './StatusTracker'

const DEPOSIT_STEPS = ['pending', 'seen', 'confirmed', 'proof_requested', 'proof_ready', 'submitted', 'finalized']

function formatJuno(zatoshi: string): string {
  try {
    return formatUnits(BigInt(zatoshi), 8)
  } catch {
    return zatoshi
  }
}

// The deposit memo is 512 bytes but only the first 68 bytes contain data;
// bytes 68-511 are zero padding. Zcash/Juno nodes auto-pad short memos to
// 512 bytes, so we can send just the compact form (136 hex chars) instead
// of the full 1024 hex chars.  This avoids copy-paste errors.
function compactMemoHex(hex: string): string {
  return hex.slice(0, 136)
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button className="copy-btn" onClick={handleCopy}>
      {copied ? 'Copied!' : (label ?? 'Copy')}
    </button>
  )
}

export default function DepositFlow() {
  const { address } = useAccount()
  const [recipient, setRecipient] = useState('')
  const [amount, setAmount] = useState('')
  const [generated, setGenerated] = useState(false)

  const effectiveRecipient = recipient || (address ?? '')

  const { data: cfg } = useQuery({
    queryKey: ['bridge-config'],
    queryFn: getConfig,
  })

  const { data: memo, isLoading, refetch } = useQuery({
    queryKey: ['deposit-memo', effectiveRecipient],
    queryFn: () => getDepositMemo(effectiveRecipient),
    enabled: false,
  })

  const handleGenerate = () => {
    if (!effectiveRecipient) return
    refetch()
    setGenerated(true)
  }

  const compactMemo = memo ? compactMemoHex(memo.memoHex) : ''
  const cliAmount = amount || '10.0'

  const cliCommand = memo
    ? `FROM=$(junocash-cli -testnet listaddresses | jq -r '[.[].unified[]?.address // empty] | first')
TO="${memo.oWalletUA}"
AMOUNT=${cliAmount}
MEMO="${compactMemo}"

junocash-cli -testnet z_sendmany "$FROM" \
  '[{"address":"'"$TO"'","amount":'"$AMOUNT"',"memo":"'"$MEMO"'"}]'`
    : ''

  return (
    <div>
      <div className="network-card">
        <div className="network-endpoint">
          <div className="network-icon">J</div>
          <div>
            <div className="network-name">Juno</div>
            <div className="network-label">Source</div>
          </div>
        </div>
        <div className="network-arrow">&rarr;</div>
        <div className="network-endpoint">
          <div className="network-icon">B</div>
          <div>
            <div className="network-name">Base</div>
            <div className="network-label">Destination</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="field">
          <label className="label">Base Recipient Address</label>
          <input
            className="mono"
            placeholder={address ?? '0x...'}
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
          />
        </div>
        <div className="field">
          <label className="label">Amount (JUNO)</label>
          <input
            type="number"
            step="0.00000001"
            min="0"
            placeholder="10.0"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
        </div>
        {cfg && cfg.feeBps > 0 && (
          <div className="fee-line" style={{ marginTop: 0 }}>
            <span>Bridge fee</span>
            <span>{(cfg.feeBps / 100).toFixed(2)}%</span>
          </div>
        )}
        {cfg && cfg.minDepositAmount !== '0' && (
          <div className="fee-line" style={{ marginTop: 0 }}>
            <span>Min deposit</span>
            <span>{formatJuno(cfg.minDepositAmount)} JUNO</span>
          </div>
        )}
        <button className="primary" onClick={handleGenerate} disabled={!effectiveRecipient || isLoading}>
          {isLoading ? 'Generating...' : 'Generate Deposit Instructions'}
        </button>
      </div>

      {generated && memo && (
        <>
          <div className="card">
            <h3>Send JUNO via CLI</h3>
            <p style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 12 }}>
              Copy and paste this into your terminal. The <code style={{ color: 'var(--text)' }}>FROM</code> address is auto-detected from your wallet.
            </p>
            <div className="cli-block">
              <div className="cli-header">
                <span>junocash-cli</span>
                <CopyButton text={cliCommand} label="Copy command" />
              </div>
              <pre className="cli-code">{cliCommand}</pre>
            </div>
          </div>

          <div className="card">
            <h3>Manual Details</h3>
            <div className="field">
              <label className="label">Destination Address</label>
              <div className="copy-field">
                <span style={{ flex: 1 }}>{memo.oWalletUA}</span>
                <CopyButton text={memo.oWalletUA} />
              </div>
            </div>
            <div className="field">
              <label className="label">Memo (required)</label>
              <div className="copy-field">
                <span style={{ flex: 1 }}>{compactMemo}</span>
                <CopyButton text={compactMemo} />
              </div>
            </div>
            <div className="warning-box">
              You MUST include the memo in your Juno transaction. Without it, your deposit cannot be processed and funds may be lost.
            </div>
          </div>

          <div className="card">
            <h3>Track Progress</h3>
            <StatusTracker steps={DEPOSIT_STEPS} current="pending" />
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 8 }}>
              Waiting for Juno transaction...
            </div>
          </div>
        </>
      )}
    </div>
  )
}
