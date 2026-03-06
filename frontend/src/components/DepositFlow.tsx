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

export default function DepositFlow() {
  const { address } = useAccount()
  const [recipient, setRecipient] = useState('')
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
        {cfg && cfg.minDepositAmount !== '0' && (
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
            Min deposit: {formatJuno(cfg.minDepositAmount)} JUNO
          </div>
        )}
        {cfg && cfg.feeBps > 0 && (
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
            Bridge fee: {(cfg.feeBps / 100).toFixed(2)}%
          </div>
        )}
        <button className="primary" onClick={handleGenerate} disabled={!effectiveRecipient || isLoading}>
          {isLoading ? 'Generating...' : 'Generate Deposit Address'}
        </button>
      </div>

      {generated && memo && (
        <div className="card">
          <h3>Send JUNO to this address</h3>
          <div className="field">
            <label className="label">oWallet Unified Address</label>
            <div className="copy-field">
              <span style={{ flex: 1 }}>{memo.oWalletUA}</span>
              <button className="copy-btn" onClick={() => navigator.clipboard.writeText(memo.oWalletUA)}>Copy</button>
            </div>
          </div>
          <div className="field">
            <label className="label">Memo (CRITICAL)</label>
            <div className="copy-field">
              <span style={{ flex: 1 }}>{memo.memoHex}</span>
              <button className="copy-btn" onClick={() => navigator.clipboard.writeText(memo.memoHex)}>Copy</button>
            </div>
          </div>
          <div className="warning-box">
            You MUST include the memo above in your Juno transaction. Without it, your deposit cannot be processed and funds may be lost.
          </div>

          <h3 style={{ marginTop: 16 }}>Track Status</h3>
          <StatusTracker steps={DEPOSIT_STEPS} current="pending" />
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 8 }}>
            Waiting for Juno transaction...
          </div>
        </div>
      )}
    </div>
  )
}
