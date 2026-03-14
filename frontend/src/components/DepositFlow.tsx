import { useState } from 'react'
import { useAccount } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { formatUnits } from 'viem'
import { QRCodeSVG } from 'qrcode.react'
import { getDepositMemo, getConfig } from '../api/bridge'
import InfoHint from './InfoHint'
import { runtimeConfig } from '../config/runtime'
import { validateBaseRecipient, validateDepositAmount } from '../lib/bridgeUi'

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
    if (!effectiveRecipient || formError) return
    refetch()
    setGenerated(true)
  }

  const compactMemo = memo ? compactMemoHex(memo.memoHex) : ''
  const recipientError = validateBaseRecipient(recipient, address)
  const amountError = validateDepositAmount(amount, cfg?.minDepositAmount)
  const formError = recipientError || amountError
  const cliAmount = amount.trim()
  const cliModeArg = runtimeConfig.junoCliModeFlag.trim()
  const qrValue = memo
    ? `${memo.oWalletUA}${cliAmount ? `?amount=${cliAmount}&memo=${compactMemo}` : `?memo=${compactMemo}`}`
    : ''

  const cliCommand = memo
    ? `FROM="YOUR_JUNO_ADDRESS"
TO="${memo.oWalletUA}"
AMOUNT=${cliAmount || '"YOUR_JUNO_AMOUNT"'}
MEMO="${compactMemo}"

junocash-cli ${cliModeArg ? `${cliModeArg} ` : ''}z_sendmany "$FROM" \
  '[{"address":"'"$TO"'","amount":'"$AMOUNT"',"memo":"'"$MEMO"'"}]'`
    : ''

  return (
    <div>
      <div className="network-card">
        <div className="network-endpoint">
          <div className="network-icon">
            <img className="network-logo" src={runtimeConfig.junoLogoUrl} alt="Juno" />
          </div>
          <div>
            <div className="network-name">Juno</div>
            <div className="network-label">Source chain</div>
          </div>
        </div>
        <div className="network-arrow">&rarr;</div>
        <div className="network-endpoint">
          <div className="network-icon">
            <img className="network-logo" src={runtimeConfig.baseLogoUrl} alt="Base" />
          </div>
          <div>
            <div className="network-name">Base</div>
            <div className="network-label">Destination chain</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="field">
          <label className="label">
            Base Recipient Address <InfoHint label="Any Base address works. Leave this blank to use the currently connected wallet." />
          </label>
          <input
            className="mono"
            placeholder={address ?? '0x...'}
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
          />
          <div className="field-help">
            Leave blank to deposit to the connected Base wallet.
          </div>
        </div>
        <div className="field">
          <label className="label">
            Amount (JUNO) <span className="optional-pill">Optional</span>{' '}
            <InfoHint label="The amount only pre-fills the QR code and CLI instructions. The memo is what actually routes the deposit." />
          </label>
          <input
            type="number"
            step="0.00000001"
            min="0"
            placeholder="Leave blank to fill this in later"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
        </div>
        {formError && <div className="error-box">{formError}</div>}
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
        {cfg && cfg.minDepositAmount !== '0' && (
          <div className="warning-box" style={{ marginTop: 8, marginBottom: 0 }}>
            Deposits below {formatJuno(cfg.minDepositAmount)} JUNO are rejected and will not mint on Base.
          </div>
        )}
        <button className="primary" onClick={handleGenerate} disabled={!effectiveRecipient || isLoading || !!formError}>
          {isLoading ? 'Generating...' : 'Generate Deposit Instructions'}
        </button>
      </div>

      {generated && memo && (
        <>
          <div className="card">
            <h3>Send JUNO via CLI</h3>
            <div style={{ display: 'flex', justifyContent: 'center', margin: '16px 0' }}>
              <QRCodeSVG
                value={qrValue}
                size={180}
                level="M"
                includeMargin
              />
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 12 }}>
              Scan the QR code with a Juno wallet, or replace <code style={{ color: 'var(--accent)' }}>YOUR_JUNO_ADDRESS</code> with your shielded address and paste into your terminal.
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

        </>
      )}
    </div>
  )
}
