import { useEffect, useState } from 'react'
import { useAccount } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { formatUnits } from 'viem'
import { QRCodeSVG } from 'qrcode.react'
import { getDepositMemo, getConfig } from '../api/bridge'
import InfoHint from './InfoHint'
import { runtimeConfig } from '../config/runtime'
import { validateBaseRecipient, validateDepositAmount } from '../lib/bridgeUi'

type RecipientMode = 'wallet' | 'custom'
type InstructionStep = 'closed' | 'warnings' | 'transport' | 'content'
type InstructionTransport = 'qr' | 'cli' | 'manual' | null

function formatJuno(zatoshi: string): string {
  try {
    return formatUnits(BigInt(zatoshi), 8)
  } catch {
    return zatoshi
  }
}

function formatQueryError(error: unknown): string {
  if (error instanceof Error && error.message.trim() !== '') {
    return error.message
  }
  return 'Unable to generate deposit instructions right now.'
}

// The deposit memo is 512 bytes but only the first 68 bytes contain data;
// bytes 68-511 are zero padding. Zcash/Juno nodes auto-pad short memos to
// 512 bytes, so we can send just the compact form (136 hex chars) instead
// of the full 1024 hex chars. This avoids copy-paste errors.
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
  const [recipientMode, setRecipientMode] = useState<RecipientMode>(address ? 'wallet' : 'custom')
  const [customRecipient, setCustomRecipient] = useState('')
  const [amount, setAmount] = useState('')
  const [instructionStep, setInstructionStep] = useState<InstructionStep>('closed')
  const [transport, setTransport] = useState<InstructionTransport>(null)

  useEffect(() => {
    if (!address) {
      setRecipientMode('custom')
      return
    }

    setRecipientMode((current) => (current === 'custom' ? current : 'wallet'))
  }, [address])

  const effectiveRecipient = recipientMode === 'wallet' ? address?.trim() ?? '' : customRecipient.trim()
  const recipientValue = recipientMode === 'wallet' ? address ?? '' : customRecipient
  const minDepositLabel = formatJuno('0')

  const { data: cfg } = useQuery({
    queryKey: ['bridge-config'],
    queryFn: getConfig,
  })

  const {
    data: memo,
    error: memoError,
    isFetching: isMemoFetching,
    refetch,
  } = useQuery({
    queryKey: ['deposit-memo', effectiveRecipient],
    queryFn: () => getDepositMemo(effectiveRecipient),
    enabled: false,
  })

  const compactMemo = memo ? compactMemoHex(memo.memoHex) : ''
  const recipientError = validateBaseRecipient(
    recipientMode === 'wallet' ? '' : customRecipient,
    recipientMode === 'wallet' ? address : undefined,
  )
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
  const formattedMinDeposit = cfg ? formatJuno(cfg.minDepositAmount) : minDepositLabel

  const closeInstructions = () => {
    setInstructionStep('closed')
    setTransport(null)
  }

  const handleGenerate = () => {
    if (!cfg || !effectiveRecipient || formError) {
      return
    }

    setTransport(null)
    setInstructionStep('warnings')
  }

  const handleAgree = async () => {
    if (!cfg || !effectiveRecipient || formError) {
      return
    }

    const result = await refetch()
    if (result.data) {
      setTransport(null)
      setInstructionStep('transport')
    }
  }

  const handleSelectTransport = (nextTransport: Exclude<InstructionTransport, null>) => {
    setTransport(nextTransport)
    setInstructionStep('content')
  }

  const handleUseConnectedWallet = () => {
    setCustomRecipient('')
    setRecipientMode('wallet')
  }

  const handleEditRecipient = () => {
    setCustomRecipient('')
    setRecipientMode('custom')
  }

  const renderTransportContent = () => {
    if (!memo || transport === null) {
      return null
    }

    if (transport === 'qr') {
      return (
        <>
          <div className="qr-container">
            <QRCodeSVG value={qrValue} size={180} level="M" includeMargin />
          </div>
          <p className="deposit-modal-copy">
            Scan with a Juno wallet. If the wallet does not preserve the memo automatically, use the manual details below.
          </p>
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
        </>
      )
    }

    if (transport === 'cli') {
      return (
        <>
          <p className="deposit-modal-copy">
            Replace <code style={{ color: 'var(--accent)' }}>YOUR_JUNO_ADDRESS</code> with your wallet address before running the command.
          </p>
          <div className="cli-block">
            <div className="cli-header">
              <span>junocash-cli</span>
              <CopyButton text={cliCommand} label="Copy command" />
            </div>
            <pre className="cli-code">{cliCommand}</pre>
          </div>
        </>
      )
    }

    return (
      <>
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
        {cliAmount !== '' ? (
          <div className="field">
            <label className="label">Amount</label>
            <div className="copy-field">
              <span style={{ flex: 1 }}>{cliAmount} JUNO</span>
              <CopyButton text={cliAmount} />
            </div>
          </div>
        ) : (
          <div className="warning-box">
            Enter the amount manually in your Juno wallet, but do not send less than {formattedMinDeposit} JUNO.
          </div>
        )}
      </>
    )
  }

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
          <label className="label" htmlFor="deposit-base-recipient">
            Base Recipient Address <InfoHint label="Any Base address works. Leave this blank to use the currently connected wallet." />
          </label>
          <input
            id="deposit-base-recipient"
            className={`mono recipient-input ${recipientMode === 'wallet' ? 'is-readonly' : ''}`}
            placeholder="0x..."
            readOnly={recipientMode === 'wallet'}
            value={recipientValue}
            onChange={(event) => setCustomRecipient(event.target.value)}
          />
          <div className="field-help">
            {recipientMode === 'wallet' && address
              ? 'Deposits will mint to the connected Base wallet unless you switch to a custom recipient.'
              : address
                ? 'Enter another Base recipient or use the connected wallet again.'
                : 'Connect a wallet to auto-fill this field, or enter a Base recipient manually.'}
          </div>
          <div className="field-actions">
            {recipientMode === 'wallet' && address ? (
              <button type="button" className="field-action-btn" onClick={handleEditRecipient}>
                Edit
              </button>
            ) : null}
            {recipientMode === 'custom' && address ? (
              <button type="button" className="field-action-btn" onClick={handleUseConnectedWallet}>
                Use connected wallet
              </button>
            ) : null}
          </div>
        </div>
        <div className="field">
          <label className="label" htmlFor="deposit-amount">
            Amount (JUNO) <span className="optional-pill">Optional</span>{' '}
            <InfoHint label="The amount only pre-fills the QR code and CLI instructions. The memo is what actually routes the deposit." />
          </label>
          <input
            id="deposit-amount"
            type="number"
            step="0.00000001"
            min="0"
            placeholder="Leave blank to fill this in later"
            value={amount}
            onChange={(event) => setAmount(event.target.value)}
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
        <button className="primary" onClick={handleGenerate} disabled={!cfg || !effectiveRecipient || !!formError}>
          Generate Deposit Instructions
        </button>
      </div>

      {instructionStep !== 'closed' && (
        <div className="modal-overlay" onClick={closeInstructions}>
          <div className="modal-content deposit-instructions-modal" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">
                {instructionStep === 'warnings'
                  ? 'Deposit Safety Check'
                  : instructionStep === 'transport'
                    ? 'Choose Instruction Format'
                    : 'Deposit Instructions'}
              </span>
              <button className="modal-close" onClick={closeInstructions} aria-label="Close deposit instructions">
                &times;
              </button>
            </div>
            <div className="modal-body deposit-modal-body">
              {instructionStep === 'warnings' && (
                <>
                  <p className="deposit-modal-copy">
                    Review these warnings before generating the deposit memo and send instructions.
                  </p>
                  <ol className="deposit-warning-list">
                    <li>I will not send less than {formattedMinDeposit} JUNO or my funds will be permenantly lost</li>
                    <li>I must include the memo exactly or my funds will be permenantly lost</li>
                    <li>Juno Intents is not responsible for losses from incorrect sending params</li>
                  </ol>
                  {memoError ? <div className="error-box">{formatQueryError(memoError)}</div> : null}
                  <div className="deposit-modal-actions">
                    <button type="button" className="ghost-btn" onClick={closeInstructions}>
                      Cancel
                    </button>
                    <button type="button" className="primary deposit-modal-primary" onClick={handleAgree} disabled={isMemoFetching}>
                      {isMemoFetching ? 'Generating...' : 'I agree'}
                    </button>
                  </div>
                </>
              )}

              {instructionStep === 'transport' && (
                <>
                  <p className="deposit-modal-copy">
                    Select how you want the deposit instructions displayed.
                  </p>
                  <div className="transport-grid">
                    <button
                      type="button"
                      className="transport-option"
                      aria-label="QR Code"
                      onClick={() => handleSelectTransport('qr')}
                    >
                      <span className="transport-option-title">QR Code</span>
                      <span className="transport-option-copy">Best for scanning directly from a Juno wallet.</span>
                    </button>
                    <button
                      type="button"
                      className="transport-option"
                      aria-label="Junocash CLI"
                      onClick={() => handleSelectTransport('cli')}
                    >
                      <span className="transport-option-title">Junocash CLI</span>
                      <span className="transport-option-copy">Copy a ready-to-edit CLI command.</span>
                    </button>
                    <button
                      type="button"
                      className="transport-option"
                      aria-label="Manual Send"
                      onClick={() => handleSelectTransport('manual')}
                    >
                      <span className="transport-option-title">Manual Send</span>
                      <span className="transport-option-copy">Copy the address and memo separately.</span>
                    </button>
                  </div>
                </>
              )}

              {instructionStep === 'content' && transport !== null && memo && (
                <>
                  {renderTransportContent()}
                  <div className="warning-box">
                    You MUST include the memo in your Juno transaction. Without it, your deposit cannot be processed and funds may be lost.
                  </div>
                  <div className="deposit-modal-actions">
                    <button type="button" className="ghost-btn" onClick={() => setInstructionStep('transport')}>
                      Back
                    </button>
                    <button type="button" className="primary deposit-modal-primary" onClick={closeInstructions}>
                      Done
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
