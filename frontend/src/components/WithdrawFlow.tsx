import { useState, useEffect } from 'react'
import { useAccount, useReadContract, useWriteContract, useWaitForTransactionReceipt } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { parseUnits, formatUnits, maxUint256 } from 'viem'
import { getConfig, decodeRecipient } from '../api/bridge'
import { WJUNO_ABI, BRIDGE_ABI } from '../config/contracts'
import InfoHint from './InfoHint'
import { runtimeConfig } from '../config/runtime'
import { parseAmountToZats, upsertRecentRecipients, validateJunoRecipient, validateWithdrawAmount } from '../lib/bridgeUi'

const RECENT_RECIPIENTS_KEY = 'juno-bridge:recent-juno-recipients'

function formatJuno(zatoshi: string): string {
  try {
    return formatUnits(BigInt(zatoshi), 8)
  } catch {
    return zatoshi
  }
}

export default function WithdrawFlow() {
  const { address } = useAccount()
  const [amount, setAmount] = useState('')
  const [junoRecipient, setJunoRecipient] = useState('')
  const [step, setStep] = useState<'input' | 'approve' | 'request' | 'success'>('input')
  const [successTxHash, setSuccessTxHash] = useState<string | null>(null)
  const [decodeError, setDecodeError] = useState<string | null>(null)
  const [recentRecipients, setRecentRecipients] = useState<string[]>(() => {
    const raw = window.localStorage.getItem(RECENT_RECIPIENTS_KEY)
    if (!raw) {
      return []
    }
    try {
      const parsed = JSON.parse(raw)
      return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === 'string') : []
    } catch {
      return []
    }
  })

  const { data: cfg } = useQuery({
    queryKey: ['bridge-config'],
    queryFn: getConfig,
  })

  const bridgeAddress = cfg?.bridgeAddress as `0x${string}` | undefined
  const wjunoAddress = cfg?.wjunoAddress

  const { data: balance } = useReadContract({
    address: wjunoAddress as `0x${string}` | undefined,
    abi: WJUNO_ABI,
    functionName: 'balanceOf',
    args: address ? [address] : undefined,
    query: { enabled: !!address && !!wjunoAddress },
  })

  const { data: allowance, refetch: refetchAllowance } = useReadContract({
    address: wjunoAddress as `0x${string}` | undefined,
    abi: WJUNO_ABI,
    functionName: 'allowance',
    args: address && bridgeAddress ? [address, bridgeAddress] : undefined,
    query: { enabled: !!address && !!wjunoAddress && !!bridgeAddress },
  })

  const {
    writeContract: approve,
    data: approveTxHash,
    error: approveError,
    reset: resetApprove,
  } = useWriteContract()
  const {
    writeContract: requestWithdraw,
    data: requestTxHash,
    error: requestError,
    reset: resetRequest,
  } = useWriteContract()

  const { isSuccess: approveConfirmed } = useWaitForTransactionReceipt({ hash: approveTxHash })

  useEffect(() => {
    if (approveError && step === 'approve') {
      setStep('input')
      resetApprove()
    }
  }, [approveError, step, resetApprove])

  useEffect(() => {
    if (requestError && step === 'request') {
      setStep('input')
      resetRequest()
    }
  }, [requestError, step, resetRequest])

  useEffect(() => {
    if (approveConfirmed) {
      refetchAllowance()
    }
  }, [approveConfirmed, refetchAllowance])

  const parsedAmount = parseAmountToZats(amount) ?? 0n
  const hasSufficientAllowance = allowance !== undefined && parsedAmount > 0n && (allowance as bigint) >= parsedAmount
  const amountError = validateWithdrawAmount(amount, cfg?.minWithdrawAmount, balance as bigint | undefined)
  const recipientError = validateJunoRecipient(junoRecipient)
  const formError = decodeError || amountError || recipientError

  useEffect(() => {
    window.localStorage.setItem(RECENT_RECIPIENTS_KEY, JSON.stringify(recentRecipients))
  }, [recentRecipients])

  const handleApprove = () => {
    if (!wjunoAddress || !bridgeAddress || formError) return
    approve({
      address: wjunoAddress as `0x${string}`,
      abi: WJUNO_ABI,
      functionName: 'approve',
      args: [bridgeAddress, maxUint256],
    })
    setStep('approve')
  }

  const handleRequestWithdraw = async () => {
    if (!bridgeAddress || !amount || !junoRecipient || formError) return
    setDecodeError(null)
    try {
      const orchardHex = await decodeRecipient(junoRecipient)
      requestWithdraw({
        address: bridgeAddress as `0x${string}`,
        abi: BRIDGE_ABI,
        functionName: 'requestWithdraw',
        args: [parseUnits(amount, 8), `0x${orchardHex}`],
      })
      setStep('request')
    } catch (err: any) {
      setDecodeError(err.message || 'Invalid Juno address')
    }
  }

  const { isSuccess: requestConfirmed } = useWaitForTransactionReceipt({ hash: requestTxHash })

  useEffect(() => {
    if (step === 'request' && requestConfirmed && requestTxHash) {
      setRecentRecipients((existing) => upsertRecentRecipients(existing, junoRecipient))
      setSuccessTxHash(requestTxHash)
      setStep('success')
    }
  }, [step, requestConfirmed, requestTxHash])

  const handleDismissSuccess = () => {
    setStep('input')
    setSuccessTxHash(null)
    setAmount('')
    setJunoRecipient('')
    resetRequest()
  }

  const handleMax = () => {
    if (balance === undefined) {
      return
    }
    setAmount(formatUnits(balance as bigint, 8))
  }

  if (step === 'success') {
    return (
      <div className="modal-overlay" onClick={handleDismissSuccess}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          <div className="modal-body" style={{ padding: '32px 24px' }}>
            <div className="success-icon">&#10003;</div>
            <div className="success-title">Withdrawal Submitted</div>
            <div className="success-subtitle">
              Your Base -&gt; Juno withdrawal of {amount} JUNO has been submitted on-chain. The bridge operators will process it shortly.
            </div>
            {successTxHash && (
              <div className="detail-row" style={{ borderBottom: 'none', justifyContent: 'center' }}>
                <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)', wordBreak: 'break-all', textAlign: 'center' }}>
                  Tx: {successTxHash}
                </span>
              </div>
            )}
            <button className="primary" onClick={handleDismissSuccess} style={{ marginTop: 16 }}>
              Done
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="network-card">
        <div className="network-endpoint">
          <div className="network-icon">
            <img className="network-logo" src={runtimeConfig.baseLogoUrl} alt="Base" />
          </div>
          <div>
            <div className="network-name">Base</div>
            <div className="network-label">Source chain</div>
          </div>
        </div>
        <div className="network-arrow">&rarr;</div>
        <div className="network-endpoint">
          <div className="network-icon">
            <img className="network-logo" src={runtimeConfig.junoLogoUrl} alt="Juno" />
          </div>
          <div>
            <div className="network-name">Juno</div>
            <div className="network-label">Destination chain</div>
          </div>
        </div>
      </div>

      <div className="asset-card">
        <div className="asset-header">
          <span className="asset-label">Amount</span>
          {address && balance !== undefined && (
            <span className="asset-balance">
              Balance: {formatUnits(balance as bigint, 8)} JUNO
            </span>
          )}
        </div>
        <div className="asset-input-row">
          <input
            type="number"
            placeholder="0.00"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
          <span className="asset-ticker">JUNO</span>
          <button className="ghost-btn" type="button" onClick={handleMax} disabled={balance === undefined}>
            Max
          </button>
        </div>
        {cfg && cfg.feeBps > 0 && (
          <div className="fee-line">
            <span>Bridge Fee</span>
            <span>{(cfg.feeBps / 100).toFixed(2)}%</span>
          </div>
        )}
        {cfg && cfg.minWithdrawAmount !== '0' && (
          <div className="fee-line">
            <span>Min Withdrawal</span>
            <span>{formatJuno(cfg.minWithdrawAmount)} JUNO</span>
          </div>
        )}
      </div>

      <div className="card">
        <div className="field">
          <label className="label">
            Juno Recipient Address <InfoHint label="Use any valid Juno unified address. Recent addresses are saved locally in this browser." />
          </label>
          <input
            className="mono"
            placeholder={`Unified address (${runtimeConfig.baseChain.id === 8453 ? 'juno1...' : 'jtest1...'})`}
            value={junoRecipient}
            onChange={(e) => { setJunoRecipient(e.target.value); setDecodeError(null) }}
          />
          {recentRecipients.length > 0 && (
            <div className="recent-recipient-row">
              {recentRecipients.map((recent) => (
                <button
                  key={recent}
                  className="recent-chip"
                  type="button"
                  onClick={() => {
                    setJunoRecipient(recent)
                    setDecodeError(null)
                  }}
                >
                  {recent.slice(0, 12)}...{recent.slice(-8)}
                </button>
              ))}
            </div>
          )}
          {formError && <div className="error-box">{formError}</div>}
        </div>
        {step === 'input' && !hasSufficientAllowance && (
          <button className="primary" onClick={handleApprove} disabled={!amount || !junoRecipient || !address || !!formError}>
            Approve wJUNO
          </button>
        )}
        {step === 'input' && hasSufficientAllowance && (
          <button className="primary" onClick={handleRequestWithdraw} disabled={!amount || !junoRecipient || !address || !!formError}>
            Request Withdrawal
          </button>
        )}
        {step === 'approve' && !approveConfirmed && (
          <button className="primary" disabled>
            Waiting for approval...
          </button>
        )}
        {step === 'approve' && approveConfirmed && (
          <button className="primary" onClick={handleRequestWithdraw} disabled={!!formError}>
            Request Withdrawal
          </button>
        )}
        {step === 'request' && !requestConfirmed && (
          <button className="primary" disabled>
            Waiting for on-chain confirmation...
          </button>
        )}
      </div>
    </div>
  )
}
