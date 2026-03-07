import { useState, useEffect } from 'react'
import { useAccount, useReadContract, useWriteContract, useWaitForTransactionReceipt } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { parseUnits, formatUnits, maxUint256, stringToHex } from 'viem'
import { getConfig } from '../api/bridge'
import { WJUNO_ABI, BRIDGE_ABI } from '../config/contracts'

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
  const [step, setStep] = useState<'input' | 'approve' | 'request'>('input')

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

  // Reset step on approve error (user rejected, tx failed, etc.)
  useEffect(() => {
    if (approveError && step === 'approve') {
      setStep('input')
      resetApprove()
    }
  }, [approveError, step, resetApprove])

  // Reset step on request error
  useEffect(() => {
    if (requestError && step === 'request') {
      setStep('input')
      resetRequest()
    }
  }, [requestError, step, resetRequest])

  // Refetch allowance after approval confirmed
  useEffect(() => {
    if (approveConfirmed) {
      refetchAllowance()
    }
  }, [approveConfirmed, refetchAllowance])

  const parsedAmount = amount ? parseUnits(amount, 8) : 0n
  const hasSufficientAllowance = allowance !== undefined && parsedAmount > 0n && (allowance as bigint) >= parsedAmount

  const handleApprove = () => {
    if (!wjunoAddress || !bridgeAddress) return
    approve({
      address: wjunoAddress as `0x${string}`,
      abi: WJUNO_ABI,
      functionName: 'approve',
      args: [bridgeAddress, maxUint256],
    })
    setStep('approve')
  }

  const handleRequestWithdraw = () => {
    if (!bridgeAddress || !amount || !junoRecipient) return
    requestWithdraw({
      address: bridgeAddress as `0x${string}`,
      abi: BRIDGE_ABI,
      functionName: 'requestWithdraw',
      args: [parseUnits(amount, 8), stringToHex(junoRecipient)],
    })
    setStep('request')
  }

  const { isSuccess: requestConfirmed } = useWaitForTransactionReceipt({ hash: requestTxHash })

  if (step === 'request' && requestConfirmed) {
    setStep('input')
  }

  return (
    <div>
      <div className="network-card">
        <div className="network-endpoint">
          <div className="network-icon">B</div>
          <div>
            <div className="network-name">Base</div>
            <div className="network-label">Source</div>
          </div>
        </div>
        <div className="network-arrow">&rarr;</div>
        <div className="network-endpoint">
          <div className="network-icon">J</div>
          <div>
            <div className="network-name">Juno</div>
            <div className="network-label">Destination</div>
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
          <label className="label">Juno Recipient Address</label>
          <input
            className="mono"
            placeholder="Juno unified address (jtest1...)"
            value={junoRecipient}
            onChange={(e) => setJunoRecipient(e.target.value)}
          />
        </div>
        {step === 'input' && !hasSufficientAllowance && (
          <button className="primary" onClick={handleApprove} disabled={!amount || !junoRecipient || !address}>
            Approve wJUNO
          </button>
        )}
        {step === 'input' && hasSufficientAllowance && (
          <button className="primary" onClick={handleRequestWithdraw} disabled={!amount || !junoRecipient || !address}>
            Request Withdrawal
          </button>
        )}
        {step === 'approve' && !approveConfirmed && (
          <button className="primary" disabled>
            Waiting for approval...
          </button>
        )}
        {step === 'approve' && approveConfirmed && (
          <button className="primary" onClick={handleRequestWithdraw}>
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
