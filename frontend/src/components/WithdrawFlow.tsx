import { useState } from 'react'
import { useAccount, useReadContract, useWriteContract, useWaitForTransactionReceipt } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { parseUnits, formatUnits } from 'viem'
import { getConfig } from '../api/bridge'
import { WJUNO_ABI } from '../config/contracts'
import StatusTracker from './StatusTracker'

const WITHDRAW_STEPS = ['requested', 'planned', 'signing', 'signed', 'broadcasted', 'confirmed', 'finalizing', 'finalized']

export default function WithdrawFlow() {
  const { address } = useAccount()
  const [amount, setAmount] = useState('')
  const [junoRecipient, setJunoRecipient] = useState('')
  const [step, setStep] = useState<'input' | 'approve' | 'request' | 'tracking'>('input')

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

  const { writeContract: approve, data: approveTxHash } = useWriteContract()
  const { writeContract: requestWithdraw, data: requestTxHash } = useWriteContract()

  const { isSuccess: approveConfirmed } = useWaitForTransactionReceipt({ hash: approveTxHash })

  const handleApprove = () => {
    if (!wjunoAddress || !bridgeAddress || !amount) return
    approve({
      address: wjunoAddress as `0x${string}`,
      abi: WJUNO_ABI,
      functionName: 'approve',
      args: [bridgeAddress, parseUnits(amount, 8)],
    })
    setStep('approve')
  }

  const [withdrawalId, setWithdrawalId] = useState<string | null>(null)

  const handleRequestWithdraw = () => {
    if (!bridgeAddress || !amount || !junoRecipient) return
    requestWithdraw({
      address: bridgeAddress as `0x${string}`,
      abi: [{ name: 'requestWithdraw', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'amount', type: 'uint256' }, { name: 'junoRecipient', type: 'bytes' }], outputs: [] }],
      functionName: 'requestWithdraw',
      args: [parseUnits(amount, 8), junoRecipient as `0x${string}`],
    })
    setStep('request')
  }

  const { isSuccess: requestConfirmed } = useWaitForTransactionReceipt({ hash: requestTxHash })

  // Once on-chain request is confirmed, move to tracking
  if (step === 'request' && requestConfirmed && requestTxHash && !withdrawalId) {
    setWithdrawalId(requestTxHash)
    setStep('tracking')
  }

  return (
    <div>
      <div className="card">
        <h3>Withdraw: Base &rarr; Juno</h3>
        {address && balance !== undefined && (
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
            wJUNO Balance: {formatUnits(balance as bigint, 8)} JUNO
          </div>
        )}
        <div className="field">
          <label className="label">Amount (JUNO)</label>
          <input
            type="number"
            placeholder="0.0"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
        </div>
        <div className="field">
          <label className="label">Juno Recipient Address</label>
          <input
            className="mono"
            placeholder="Juno unified address hex"
            value={junoRecipient}
            onChange={(e) => setJunoRecipient(e.target.value)}
          />
        </div>
        {step === 'input' && (
          <button className="primary" onClick={handleApprove} disabled={!amount || !junoRecipient || !address}>
            Approve wJUNO
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

      {step === 'tracking' && (
        <div className="card">
          <h3>Withdrawal Status</h3>
          <StatusTracker steps={WITHDRAW_STEPS} current="requested" />
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 8 }}>
            Processing withdrawal...
          </div>
        </div>
      )}
    </div>
  )
}
