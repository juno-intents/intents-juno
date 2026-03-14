import { formatUnits } from 'viem'
import type { DepositStatus, WithdrawalStatus } from '../api/types'

interface Props {
  type: 'deposit' | 'withdrawal'
  data: DepositStatus | WithdrawalStatus
  onClose: () => void
}

function formatJuno(zatoshi: string): string {
  try {
    return formatUnits(BigInt(zatoshi), 8)
  } catch {
    return zatoshi
  }
}

function truncate(s: string): string {
  if (!s || s.length < 16) return s || '-'
  return s.slice(0, 10) + '...' + s.slice(-6)
}

export default function TxDetailModal({ type, data, onClose }: Props) {
  const isDeposit = type === 'deposit'
  const d = data as DepositStatus
  const w = data as WithdrawalStatus
  const currentState = isDeposit ? d.state : w.state
  const statusClass = currentState === 'finalized' ? 'green' : currentState === 'rejected' ? 'red' : 'orange'

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">{isDeposit ? 'Juno -> Base' : 'Base -> Juno'} Details</span>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body">
          <div className="detail-row">
            <span className="detail-label">ID</span>
            <span className="detail-value mono">{isDeposit ? d.depositId : w.withdrawalId}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Status</span>
            <span className={`status-badge ${statusClass}`}>
              {currentState}
            </span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Amount</span>
            <span className="detail-value mono">{formatJuno(isDeposit ? d.amount : w.amount)} JUNO</span>
          </div>
          {isDeposit && d.baseRecipient && (
            <div className="detail-row">
              <span className="detail-label">Base Recipient</span>
              <span className="detail-value mono">{truncate(d.baseRecipient)}</span>
            </div>
          )}
          {isDeposit && d.txHash && (
            <div className="detail-row">
              <span className="detail-label">Juno Tx</span>
              <span className="detail-value mono">{truncate(d.txHash)}</span>
            </div>
          )}
          {isDeposit && d.rejectionReason && (
            <div className="detail-row">
              <span className="detail-label">Rejection Reason</span>
              <span className="detail-value">{d.rejectionReason}</span>
            </div>
          )}
          {!isDeposit && w.requester && (
            <div className="detail-row">
              <span className="detail-label">Requester</span>
              <span className="detail-value mono">{truncate(w.requester)}</span>
            </div>
          )}
          {!isDeposit && w.baseTxHash && (
            <div className="detail-row">
              <span className="detail-label">Base Tx</span>
              <span className="detail-value mono">{truncate(w.baseTxHash)}</span>
            </div>
          )}
          {!isDeposit && w.junoTxId && (
            <div className="detail-row">
              <span className="detail-label">Juno Tx</span>
              <span className="detail-value mono">{truncate(w.junoTxId)}</span>
            </div>
          )}
          {!isDeposit && w.batchId && (
            <div className="detail-row">
              <span className="detail-label">Batch</span>
              <span className="detail-value mono">{truncate(w.batchId)}</span>
            </div>
          )}
          {!isDeposit && w.feeBps > 0 && (
            <div className="detail-row">
              <span className="detail-label">Fee</span>
              <span className="detail-value">{(w.feeBps / 100).toFixed(2)}%</span>
            </div>
          )}
          {!isDeposit && w.expiry && w.expiry !== '0' && (
            <div className="detail-row">
              <span className="detail-label">Expiry</span>
              <span className="detail-value mono">{w.expiry}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
