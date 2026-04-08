import { useEffect, useState } from 'react'
import { formatUnits } from 'viem'
import type { DepositStatus, WithdrawalStatus } from '../api/types'
import { basescanAddressUrl, basescanTxUrl, junocashTxUrl } from '../lib/bridgeUi'

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

interface DetailValueProps {
  label: string
  value?: string
  href?: string
  copyable?: boolean
  statusClass?: string
  children?: React.ReactNode
}

function DetailValue({ label, value, href, copyable, statusClass, children }: DetailValueProps) {
  return (
    <div className="detail-row">
      <span className="detail-label">{label}</span>
      <div className="detail-value-group">
        {statusClass ? (
          <span className={`status-badge ${statusClass}`}>{value}</span>
        ) : children ? (
          children
        ) : href && value ? (
          <a className="detail-link mono" href={href} target="_blank" rel="noreferrer">
            {value}
          </a>
        ) : (
          <span className="detail-value mono">{value || '-'}</span>
        )}
        {copyable && value && (
          <button className="copy-btn" type="button">
            Copy
          </button>
        )}
      </div>
    </div>
  )
}

export default function TxDetailModal({ type, data, onClose }: Props) {
  const isDeposit = type === 'deposit'
  const d = data as DepositStatus
  const w = data as WithdrawalStatus
  const currentState = isDeposit ? d.state : w.state
  const statusClass = currentState === 'finalized' ? 'green' : currentState === 'rejected' ? 'red' : 'orange'
  const [copied, setCopied] = useState<string | null>(null)

  useEffect(() => {
    if (copied === null) {
      return undefined
    }
    const timeout = window.setTimeout(() => setCopied(null), 1800)
    return () => window.clearTimeout(timeout)
  }, [copied])

  const handleCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied('Copied')
    } catch {
      setCopied('Copy failed')
    }
  }

  const renderField = (label: string, value?: string, options?: { href?: string; copyable?: boolean }) => (
    <div className="detail-row">
      <span className="detail-label">{label}</span>
      <div className="detail-value-group">
        {options?.href && value ? (
          <a className="detail-link mono" href={options.href} target="_blank" rel="noreferrer">
            {value}
          </a>
        ) : (
          <span className="detail-value mono">{value || '-'}</span>
        )}
        {options?.copyable && value && (
          <button className="copy-btn" type="button" onClick={() => handleCopy(value)}>
            Copy
          </button>
        )}
      </div>
    </div>
  )

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-header-text">
            <span className="modal-title">{isDeposit ? 'Junocash -> Base' : 'Base -> Junocash'} Details</span>
            {copied && <span className="modal-step">{copied}</span>}
          </div>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body">
          {renderField('ID', isDeposit ? d.depositId : w.withdrawalId, { copyable: true })}
          <DetailValue label="Status" value={currentState} statusClass={statusClass} />
          <div className="detail-row">
            <span className="detail-label">Amount</span>
            <span className="detail-value mono">{formatJuno(isDeposit ? d.amount : w.amount)} JUNO</span>
          </div>
          {isDeposit && d.baseRecipient && renderField('Base Recipient', d.baseRecipient, {
            href: basescanAddressUrl(d.baseRecipient),
            copyable: true,
          })}
          {isDeposit && d.baseTxHash && renderField('Base Tx', d.baseTxHash, {
            href: basescanTxUrl(d.baseTxHash),
            copyable: true,
          })}
          {isDeposit && d.txHash && renderField('Junocash Tx', d.txHash, {
            href: junocashTxUrl(d.txHash),
            copyable: true,
          })}
          {isDeposit && d.rejectionReason && (
            <div className="detail-row">
              <span className="detail-label">Rejection Reason</span>
              <span className="detail-value">{d.rejectionReason}</span>
            </div>
          )}
          {!isDeposit && w.requester && renderField('Requester', w.requester, {
            href: basescanAddressUrl(w.requester),
            copyable: true,
          })}
          {!isDeposit && w.baseTxHash && renderField('Base Tx', w.baseTxHash, {
            href: basescanTxUrl(w.baseTxHash),
            copyable: true,
          })}
          {!isDeposit && w.junoTxId && renderField('Junocash Tx', w.junoTxId, {
            href: junocashTxUrl(w.junoTxId),
            copyable: true,
          })}
          {!isDeposit && w.batchId && renderField('Batch', w.batchId, { copyable: true })}
          {!isDeposit && w.feeBps > 0 && (
            <div className="detail-row">
              <span className="detail-label">Fee</span>
              <span className="detail-value">{(w.feeBps / 100).toFixed(2)}%</span>
            </div>
          )}
          {!isDeposit && w.expiry && w.expiry !== '0' && renderField('Expiry', w.expiry)}
        </div>
      </div>
    </div>
  )
}
