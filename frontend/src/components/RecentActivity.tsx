import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatUnits } from 'viem'
import { listDeposits, listWithdrawals } from '../api/bridge'
import type { DepositStatus, WithdrawalStatus } from '../api/types'
import StatusTracker from './StatusTracker'
import TxDetailModal from './TxDetailModal'

interface Props {
  address: string
}

const DEPOSIT_STEPS = ['pending', 'seen', 'confirmed', 'proof_requested', 'proof_ready', 'submitted', 'finalized']
const WITHDRAW_STEPS = ['requested', 'planned', 'signing', 'signed', 'broadcasted', 'confirmed', 'finalizing', 'finalized']

function formatJuno(zatoshi: string): string {
  try {
    return formatUnits(BigInt(zatoshi), 8)
  } catch {
    return zatoshi
  }
}

export default function RecentActivity({ address }: Props) {
  const [modalData, setModalData] = useState<{ type: 'deposit' | 'withdrawal'; data: DepositStatus | WithdrawalStatus } | null>(null)

  const { data: deposits } = useQuery({
    queryKey: ['my-deposits', address],
    queryFn: () => listDeposits({ baseRecipient: address, limit: '10' }),
    enabled: !!address,
    refetchInterval: 15000,
  })

  const { data: withdrawals } = useQuery({
    queryKey: ['my-withdrawals', address],
    queryFn: () => listWithdrawals({ requester: address, limit: '10' }),
    enabled: !!address,
    refetchInterval: 15000,
  })

  const deps = deposits?.data ?? []
  const wds = withdrawals?.data ?? []

  if (deps.length === 0 && wds.length === 0) {
    return (
      <div className="card">
        <div className="empty-state">
          No recent activity for connected wallet.
        </div>
      </div>
    )
  }

  return (
    <div>
      {deps.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8, fontWeight: 500 }}>
            MY DEPOSITS
          </div>
          {deps.map((d) => (
            <div className="tx-item" key={d.depositId} onClick={() => setModalData({ type: 'deposit', data: d })}>
              <div className="tx-item-header">
                <div className="tx-left">
                  <div className="tx-type">Deposit</div>
                  <div className="tx-id">{d.depositId.slice(0, 10)}...{d.depositId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  <div className="tx-amount">{formatJuno(d.amount)} JUNO</div>
                </div>
              </div>
              <StatusTracker steps={DEPOSIT_STEPS} current={d.state} />
            </div>
          ))}
        </div>
      )}
      {wds.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8, fontWeight: 500 }}>
            MY WITHDRAWALS
          </div>
          {wds.map((w) => (
            <div className="tx-item" key={w.withdrawalId} onClick={() => setModalData({ type: 'withdrawal', data: w })}>
              <div className="tx-item-header">
                <div className="tx-left">
                  <div className="tx-type">Withdrawal</div>
                  <div className="tx-id">{w.withdrawalId.slice(0, 10)}...{w.withdrawalId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  <div className="tx-amount">{formatJuno(w.amount)} JUNO</div>
                </div>
              </div>
              <StatusTracker steps={WITHDRAW_STEPS} current={w.state} />
            </div>
          ))}
        </div>
      )}

      {modalData && (
        <TxDetailModal
          type={modalData.type}
          data={modalData.data}
          onClose={() => setModalData(null)}
        />
      )}
    </div>
  )
}
