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
  const [depositLimit, setDepositLimit] = useState(5)
  const [withdrawalLimit, setWithdrawalLimit] = useState(5)

  const { data: deposits } = useQuery({
    queryKey: ['my-deposits', address, depositLimit],
    queryFn: () => listDeposits({ baseRecipient: address, limit: String(depositLimit), offset: '0' }),
    enabled: !!address,
    refetchInterval: 15000,
  })

  const { data: withdrawals } = useQuery({
    queryKey: ['my-withdrawals', address, withdrawalLimit],
    queryFn: () => listWithdrawals({ requester: address, limit: String(withdrawalLimit), offset: '0' }),
    enabled: !!address,
    refetchInterval: 15000,
  })

  const deps = deposits?.data ?? []
  const wds = withdrawals?.data ?? []
  const canLoadMoreDeposits = (deposits?.total ?? 0) > deps.length
  const canLoadMoreWithdrawals = (withdrawals?.total ?? 0) > wds.length

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
                  <div className="tx-type">Junocash -&gt; Base</div>
                  <div className="tx-id">{d.depositId.slice(0, 10)}...{d.depositId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  <div className="tx-amount">{formatJuno(d.amount)} JUNO</div>
                </div>
              </div>
              <StatusTracker
                steps={DEPOSIT_STEPS}
                current={d.state}
                confirmations={d.confirmations}
                requiredConfirmations={d.requiredConfirmations}
              />
            </div>
          ))}
          {canLoadMoreDeposits && (
            <button className="secondary-btn" type="button" onClick={() => setDepositLimit((current) => current + 5)}>
              Load more deposits
            </button>
          )}
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
                  <div className="tx-type">Base -&gt; Junocash</div>
                  <div className="tx-id">{w.withdrawalId.slice(0, 10)}...{w.withdrawalId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  <div className="tx-amount">{formatJuno(w.amount)} JUNO</div>
                </div>
              </div>
              <StatusTracker steps={WITHDRAW_STEPS} current={w.state} />
            </div>
          ))}
          {canLoadMoreWithdrawals && (
            <button className="secondary-btn" type="button" onClick={() => setWithdrawalLimit((current) => current + 5)}>
              Load more withdrawals
            </button>
          )}
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
