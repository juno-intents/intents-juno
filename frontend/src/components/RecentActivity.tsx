import { useQuery } from '@tanstack/react-query'
import { formatUnits } from 'viem'
import { listDeposits, listWithdrawals } from '../api/bridge'
import StatusTracker from './StatusTracker'

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
            <div className="tx-item" key={d.depositId}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div className="tx-left">
                  <div className="tx-type">Deposit</div>
                  <div className="tx-id">{d.depositId.slice(0, 10)}...{d.depositId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  <div className="tx-amount">{formatJuno(d.amount)} JUNO</div>
                </div>
              </div>
              <div style={{ marginTop: 8 }}>
                <StatusTracker steps={DEPOSIT_STEPS} current={d.state} />
              </div>
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
            <div className="tx-item" key={w.withdrawalId}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div className="tx-left">
                  <div className="tx-type">Withdrawal</div>
                  <div className="tx-id">{w.withdrawalId.slice(0, 10)}...{w.withdrawalId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  <div className="tx-amount">{formatJuno(w.amount)} JUNO</div>
                </div>
              </div>
              <div style={{ marginTop: 8 }}>
                <StatusTracker steps={WITHDRAW_STEPS} current={w.state} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
