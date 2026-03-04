import { useQuery } from '@tanstack/react-query'
import { listDeposits, listWithdrawals } from '../api/bridge'

interface Props {
  address: string
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
        <h3>Recent Activity</h3>
        <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>
          No recent activity for connected wallet.
        </div>
      </div>
    )
  }

  return (
    <div>
      {deps.length > 0 && (
        <div className="card">
          <h3>My Deposits</h3>
          {deps.map((d) => (
            <div className="result-item" key={d.depositId}>
              <div className="id">{d.depositId}</div>
              <div className="meta">
                <span className={`status-badge ${d.state === 'finalized' ? 'green' : 'orange'}`}>{d.state}</span>
                {' '}{d.amount} zatoshi
              </div>
            </div>
          ))}
        </div>
      )}
      {wds.length > 0 && (
        <div className="card">
          <h3>My Withdrawals</h3>
          {wds.map((w) => (
            <div className="result-item" key={w.withdrawalId}>
              <div className="id">{w.withdrawalId}</div>
              <div className="meta">
                <span className={`status-badge ${w.state === 'finalized' ? 'green' : 'orange'}`}>{w.state}</span>
                {' '}{w.amount} zatoshi
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
