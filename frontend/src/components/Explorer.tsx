import { useState } from 'react'
import { useAccount } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { formatUnits } from 'viem'
import { listDeposits, listWithdrawals } from '../api/bridge'
import RecentActivity from './RecentActivity'

function formatJuno(zatoshi: string): string {
  try {
    return formatUnits(BigInt(zatoshi), 8)
  } catch {
    return zatoshi
  }
}

function detectSearchType(q: string): 'address' | 'txhash' | 'unknown' {
  const clean = q.trim().toLowerCase()
  if (clean.startsWith('0x')) {
    if (clean.length === 42) return 'address'
    if (clean.length === 66) return 'txhash'
  }
  return 'unknown'
}

function statusColor(state: string): string {
  if (state === 'finalized') return 'green'
  if (state === 'pending' || state === 'unknown') return 'dim'
  return 'orange'
}

export default function Explorer() {
  const { address } = useAccount()
  const [query, setQuery] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  const searchType = detectSearchType(searchTerm)

  const { data: depositResults } = useQuery({
    queryKey: ['search-deposits', searchTerm, searchType],
    queryFn: () => {
      if (searchType === 'address') return listDeposits({ baseRecipient: searchTerm, limit: '20' })
      if (searchType === 'txhash') return listDeposits({ txHash: searchTerm })
      return Promise.resolve({ version: 'v1', data: [], total: 0, limit: 20, offset: 0 })
    },
    enabled: !!searchTerm && searchType !== 'unknown',
  })

  const { data: withdrawResults } = useQuery({
    queryKey: ['search-withdrawals', searchTerm, searchType],
    queryFn: () => {
      if (searchType === 'address') return listWithdrawals({ requester: searchTerm, limit: '20' })
      if (searchType === 'txhash') return listWithdrawals({ baseTxHash: searchTerm })
      return Promise.resolve({ version: 'v1', data: [], total: 0, limit: 20, offset: 0 })
    },
    enabled: !!searchTerm && searchType !== 'unknown',
  })

  const handleSearch = () => {
    setSearchTerm(query.trim())
  }

  const deposits = depositResults?.data ?? []
  const withdrawals = withdrawResults?.data ?? []

  return (
    <div>
      <div className="search-bar">
        <span className="search-icon">&#128269;</span>
        <input
          className="mono"
          placeholder="Search by address (0x...) or tx hash"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
        />
      </div>

      {searchTerm && (
        <>
          {deposits.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8, fontWeight: 500 }}>
                DEPOSITS ({depositResults?.total ?? 0})
              </div>
              {deposits.map((d) => (
                <div className="tx-item" key={d.depositId}>
                  <div className="tx-left">
                    <div className="tx-type">Deposit</div>
                    <div className="tx-id">{d.depositId.slice(0, 10)}...{d.depositId.slice(-6)}</div>
                  </div>
                  <div className="tx-right">
                    <div className="tx-amount">{formatJuno(d.amount)} JUNO</div>
                    <span className={`status-pill-sm ${statusColor(d.state)}`}>{d.state}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {withdrawals.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8, fontWeight: 500 }}>
                WITHDRAWALS ({withdrawResults?.total ?? 0})
              </div>
              {withdrawals.map((w) => (
                <div className="tx-item" key={w.withdrawalId}>
                  <div className="tx-left">
                    <div className="tx-type">Withdrawal</div>
                    <div className="tx-id">{w.withdrawalId.slice(0, 10)}...{w.withdrawalId.slice(-6)}</div>
                  </div>
                  <div className="tx-right">
                    <div className="tx-amount">{formatJuno(w.amount)} JUNO</div>
                    <span className={`status-pill-sm ${statusColor(w.state)}`}>{w.state}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {deposits.length === 0 && withdrawals.length === 0 && (
            <div className="card">
              <div className="empty-state">
                No deposits or withdrawals found for this search.
              </div>
            </div>
          )}
        </>
      )}

      {!searchTerm && address && <RecentActivity address={address} />}

      {!searchTerm && !address && (
        <div className="card">
          <div className="empty-state">
            Connect your wallet to see recent activity, or search by address / tx hash.
          </div>
        </div>
      )}
    </div>
  )
}
