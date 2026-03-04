import { useState } from 'react'
import { useAccount } from 'wagmi'
import { useQuery } from '@tanstack/react-query'
import { listDeposits, listWithdrawals } from '../api/bridge'
import RecentActivity from './RecentActivity'

function detectSearchType(q: string): 'address' | 'txhash' | 'unknown' {
  const clean = q.trim().toLowerCase()
  if (clean.startsWith('0x')) {
    if (clean.length === 42) return 'address'
    if (clean.length === 66) return 'txhash'
  }
  return 'unknown'
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
            <div className="card">
              <h3>Deposits ({depositResults?.total ?? 0})</h3>
              {deposits.map((d) => (
                <div className="result-item" key={d.depositId}>
                  <div className="id">{d.depositId}</div>
                  <div className="meta">
                    <span className={`status-badge ${d.state === 'finalized' ? 'green' : 'orange'}`}>{d.state}</span>
                    {' '}{d.amount} zatoshi
                    {d.txHash && <span> &middot; tx: {d.txHash.slice(0, 10)}...</span>}
                  </div>
                </div>
              ))}
            </div>
          )}

          {withdrawals.length > 0 && (
            <div className="card">
              <h3>Withdrawals ({withdrawResults?.total ?? 0})</h3>
              {withdrawals.map((w) => (
                <div className="result-item" key={w.withdrawalId}>
                  <div className="id">{w.withdrawalId}</div>
                  <div className="meta">
                    <span className={`status-badge ${w.state === 'finalized' ? 'green' : 'orange'}`}>{w.state}</span>
                    {' '}{w.amount} zatoshi
                    {w.junoTxId && <span> &middot; juno: {w.junoTxId.slice(0, 10)}...</span>}
                  </div>
                </div>
              ))}
            </div>
          )}

          {deposits.length === 0 && withdrawals.length === 0 && (
            <div className="card">
              <h3>No results</h3>
              <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>
                No deposits or withdrawals found for this search.
              </div>
            </div>
          )}
        </>
      )}

      {!searchTerm && address && <RecentActivity address={address} />}
    </div>
  )
}
