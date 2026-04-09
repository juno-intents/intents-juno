import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatUnits } from 'viem'
import { listDeposits, listRecentDeposits, listRecentWithdrawals, listWithdrawals } from '../api/bridge'
import type { DepositStatus, WithdrawalStatus } from '../api/types'
import { formatTimeAgo } from '../lib/time'
import StatusTracker from './StatusTracker'
import TxDetailModal from './TxDetailModal'

const DEPOSIT_STEPS = ['pending', 'seen', 'confirmed', 'proof_requested', 'proof_ready', 'submitted', 'finalized']
const WITHDRAW_STEPS = ['requested', 'planned', 'signing', 'signed', 'broadcasted', 'confirmed', 'finalizing', 'finalized']

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

export default function NetworkActivity() {
  const [query, setQuery] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [modalData, setModalData] = useState<{ type: 'deposit' | 'withdrawal'; data: DepositStatus | WithdrawalStatus } | null>(null)

  const searchType = detectSearchType(searchTerm)

  const { data: recentDeposits } = useQuery({
    queryKey: ['recent-network-deposits'],
    queryFn: () => listRecentDeposits({ limit: '10', offset: '0' }),
    enabled: searchTerm === '',
    refetchInterval: 15000,
  })

  const { data: recentWithdrawals } = useQuery({
    queryKey: ['recent-network-withdrawals'],
    queryFn: () => listRecentWithdrawals({ limit: '10', offset: '0' }),
    enabled: searchTerm === '',
    refetchInterval: 15000,
  })

  const { data: searchedDeposits } = useQuery({
    queryKey: ['search-network-deposits', searchTerm, searchType],
    queryFn: () => {
      if (searchType === 'address') return listDeposits({ baseRecipient: searchTerm, limit: '20' })
      if (searchType === 'txhash') return listDeposits({ txHash: searchTerm })
      return Promise.resolve({ version: 'v1', data: [], total: 0, limit: 20, offset: 0 })
    },
    enabled: searchTerm !== '' && searchType !== 'unknown',
  })

  const { data: searchedWithdrawals } = useQuery({
    queryKey: ['search-network-withdrawals', searchTerm, searchType],
    queryFn: () => {
      if (searchType === 'address') return listWithdrawals({ requester: searchTerm, limit: '20' })
      if (searchType === 'txhash') return listWithdrawals({ baseTxHash: searchTerm })
      return Promise.resolve({ version: 'v1', data: [], total: 0, limit: 20, offset: 0 })
    },
    enabled: searchTerm !== '' && searchType !== 'unknown',
  })

  const handleSearch = () => {
    setSearchTerm(query.trim())
  }

  const deposits = searchTerm === '' ? (recentDeposits?.data ?? []) : (searchedDeposits?.data ?? [])
  const withdrawals = searchTerm === '' ? (recentWithdrawals?.data ?? []) : (searchedWithdrawals?.data ?? [])
  const depositsTotal = searchTerm === '' ? (recentDeposits?.total ?? 0) : (searchedDeposits?.total ?? 0)
  const withdrawalsTotal = searchTerm === '' ? (recentWithdrawals?.total ?? 0) : (searchedWithdrawals?.total ?? 0)

  return (
    <div>
      <div className="search-bar">
        <span className="search-icon">&#128269;</span>
        <input
          className="mono"
          placeholder="Search by Base address (0x...) or tx hash"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => event.key === 'Enter' && handleSearch()}
        />
      </div>

      {deposits.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8, fontWeight: 500 }}>
            NETWORK DEPOSITS ({depositsTotal})
          </div>
          {deposits.map((deposit) => (
            <div className="tx-item" key={deposit.depositId} onClick={() => setModalData({ type: 'deposit', data: deposit })}>
              <div className="tx-item-header">
                <div className="tx-left">
                  <div className="tx-type">Junocash -&gt; Base</div>
                  <div className="tx-id">{deposit.depositId.slice(0, 10)}...{deposit.depositId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  {deposit.createdAt && <div className="tx-time">{formatTimeAgo(deposit.createdAt)}</div>}
                  <div className="tx-amount">{formatJuno(deposit.amount)} JUNO</div>
                </div>
              </div>
              <StatusTracker
                steps={DEPOSIT_STEPS}
                current={deposit.state}
                confirmations={deposit.confirmations}
                requiredConfirmations={deposit.requiredConfirmations}
              />
            </div>
          ))}
        </div>
      )}

      {withdrawals.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8, fontWeight: 500 }}>
            NETWORK WITHDRAWALS ({withdrawalsTotal})
          </div>
          {withdrawals.map((withdrawal) => (
            <div className="tx-item" key={withdrawal.withdrawalId} onClick={() => setModalData({ type: 'withdrawal', data: withdrawal })}>
              <div className="tx-item-header">
                <div className="tx-left">
                  <div className="tx-type">Base -&gt; Junocash</div>
                  <div className="tx-id">{withdrawal.withdrawalId.slice(0, 10)}...{withdrawal.withdrawalId.slice(-6)}</div>
                </div>
                <div className="tx-right">
                  {withdrawal.createdAt && <div className="tx-time">{formatTimeAgo(withdrawal.createdAt)}</div>}
                  <div className="tx-amount">{formatJuno(withdrawal.amount)} JUNO</div>
                </div>
              </div>
              <StatusTracker steps={WITHDRAW_STEPS} current={withdrawal.state} />
            </div>
          ))}
        </div>
      )}

      {deposits.length === 0 && withdrawals.length === 0 && (
        <div className="card">
          <div className="empty-state">
            {searchTerm === ''
              ? 'No recent network activity yet.'
              : 'No deposits or withdrawals found for this search.'}
          </div>
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
