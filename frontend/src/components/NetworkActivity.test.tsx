import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { listRecentDeposits, listRecentWithdrawals } from '../api/bridge'
import NetworkActivity from './NetworkActivity'

vi.mock('../api/bridge', () => ({
  listDeposits: vi.fn(),
  listWithdrawals: vi.fn(),
  listRecentDeposits: vi.fn(),
  listRecentWithdrawals: vi.fn(),
}))

function renderNetworkActivity() {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return render(
    <QueryClientProvider client={client}>
      <NetworkActivity />
    </QueryClientProvider>,
  )
}

describe('NetworkActivity', () => {
  it('loads recent network-wide deposits and withdrawals by default', async () => {
    vi.mocked(listRecentDeposits).mockResolvedValue({
      version: 'v1',
      total: 1,
      limit: 10,
      offset: 0,
      data: [{
        version: 'v1',
        found: true,
        depositId: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        state: 'seen',
        amount: '100000000',
        baseRecipient: '0x1234567890123456789012345678901234567890',
        txHash: 'e1b3dc82527e18b90bc11bc2d69c7c44fca61e43126fac64e5ecac9d0dd0d4bd',
        baseTxHash: '0xf19c70e3fa1448cb43d90faea0fe41a9d199af0dbc7f6b6df4a25d5b73031fa1',
      }],
    })
    vi.mocked(listRecentWithdrawals).mockResolvedValue({
      version: 'v1',
      total: 1,
      limit: 10,
      offset: 0,
      data: [{
        version: 'v1',
        found: true,
        withdrawalId: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        state: 'requested',
        amount: '100000000',
        feeBps: 50,
        requester: '0x1234567890123456789012345678901234567890',
        expiry: '2026-04-08T00:00:00Z',
        batchId: '',
        junoTxId: '',
        baseTxHash: '',
      }],
    })

    renderNetworkActivity()

    await waitFor(() => {
      expect(listRecentDeposits).toHaveBeenCalledWith({ limit: '10', offset: '0' })
    })
    expect(listRecentWithdrawals).toHaveBeenCalledWith({ limit: '10', offset: '0' })
    expect(await screen.findByText(/NETWORK DEPOSITS/i)).toBeInTheDocument()
    expect(await screen.findByText(/NETWORK WITHDRAWALS/i)).toBeInTheDocument()
  })
})
