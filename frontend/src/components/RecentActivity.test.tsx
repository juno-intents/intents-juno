import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { listDeposits, listWithdrawals } from '../api/bridge'
import RecentActivity from './RecentActivity'

vi.mock('../api/bridge', () => ({
  listDeposits: vi.fn(),
  listWithdrawals: vi.fn(),
}))

function renderRecentActivity() {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return render(
    <QueryClientProvider client={client}>
      <RecentActivity address="0x1234567890123456789012345678901234567890" />
    </QueryClientProvider>,
  )
}

describe('RecentActivity', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(listDeposits).mockResolvedValue({
      version: 'v1',
      total: 6,
      limit: 5,
      offset: 0,
      data: Array.from({ length: 5 }, (_, idx) => ({
        version: 'v1',
        found: true,
        depositId: `0x${String(idx + 1).padStart(64, '0')}`,
        state: 'confirmed',
        amount: '100000000',
        baseRecipient: '0x1234567890123456789012345678901234567890',
        txHash: `0x${String(idx + 11).padStart(64, '0')}`,
        baseTxHash: '',
      })),
    })

    vi.mocked(listWithdrawals).mockResolvedValue({
      version: 'v1',
      total: 6,
      limit: 5,
      offset: 0,
      data: Array.from({ length: 5 }, (_, idx) => ({
        version: 'v1',
        found: true,
        withdrawalId: `0x${String(idx + 21).padStart(64, '0')}`,
        state: 'requested',
        amount: '100000000',
        feeBps: 50,
        requester: '0x1234567890123456789012345678901234567890',
        expiry: '2026-04-08T00:00:00Z',
        batchId: '',
        junoTxId: '',
        baseTxHash: '',
      })),
    })
  })

  it('starts at five per section and loads more on demand', async () => {
    const user = userEvent.setup()
    renderRecentActivity()

    await waitFor(() => {
      expect(listDeposits).toHaveBeenCalledWith({
        baseRecipient: '0x1234567890123456789012345678901234567890',
        limit: '5',
        offset: '0',
      })
    })
    expect(listWithdrawals).toHaveBeenCalledWith({
      requester: '0x1234567890123456789012345678901234567890',
      limit: '5',
      offset: '0',
    })

    vi.mocked(listDeposits).mockResolvedValueOnce({
      version: 'v1',
      total: 6,
      limit: 10,
      offset: 0,
      data: Array.from({ length: 6 }, (_, idx) => ({
        version: 'v1',
        found: true,
        depositId: `0x${String(idx + 1).padStart(64, '0')}`,
        state: 'confirmed',
        amount: '100000000',
        baseRecipient: '0x1234567890123456789012345678901234567890',
        txHash: `0x${String(idx + 11).padStart(64, '0')}`,
        baseTxHash: '',
      })),
    })

    await user.click(await screen.findByRole('button', { name: /Load more deposits/i }))

    await waitFor(() => {
      expect(listDeposits).toHaveBeenLastCalledWith({
        baseRecipient: '0x1234567890123456789012345678901234567890',
        limit: '10',
        offset: '0',
      })
    })
  })
})
