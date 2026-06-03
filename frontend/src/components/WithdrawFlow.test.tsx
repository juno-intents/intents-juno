import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { useAccount, useReadContract, useWaitForTransactionReceipt, useWriteContract } from 'wagmi'
import { decodeRecipient, getConfig } from '../api/bridge'
import WithdrawFlow from './WithdrawFlow'

vi.mock('wagmi', () => ({
  useAccount: vi.fn(),
  useReadContract: vi.fn(),
  useWaitForTransactionReceipt: vi.fn(),
  useWriteContract: vi.fn(),
}))

vi.mock('../api/bridge', () => ({
  getConfig: vi.fn(),
  decodeRecipient: vi.fn(),
}))

vi.mock('../config/runtime', () => ({
  runtimeConfig: {
    junoLogoUrl: '/juno-icon.svg',
    baseLogoUrl: '/base-icon.png',
    baseChain: { id: 8453 },
  },
}))

const activeConfig = {
  version: 'v1',
  baseChainId: 8453,
  bridgeAddress: '0x0F65702343DE210098c2d83302B96E516CE3072f',
  wjunoAddress: '0x2E8F83541AB39C8451b3e557A19bE531a59DdECc',
  oWalletUA: 'j1test',
  withdrawalExpiryWindowSeconds: 86400,
  minDepositAmount: '201005025',
  depositMinConfirmations: 200,
  minWithdrawAmount: '200000000',
  feeBps: 50,
  bridgePaused: false,
}

const pausedConfig = {
  ...activeConfig,
  bridgePaused: true,
  bridgePauseMessage: 'Bridge is paused while operators investigate a Junocash chain incident.',
}

function renderWithdrawFlow() {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return render(
    <QueryClientProvider client={client}>
      <WithdrawFlow />
    </QueryClientProvider>,
  )
}

describe('WithdrawFlow', () => {
  it('disables withdrawal actions while the bridge is paused', async () => {
    vi.mocked(useAccount).mockReturnValue({
      address: '0x1234567890123456789012345678901234567890',
    } as unknown as ReturnType<typeof useAccount>)
    vi.mocked(useReadContract).mockReturnValue({ data: 3_00000000n } as unknown as ReturnType<typeof useReadContract>)
    vi.mocked(useWriteContract).mockReturnValue({
      writeContract: vi.fn(),
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useWriteContract>)
    vi.mocked(useWaitForTransactionReceipt).mockReturnValue({ isSuccess: false } as unknown as ReturnType<typeof useWaitForTransactionReceipt>)
    vi.mocked(getConfig).mockResolvedValue(pausedConfig)

    renderWithdrawFlow()

    expect(await screen.findByText('Bridge is paused')).toBeInTheDocument()
    expect(screen.getByText('Bridge is paused while operators investigate a Junocash chain incident.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Withdrawals paused' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Approve wJUNO' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Request Withdrawal' })).not.toBeInTheDocument()
  })

  it('refetches pause state before submitting a withdrawal from a stale tab', async () => {
    const user = userEvent.setup()
    const writeContract = vi.fn()
    vi.mocked(useAccount).mockReturnValue({
      address: '0x1234567890123456789012345678901234567890',
    } as unknown as ReturnType<typeof useAccount>)
    vi.mocked(useReadContract).mockReturnValue({ data: 3_00000000n } as unknown as ReturnType<typeof useReadContract>)
    vi.mocked(useWriteContract).mockReturnValue({
      writeContract,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useWriteContract>)
    vi.mocked(useWaitForTransactionReceipt).mockReturnValue({ isSuccess: false } as unknown as ReturnType<typeof useWaitForTransactionReceipt>)
    vi.mocked(decodeRecipient).mockResolvedValue('00'.repeat(43))
    vi.mocked(getConfig)
      .mockResolvedValueOnce(activeConfig)
      .mockResolvedValueOnce(pausedConfig)

    renderWithdrawFlow()

    await user.type(await screen.findByPlaceholderText('0.00'), '2')
    await user.type(screen.getByPlaceholderText('Junocash address (j1...)'), 'j1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq')
    await user.click(screen.getByRole('button', { name: 'Request Withdrawal' }))

    await waitFor(() => expect(screen.getByRole('button', { name: 'Withdrawals paused' })).toBeDisabled())
    expect(decodeRecipient).not.toHaveBeenCalled()
    expect(writeContract).not.toHaveBeenCalled()
  })

  it('fails closed when withdrawal pause refresh fails from a stale tab', async () => {
    const user = userEvent.setup()
    const writeContract = vi.fn()
    vi.mocked(useAccount).mockReturnValue({
      address: '0x1234567890123456789012345678901234567890',
    } as unknown as ReturnType<typeof useAccount>)
    vi.mocked(useReadContract).mockReturnValue({ data: 3_00000000n } as unknown as ReturnType<typeof useReadContract>)
    vi.mocked(useWriteContract).mockReturnValue({
      writeContract,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useWriteContract>)
    vi.mocked(useWaitForTransactionReceipt).mockReturnValue({ isSuccess: false } as unknown as ReturnType<typeof useWaitForTransactionReceipt>)
    vi.mocked(decodeRecipient).mockResolvedValue('00'.repeat(43))
    vi.mocked(getConfig)
      .mockResolvedValueOnce(activeConfig)
      .mockRejectedValueOnce(new Error('network unavailable'))

    renderWithdrawFlow()

    await user.type(await screen.findByPlaceholderText('0.00'), '2')
    await user.type(screen.getByPlaceholderText('Junocash address (j1...)'), 'j1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq')
    await user.click(screen.getByRole('button', { name: 'Request Withdrawal' }))

    expect(await screen.findByText('Bridge status could not be refreshed. Try again shortly.')).toBeInTheDocument()
    expect(decodeRecipient).not.toHaveBeenCalled()
    expect(writeContract).not.toHaveBeenCalled()
  })
})
