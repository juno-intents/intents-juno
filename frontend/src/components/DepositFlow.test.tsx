import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useAccount } from 'wagmi'
import { getConfig, getDepositMemo } from '../api/bridge'
import DepositFlow from './DepositFlow'

vi.mock('wagmi', () => ({
  useAccount: vi.fn(),
}))

vi.mock('../api/bridge', () => ({
  getConfig: vi.fn(),
  getDepositMemo: vi.fn(),
}))

vi.mock('../config/runtime', () => ({
  runtimeConfig: {
    junoLogoUrl: '/juno-icon.svg',
    baseLogoUrl: '/base-icon.png',
    junoCliModeFlag: '-testnet ',
  },
}))

vi.mock('qrcode.react', () => ({
  QRCodeSVG: ({ value }: { value: string }) => <div data-testid="deposit-qr">{value}</div>,
}))

const CONNECTED_ADDRESS = '0x1234567890123456789012345678901234567890'
const CUSTOM_ADDRESS = '0x9999999999999999999999999999999999999999'

function renderDepositFlow() {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return render(
    <QueryClientProvider client={client}>
      <DepositFlow />
    </QueryClientProvider>,
  )
}

describe('DepositFlow', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(useAccount).mockReturnValue({
      address: CONNECTED_ADDRESS,
    } as unknown as ReturnType<typeof useAccount>)

    vi.mocked(getConfig).mockResolvedValue({
      version: 'test',
      baseChainId: 84532,
      bridgeAddress: '0xbridge',
      wjunoAddress: '0xwjuno',
      oWalletUA: 'jtest1bridgewallet',
      withdrawalExpiryWindowSeconds: 600,
      minDepositAmount: '201005025',
      depositMinConfirmations: 1,
      minWithdrawAmount: '100000000',
      feeBps: 50,
    })

    vi.mocked(getDepositMemo).mockResolvedValue({
      version: 'test',
      baseRecipient: CONNECTED_ADDRESS,
      oWalletUA: 'jtest1destinationwallet',
      nonce: '7',
      memoHex: `${'ab'.repeat(68)}${'00'.repeat(444)}`,
      memoBase64: 'memo-base-64',
    })
  })

  it('defaults to the connected wallet, allows editing, and can restore wallet mode', async () => {
    const user = userEvent.setup()
    renderDepositFlow()

    const recipient = await screen.findByDisplayValue(CONNECTED_ADDRESS)
    expect(recipient).toHaveAttribute('readonly')
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Use connected wallet' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Edit' }))

    const editableRecipient = screen.getByRole('textbox', { name: /Base Recipient Address/i })
    expect(editableRecipient).not.toHaveAttribute('readonly')
    expect(editableRecipient).toHaveValue('')

    await user.type(editableRecipient, CUSTOM_ADDRESS)
    await user.click(screen.getByRole('button', { name: 'Use connected wallet' }))

    expect(screen.getByDisplayValue(CONNECTED_ADDRESS)).toHaveAttribute('readonly')
  })

  it('waits for agreement before requesting a deposit memo and then shows transport options', async () => {
    const user = userEvent.setup()
    renderDepositFlow()

    const generateButton = await screen.findByRole('button', { name: 'Generate Deposit Instructions' })

    expect(generateButton).toBeDisabled()
    expect(screen.getByText(/Enter a deposit amount/i)).toBeInTheDocument()

    await user.type(screen.getByRole('spinbutton', { name: /Amount \(JUNO\)/i }), '3')
    expect(generateButton).toBeEnabled()

    await user.click(generateButton)

    expect(screen.getByText(/I will not send less than 2.01005025 JUNO or my funds will be permanently lost/i)).toBeInTheDocument()
    expect(screen.getByText(/I must include the memo exactly or my funds will be permanently lost/i)).toBeInTheDocument()
    expect(screen.getByText(/Juno Intents is not responsible/i)).toBeInTheDocument()
    expect(getDepositMemo).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'I agree' }))

    await waitFor(() => {
      expect(getDepositMemo).toHaveBeenCalledWith(CONNECTED_ADDRESS)
    })

    expect(await screen.findByRole('button', { name: 'QR Code' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Junocash CLI' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Manual Send' })).toBeInTheDocument()
  })

  it('renders transport-specific instruction content inside the modal flow', async () => {
    const user = userEvent.setup()
    renderDepositFlow()

    await user.type(await screen.findByRole('spinbutton', { name: /Amount \(JUNO\)/i }), '3')
    await user.click(await screen.findByRole('button', { name: 'Generate Deposit Instructions' }))
    await user.click(screen.getByRole('button', { name: 'I agree' }))
    await screen.findByRole('button', { name: 'Manual Send' })

    await user.click(screen.getByRole('button', { name: 'Manual Send' }))

    expect(screen.getByText('Destination Address')).toBeInTheDocument()
    expect(screen.getByText('Memo (required)')).toBeInTheDocument()
    expect(screen.getByText('jtest1destinationwallet')).toBeInTheDocument()
    expect(screen.queryByText('junocash-cli')).not.toBeInTheDocument()
    expect(screen.queryByTestId('deposit-qr')).not.toBeInTheDocument()
  })

  it('shows a QR summary with the required amount and memo fallback details', async () => {
    const user = userEvent.setup()
    renderDepositFlow()

    await user.type(await screen.findByRole('spinbutton', { name: /Amount \(JUNO\)/i }), '3')
    await user.click(await screen.findByRole('button', { name: 'Generate Deposit Instructions' }))
    await user.click(screen.getByRole('button', { name: 'I agree' }))
    await screen.findByRole('button', { name: 'QR Code' })

    await user.click(screen.getByRole('button', { name: 'QR Code' }))

    expect(screen.getByTestId('deposit-qr')).toBeInTheDocument()
    expect(screen.getByTestId('deposit-qr')).toHaveTextContent('jtest1destinationwallet?amount=3')
    expect(screen.getByTestId('deposit-qr')).not.toHaveTextContent('memo=')
    expect(screen.getByText('Wallet will send')).toBeInTheDocument()
    expect(screen.getAllByText('3 JUNO')).not.toHaveLength(0)
    expect(screen.getByText('Memo delivery')).toBeInTheDocument()
    expect(screen.getByText('QR omits the memo. Copy the full 1024-character memo separately.')).toBeInTheDocument()
  })

  it('shows the canonical full memo in manual and cli formats', async () => {
    const user = userEvent.setup()
    const canonicalMemo = `${'ab'.repeat(68)}${'00'.repeat(444)}`
    renderDepositFlow()

    await user.type(await screen.findByRole('spinbutton', { name: /Amount \(JUNO\)/i }), '3')
    await user.click(await screen.findByRole('button', { name: 'Generate Deposit Instructions' }))
    await user.click(screen.getByRole('button', { name: 'I agree' }))
    await screen.findByRole('button', { name: 'Manual Send' })

    await user.click(screen.getByRole('button', { name: 'Manual Send' }))
    expect(screen.getByText(canonicalMemo)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Back' }))
    await user.click(screen.getByRole('button', { name: 'Junocash CLI' }))
    expect(screen.getByText(new RegExp(`MEMO=\"${canonicalMemo}\"`))).toBeInTheDocument()
  })

  it('does not carry a memo fetch error into the next warning modal open', async () => {
    const user = userEvent.setup()

    vi.mocked(getDepositMemo)
      .mockRejectedValueOnce(new Error('API 500: /v1/deposit-memo'))
      .mockResolvedValueOnce({
        version: 'test',
        baseRecipient: CONNECTED_ADDRESS,
        oWalletUA: 'jtest1destinationwallet',
        nonce: '7',
        memoHex: `${'ab'.repeat(68)}${'00'.repeat(444)}`,
        memoBase64: 'memo-base-64',
    })

    renderDepositFlow()

    await user.type(await screen.findByRole('spinbutton', { name: /Amount \(JUNO\)/i }), '3')
    await user.click(await screen.findByRole('button', { name: 'Generate Deposit Instructions' }))
    await user.click(screen.getByRole('button', { name: 'I agree' }))

    expect(await screen.findByText('API 500: /v1/deposit-memo')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await user.click(screen.getByRole('button', { name: 'Generate Deposit Instructions' }))

    expect(screen.queryByText('API 500: /v1/deposit-memo')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'I agree' }))
    expect(await screen.findByRole('button', { name: 'QR Code' })).toBeInTheDocument()
  })
})
