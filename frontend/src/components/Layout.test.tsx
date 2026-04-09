import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import Layout from './Layout'

vi.mock('@rainbow-me/rainbowkit', () => ({
  ConnectButton: ({ showBalance }: { showBalance?: boolean }) => (
    <button type="button">Connect {showBalance ? 'with balance' : 'wallet'}</button>
  ),
}))

vi.mock('../api/bridge', () => ({
  getConfig: vi.fn().mockResolvedValue({
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
  }),
}))

vi.mock('./DepositFlow', () => ({
  default: () => <div>DepositFlow</div>,
}))

vi.mock('./WithdrawFlow', () => ({
  default: () => <div>WithdrawFlow</div>,
}))

vi.mock('./Explorer', () => ({
  default: () => <div>Explorer</div>,
}))

vi.mock('./NetworkActivity', () => ({
  default: () => <div>NetworkActivity</div>,
}))

vi.mock('./ApiDocs', () => ({
  default: () => <div>ApiDocs</div>,
}))

vi.mock('./GuideModal', () => ({
  default: () => null,
}))

vi.mock('./ContractsModal', () => ({
  default: () => null,
}))

function renderLayout() {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return render(
    <QueryClientProvider client={client}>
      <Layout />
    </QueryClientProvider>,
  )
}

describe('Layout', () => {
  it('renders a whitepaper link beside the guide actions', () => {
    renderLayout()

    expect(screen.getByRole('link', { name: 'Whitepaper' })).toHaveAttribute('href', '/whitepaper.pdf')
  })

  it('includes the uniswap action and a mobile navigation menu', async () => {
    const user = userEvent.setup()
    renderLayout()

    expect(screen.getByRole('link', { name: 'Uniswap' })).toHaveAttribute(
      'href',
      'https://app.uniswap.org/explore/pools/base/0xdba3574e915900f3ac316f6c1078718d9983754951dcf5fa211b40c471cf2219',
    )

    await user.click(screen.getByRole('button', { name: /open navigation menu/i }))

    const menu = screen.getByRole('menu')
    expect(menu).toBeInTheDocument()
    expect(within(menu).getByRole('button', { name: 'Guide' })).toBeInTheDocument()
    expect(within(menu).getByRole('button', { name: 'Contracts' })).toBeInTheDocument()
    expect(within(menu).getByRole('link', { name: 'Whitepaper' })).toHaveAttribute('href', '/whitepaper.pdf')
  })
})
