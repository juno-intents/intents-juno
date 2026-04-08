import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
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
})
