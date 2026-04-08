import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import TxDetailModal from './TxDetailModal'

describe('TxDetailModal', () => {
  beforeEach(() => {
    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined),
      },
    })
  })

  it('renders deposit tx and address linkouts and supports copy feedback', async () => {
    const user = userEvent.setup()

    render(
      <TxDetailModal
        type="deposit"
        data={{
          version: 'v1',
          found: true,
          depositId: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          state: 'seen',
          amount: '100000000',
          baseRecipient: '0x1db445c5fe275aee8c1985efdf887c3ee6392cec',
          txHash: 'e1b3dc82527e18b90bc11bc2d69c7c44fca61e43126fac64e5ecac9d0dd0d4bd',
          baseTxHash: '0xf19c70e3fa1448cb43d90faea0fe41a9d199af0dbc7f6b6df4a25d5b73031fa1',
        }}
        onClose={() => {}}
      />,
    )

    expect(screen.getByRole('link', { name: /0x1db445c5fe275aee8c1985efdf887c3ee6392cec/i })).toHaveAttribute(
      'href',
      'https://basescan.org/address/0x1db445c5fe275aee8c1985efdf887c3ee6392cec',
    )
    expect(screen.getByRole('link', { name: /0xf19c70e3fa1448cb43d90faea0fe41a9d199af0dbc7f6b6df4a25d5b73031fa1/i })).toHaveAttribute(
      'href',
      'https://basescan.org/tx/0xf19c70e3fa1448cb43d90faea0fe41a9d199af0dbc7f6b6df4a25d5b73031fa1',
    )
    expect(screen.getByRole('link', { name: /e1b3dc82527e18b90bc11bc2d69c7c44fca61e43126fac64e5ecac9d0dd0d4bd/i })).toHaveAttribute(
      'href',
      'https://junocash.xplorer.info/tx/e1b3dc82527e18b90bc11bc2d69c7c44fca61e43126fac64e5ecac9d0dd0d4bd',
    )

    await user.click(screen.getAllByRole('button', { name: /copy/i })[0]!)
    expect(await screen.findByText(/Copied/i)).toBeInTheDocument()
  })
})
