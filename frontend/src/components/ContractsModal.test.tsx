import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import ContractsModal from './ContractsModal'

describe('ContractsModal', () => {
  it('renders mainnet contract linkouts', () => {
    render(<ContractsModal open chainId={8453} onClose={() => {}} />)

    expect(screen.getByText('WJuno')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /0x2E8F83541AB39C8451b3e557A19bE531a59DdECc/i })).toHaveAttribute(
      'href',
      'https://basescan.org/address/0x2E8F83541AB39C8451b3e557A19bE531a59DdECc',
    )
    expect(screen.getByRole('link', { name: /0x0F65702343DE210098c2d83302B96E516CE3072f/i })).toHaveAttribute(
      'href',
      'https://basescan.org/address/0x0F65702343DE210098c2d83302B96E516CE3072f',
    )
  })
})
