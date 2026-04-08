import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import GuideModal from './GuideModal'

describe('GuideModal', () => {
  it('renders the updated Junocash guide copy', () => {
    render(<GuideModal open onClose={() => {}} />)

    expect(screen.getByText('Junocash (JUNO) -> Base (wJUNO)')).toBeInTheDocument()
    expect(screen.getByText(/send native Junocash \(JUNO\) to the shielded bridge wallet/i)).toBeInTheDocument()
    expect(screen.getByText('Base (wJUNO) -> Junocash (JUNO)')).toBeInTheDocument()
    expect(screen.getByText(/request the withdrawal to a Junocash native j1 address/i)).toBeInTheDocument()
    expect(screen.getByText(/will not recognize deposits below the minimum and withdrawals below the minimum/i)).toBeInTheDocument()
    expect(screen.getByText(/PERMANENTLY lost and unrecoverable/i)).toBeInTheDocument()
  })
})
