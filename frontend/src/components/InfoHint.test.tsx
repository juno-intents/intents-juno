import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import InfoHint from './InfoHint'

describe('InfoHint', () => {
  it('opens on hover and closes when the pointer leaves', async () => {
    const user = userEvent.setup()
    render(<InfoHint label="Any Base address works. Leave this blank to use the currently connected wallet." />)

    const trigger = screen.getByRole('button', {
      name: 'Any Base address works. Leave this blank to use the currently connected wallet.',
    })

    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()

    await user.hover(trigger)
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'Any Base address works. Leave this blank to use the currently connected wallet.',
    )

    await user.unhover(trigger)
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('opens on focus and click, and closes on Escape', async () => {
    const user = userEvent.setup()
    render(<InfoHint label="Memo must match exactly." />)

    const trigger = screen.getByRole('button', { name: 'Memo must match exactly.' })

    trigger.focus()
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Memo must match exactly.')

    await user.keyboard('{Escape}')
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()

    await user.click(trigger)
    expect(screen.getByRole('tooltip')).toHaveTextContent('Memo must match exactly.')
  })
})
