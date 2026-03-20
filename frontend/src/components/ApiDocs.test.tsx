import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import ApiDocs from './ApiDocs'

vi.mock('../config/runtime', () => ({
  runtimeConfig: {
    apiBaseUrl: 'https://bridge.preview.intents-testing.thejunowallet.com',
  },
}))

describe('ApiDocs', () => {
  it('uses Monetas in the public amount description', () => {
    render(<ApiDocs />)

    expect(screen.getByText(/Amounts are in Monetas \(1 JUNO = 10\^8 Monetas\)/i)).toBeInTheDocument()
    expect(screen.queryByText(/zatoshi/i)).not.toBeInTheDocument()
  })
})
