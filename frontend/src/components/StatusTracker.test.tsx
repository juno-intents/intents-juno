import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import StatusTracker from './StatusTracker'

describe('StatusTracker', () => {
  it('renders per-step tooltip content so hover can reveal it without JS state', () => {
    const html = renderToStaticMarkup(
      <StatusTracker
        steps={['pending', 'submitted', 'finalized']}
        current="submitted"
      />,
    )

    expect(html).toContain('progress-step-hitbox')
    expect(html).toContain('progress-step-tooltip')
    expect(html).toContain('pending')
    expect(html).toContain('submitted')
    expect(html).toContain('finalized')
  })
})
