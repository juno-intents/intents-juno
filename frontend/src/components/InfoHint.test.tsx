import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import InfoHint from './InfoHint'

describe('InfoHint', () => {
  it('renders a focusable trigger and tooltip content in the DOM', () => {
    const html = renderToStaticMarkup(
      <InfoHint label="Any Base address works. Leave this blank to use the currently connected wallet." />,
    )

    expect(html).toContain('type="button"')
    expect(html).toContain('role="tooltip"')
    expect(html).toContain('Any Base address works. Leave this blank to use the currently connected wallet.')
  })
})
