import { describe, expect, it } from 'vitest'
import { formatTimeAgo, formatUtcTimestamp } from './time'

describe('time formatting', () => {
  it('formats a compact relative age', () => {
    const now = new Date('2026-04-09T12:00:00Z')

    expect(formatTimeAgo('2026-04-09T11:59:30Z', now)).toBe('just now')
    expect(formatTimeAgo('2026-04-09T11:55:00Z', now)).toBe('5m ago')
    expect(formatTimeAgo('2026-04-09T10:00:00Z', now)).toBe('2h ago')
    expect(formatTimeAgo('2026-04-06T12:00:00Z', now)).toBe('3d ago')
  })

  it('formats timestamps in stable UTC text', () => {
    expect(formatUtcTimestamp('2026-04-09T12:34:56Z')).toBe('2026-04-09 12:34:56 UTC')
  })
})
