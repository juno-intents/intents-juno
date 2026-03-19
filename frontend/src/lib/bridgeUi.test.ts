import { describe, expect, it } from 'vitest'
import {
  baseChainDisplayName,
  normalizeApiBase,
  parseAmountToZats,
  upsertRecentRecipients,
  validateBaseRecipient,
  validateDepositAmount,
  validateJunoRecipient,
  validateWithdrawAmount,
} from './bridgeUi'

describe('bridgeUi', () => {
  it('requires a deposit amount', () => {
    expect(validateDepositAmount('', '201005025')).toMatch(/Enter a deposit amount/)
  })

  it('rejects deposit amounts with too many decimals', () => {
    expect(validateDepositAmount('1.000000001', '201005025')).toMatch(/8 decimal/)
  })

  it('rejects deposits below the configured minimum', () => {
    expect(validateDepositAmount('1.0', '201005025')).toMatch(/below the bridge minimum/)
  })

  it('validates base recipients with wallet fallback', () => {
    expect(validateBaseRecipient('', '0x1234567890123456789012345678901234567890')).toBeNull()
    expect(validateBaseRecipient('0xnotreal', undefined)).toMatch(/valid Base address/)
  })

  it('validates withdraw amounts against balance and minimum', () => {
    expect(validateWithdrawAmount('', '100000000', 10n)).toMatch(/Enter a withdrawal amount/)
    expect(validateWithdrawAmount('1.000000001', '100000000', 10n)).toMatch(/8 decimal/)
    expect(validateWithdrawAmount('0.5', '100000000', 1000000000n)).toMatch(/below the bridge minimum/)
    expect(validateWithdrawAmount('20', '100000000', 1000000000n)).toMatch(/exceeds your available/)
    expect(validateWithdrawAmount('1', '100000000', 1000000000n)).toBeNull()
  })

  it('validates juno unified address shape', () => {
    expect(validateJunoRecipient('')).toMatch(/Enter a Juno recipient/)
    expect(validateJunoRecipient('jtest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq')).toBeNull()
    expect(validateJunoRecipient('not-an-address')).toMatch(/valid Juno unified address/)
  })

  it('dedupes and caps recent recipients', () => {
    const next = upsertRecentRecipients(
      ['jtest1b', 'jtest1c', 'jtest1d', 'jtest1e', 'jtest1f'],
      'jtest1c',
    )
    expect(next).toEqual(['jtest1c', 'jtest1b', 'jtest1d', 'jtest1e', 'jtest1f'])
  })

  it('normalizes api base urls', () => {
    expect(normalizeApiBase('https://bridge.preview.example///')).toBe('https://bridge.preview.example')
  })

  it('parses amounts to zats', () => {
    expect(parseAmountToZats('1.23456789')).toBe(123456789n)
    expect(parseAmountToZats('')).toBeNull()
  })

  it('formats friendly chain labels', () => {
    expect(baseChainDisplayName(8453)).toBe('Base Mainnet')
    expect(baseChainDisplayName(84532)).toBe('Base Sepolia')
    expect(baseChainDisplayName(999)).toBe('Base Chain 999')
  })
})
