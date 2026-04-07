import { parseUnits } from 'viem'

const BASE_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/
const JUNO_MAINNET_UNIFIED_ADDRESS_RE = /^j1[02-9ac-hj-np-z]+$/
const JUNO_TESTNET_UNIFIED_ADDRESS_RE = /^jtest1[02-9ac-hj-np-z]+$/

const RECENT_LIMIT = 5

function trimAmount(raw: string): string {
  return raw.trim()
}

function decimalPlaces(raw: string): number {
  const trimmed = trimAmount(raw)
  if (!trimmed.includes('.')) {
    return 0
  }
  return trimmed.split('.')[1]?.length ?? 0
}

export function parseAmountToZats(raw: string): bigint | null {
  const trimmed = trimAmount(raw)
  if (trimmed === '') {
    return null
  }
  try {
    return parseUnits(trimmed, 8)
  } catch {
    return null
  }
}

function parseRawZats(raw: string | undefined): bigint | null {
  const trimmed = (raw ?? '').trim()
  if (trimmed === '') {
    return null
  }
  try {
    return BigInt(trimmed)
  } catch {
    return null
  }
}

export function validateBaseRecipient(input: string, connectedAddress?: string): string | null {
  const candidate = input.trim() || connectedAddress?.trim() || ''
  if (candidate === '') {
    return 'Enter a Base recipient address or connect a wallet.'
  }
  if (!BASE_ADDRESS_RE.test(candidate)) {
    return 'Enter a valid Base address.'
  }
  return null
}

export function validateDepositAmount(input: string, minDepositAmount?: string): string | null {
  const trimmed = trimAmount(input)
  if (trimmed === '') {
    return 'Enter a deposit amount.'
  }
  if (decimalPlaces(trimmed) > 8) {
    return 'JUNO amounts support up to 8 decimal places.'
  }
  const amount = parseAmountToZats(trimmed)
  if (amount === null || amount <= 0n) {
    return 'Enter a valid deposit amount.'
  }
  const min = parseRawZats(minDepositAmount)
  if (min !== null && amount < min) {
    return 'Deposit amount is below the bridge minimum.'
  }
  return null
}

export function validateWithdrawAmount(
  input: string,
  minWithdrawAmount?: string,
  maxBalance?: bigint,
): string | null {
  const trimmed = trimAmount(input)
  if (trimmed === '') {
    return 'Enter a withdrawal amount.'
  }
  if (decimalPlaces(trimmed) > 8) {
    return 'JUNO amounts support up to 8 decimal places.'
  }
  const amount = parseAmountToZats(trimmed)
  if (amount === null || amount <= 0n) {
    return 'Enter a valid withdrawal amount.'
  }
  const min = parseRawZats(minWithdrawAmount)
  if (min !== null && amount < min) {
    return 'Withdrawal amount is below the bridge minimum.'
  }
  if (maxBalance !== undefined && amount > maxBalance) {
    return 'Withdrawal amount exceeds your available wJUNO balance.'
  }
  return null
}

export function validateJunoRecipient(input: string, baseChainId?: number): string | null {
  const trimmed = input.trim()
  if (trimmed === '') {
    return 'Enter a Juno recipient address.'
  }
  const addressPattern = baseChainId === 8453 ? JUNO_MAINNET_UNIFIED_ADDRESS_RE : JUNO_TESTNET_UNIFIED_ADDRESS_RE
  if (!addressPattern.test(trimmed)) {
    return 'Enter a valid Juno unified address.'
  }
  return null
}

export function upsertRecentRecipients(existing: string[], nextValue: string): string[] {
  const next = nextValue.trim()
  if (next === '') {
    return existing
  }
  const deduped = [next, ...existing.filter((value) => value !== next)]
  return deduped.slice(0, RECENT_LIMIT)
}

export function normalizeApiBase(raw: string | undefined): string {
  return (raw ?? '').trim().replace(/\/+$/, '')
}

export function baseChainDisplayName(chainId: number | undefined): string {
  if (chainId === 8453) {
    return 'Base Mainnet'
  }
  if (chainId === 84532) {
    return 'Base Sepolia'
  }
  if (typeof chainId === 'number' && Number.isFinite(chainId)) {
    return `Base Chain ${chainId}`
  }
  return 'Base'
}

export function junoNetworkLabel(chainId: number | undefined): string {
  return chainId === 8453 ? 'Juno Mainnet' : 'Juno Testnet'
}
