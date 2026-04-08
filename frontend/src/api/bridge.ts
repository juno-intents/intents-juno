import type { BridgeConfig, DepositMemo, DepositStatus, WithdrawalStatus, ListResponse } from './types'
import { runtimeConfig } from '../config/runtime'

const BASE = runtimeConfig.apiBaseUrl

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path)
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`)
  return res.json() as Promise<T>
}

export async function getConfig(): Promise<BridgeConfig> {
  return get('/v1/config')
}

export async function getDepositMemo(baseRecipient: string, nonce?: string): Promise<DepositMemo> {
  const params = new URLSearchParams({ baseRecipient })
  if (nonce) params.set('nonce', nonce)
  return get(`/v1/deposit-memo?${params}`)
}

export async function getDepositStatus(depositId: string): Promise<DepositStatus> {
  return get(`/v1/status/deposit/${depositId}`)
}

export async function getWithdrawalStatus(withdrawalId: string): Promise<WithdrawalStatus> {
  return get(`/v1/status/withdrawal/${withdrawalId}`)
}

export async function listDeposits(params: Record<string, string>): Promise<ListResponse<DepositStatus>> {
  const qs = new URLSearchParams(params)
  return get(`/v1/deposits?${qs}`)
}

export async function listWithdrawals(params: Record<string, string>): Promise<ListResponse<WithdrawalStatus>> {
  const qs = new URLSearchParams(params)
  return get(`/v1/withdrawals?${qs}`)
}

export async function listRecentDeposits(params: Record<string, string> = {}): Promise<ListResponse<DepositStatus>> {
  const qs = new URLSearchParams(params)
  return get(`/v1/deposits/recent?${qs}`)
}

export async function listRecentWithdrawals(params: Record<string, string> = {}): Promise<ListResponse<WithdrawalStatus>> {
  const qs = new URLSearchParams(params)
  return get(`/v1/withdrawals/recent?${qs}`)
}

export async function decodeRecipient(ua: string): Promise<string> {
  const resp = await fetch(`${BASE}/v1/decode-recipient?ua=${encodeURIComponent(ua)}`)
  const data = await resp.json()
  if (data.error) throw new Error(data.detail || data.error)
  return data.orchardReceiver
}
