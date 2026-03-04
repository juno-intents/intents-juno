export interface BridgeConfig {
  version: string
  baseChainId: number
  bridgeAddress: string
  wjunoAddress?: string
  oWalletUA: string
  refundWindowSeconds: number
  minDepositAmount: string
  minWithdrawAmount: string
}

export interface DepositMemo {
  version: string
  baseRecipient: string
  oWalletUA: string
  nonce: string
  memoHex: string
  memoBase64: string
}

export interface DepositStatus {
  version: string
  found: boolean
  depositId: string
  state: string
  amount: string
  baseRecipient: string
  txHash: string
}

export interface WithdrawalStatus {
  version: string
  found: boolean
  withdrawalId: string
  state: string
  amount: string
  feeBps: number
  requester: string
  expiry: string
  batchId: string
  junoTxId: string
  baseTxHash: string
}

export interface ListResponse<T> {
  version: string
  data: T[]
  total: number
  limit: number
  offset: number
}
