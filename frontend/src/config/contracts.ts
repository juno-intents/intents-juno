export const WJUNO_ABI = [
  {
    name: 'balanceOf',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'approve',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'allowance',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    outputs: [{ name: '', type: 'uint256' }],
  },
] as const

export const BRIDGE_ABI = [
  {
    name: 'requestWithdraw',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'amount', type: 'uint256' },
      { name: 'recipientUA', type: 'bytes' },
    ],
    outputs: [],
  },
] as const

export interface PublicContractLink {
  name: string
  address: string
}

const MAINNET_PUBLIC_CONTRACTS: PublicContractLink[] = [
  { name: 'WJuno', address: '0x2E8F83541AB39C8451b3e557A19bE531a59DdECc' },
  { name: 'OperatorRegistry', address: '0xC375bE4952cd7B43c0F5C0dC70179659763D0007' },
  { name: 'FeeDistributor', address: '0x8366284b1B7e164922e1574EE041084d0E93f69b' },
  { name: 'Bridge', address: '0x0F65702343DE210098c2d83302B96E516CE3072f' },
  { name: 'Timelock', address: '0xAB23F34ce3F087D24B28807c43042b548eF8263E' },
]

export function publicContractsForChain(chainId: number | undefined): PublicContractLink[] {
  if (chainId === 8453) {
    return MAINNET_PUBLIC_CONTRACTS
  }
  return []
}
