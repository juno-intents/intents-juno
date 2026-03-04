import { useReadContract } from 'wagmi'
import { WJUNO_ABI } from '../config/contracts'

export function useWJunoBalance(wjunoAddress: string | undefined, account: string | undefined) {
  return useReadContract({
    address: wjunoAddress as `0x${string}` | undefined,
    abi: WJUNO_ABI,
    functionName: 'balanceOf',
    args: account ? [account as `0x${string}`] : undefined,
    query: { enabled: !!wjunoAddress && !!account, refetchInterval: 10_000 },
  })
}
