import { useQuery } from '@tanstack/react-query'
import { getConfig, getDepositStatus, getWithdrawalStatus } from '../api/bridge'

export function useBridgeConfig() {
  return useQuery({
    queryKey: ['bridge-config'],
    queryFn: getConfig,
    staleTime: 60_000,
  })
}

export function useDepositStatus(depositId: string | undefined) {
  return useQuery({
    queryKey: ['deposit-status', depositId],
    queryFn: () => getDepositStatus(depositId!),
    enabled: !!depositId,
    refetchInterval: 5000,
  })
}

export function useWithdrawalStatus(withdrawalId: string | undefined) {
  return useQuery({
    queryKey: ['withdrawal-status', withdrawalId],
    queryFn: () => getWithdrawalStatus(withdrawalId!),
    enabled: !!withdrawalId,
    refetchInterval: 5000,
  })
}
