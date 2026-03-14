import { http } from 'wagmi'
import { getDefaultConfig } from '@rainbow-me/rainbowkit'
import { runtimeConfig } from './runtime'

export const config = getDefaultConfig({
  appName: 'Juno Bridge',
  projectId: runtimeConfig.walletConnectProjectId,
  chains: [runtimeConfig.baseChain],
  transports: {
    [runtimeConfig.baseChain.id]: http(),
  },
})
