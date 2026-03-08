import { http } from 'wagmi'
import { baseSepolia } from 'wagmi/chains'
import { getDefaultConfig } from '@rainbow-me/rainbowkit'

export const config = getDefaultConfig({
  appName: 'Juno Bridge',
  projectId: 'juno-bridge', // WalletConnect project ID placeholder
  chains: [baseSepolia],
  transports: {
    [baseSepolia.id]: http(),
  },
})
