import { base, baseSepolia } from 'wagmi/chains'
import { baseChainDisplayName, junoNetworkLabel, normalizeApiBase } from '../lib/bridgeUi'

const envBaseChainId = Number(import.meta.env.VITE_BASE_CHAIN_ID || baseSepolia.id)
const selectedBaseChain = envBaseChainId === base.id ? base : baseSepolia

export const runtimeConfig = {
  apiBaseUrl: normalizeApiBase(import.meta.env.VITE_BRIDGE_API_BASE_URL),
  devProxyTarget: normalizeApiBase(import.meta.env.VITE_BRIDGE_DEV_PROXY_TARGET) || 'http://localhost:19693',
  walletConnectProjectId: (import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'juno-bridge').trim(),
  baseChain: selectedBaseChain,
  isMainnet: selectedBaseChain.id === base.id,
  baseChainDisplayName: baseChainDisplayName(selectedBaseChain.id),
  junoNetworkLabel: junoNetworkLabel(selectedBaseChain.id),
  junoCliModeFlag: selectedBaseChain.id === base.id ? '' : '-testnet ',
  baseLogoUrl: 'https://base.org/document/favicon-32x32.png',
  junoLogoUrl: 'https://juno.cash/icon.png?icon.b901cfc8.png',
}
