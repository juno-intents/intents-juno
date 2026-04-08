import { base, baseSepolia } from 'wagmi/chains'
import { baseChainDisplayName, junoNetworkLabel, normalizeApiBase } from '../lib/bridgeUi'

type RuntimeEnv = {
  DEV?: boolean
  MODE?: string
  VITE_BASE_CHAIN_ID?: string
  VITE_BRIDGE_API_BASE_URL?: string
  VITE_BRIDGE_DEV_PROXY_TARGET?: string
  VITE_WALLETCONNECT_PROJECT_ID?: string
}

function resolveBaseChain(chainIDRaw: string, isDev: boolean) {
  if (chainIDRaw === '') {
    if (isDev) {
      return baseSepolia
    }
    throw new Error('VITE_BASE_CHAIN_ID is required outside development')
  }
  const chainID = Number(chainIDRaw)
  if (chainID === base.id) {
    return base
  }
  if (chainID === baseSepolia.id) {
    return baseSepolia
  }
  throw new Error(`unsupported Base chain id: ${chainIDRaw}`)
}

function resolveWalletConnectProjectID(projectIDRaw: string, isDev: boolean): string {
  if (projectIDRaw !== '') {
    return projectIDRaw
  }
  if (isDev) {
    return 'juno-bridge-dev'
  }
  throw new Error('VITE_WALLETCONNECT_PROJECT_ID is required outside development')
}

export function resolveRuntimeConfig(env: RuntimeEnv) {
  const isDev = env.DEV === true || env.MODE === 'development'
  const baseChain = resolveBaseChain((env.VITE_BASE_CHAIN_ID ?? '').trim(), isDev)
  const walletConnectProjectId = resolveWalletConnectProjectID(
    (env.VITE_WALLETCONNECT_PROJECT_ID ?? '').trim(),
    isDev,
  )

  return {
    apiBaseUrl: normalizeApiBase(env.VITE_BRIDGE_API_BASE_URL),
    devProxyTarget: normalizeApiBase(env.VITE_BRIDGE_DEV_PROXY_TARGET) || 'http://localhost:19693',
    walletConnectProjectId,
    baseChain,
    isMainnet: baseChain.id === base.id,
    baseChainDisplayName: baseChainDisplayName(baseChain.id),
    junoNetworkLabel: junoNetworkLabel(baseChain.id),
    junoCliModeFlag: baseChain.id === base.id ? '' : '-testnet ',
    baseLogoUrl: '/wjuno-token.svg',
    junoLogoUrl: '/junocash-logo.svg',
  }
}
