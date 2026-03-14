import { describe, expect, it } from 'vitest'
import { resolveRuntimeConfig } from './runtimeConfig'

describe('resolveRuntimeConfig', () => {
  it('uses development defaults when local env is incomplete', () => {
    const cfg = resolveRuntimeConfig({ DEV: true })
    expect(cfg.baseChain.id).toBe(84532)
    expect(cfg.walletConnectProjectId).toBe('juno-bridge-dev')
  })

  it('rejects missing walletconnect project ids outside development', () => {
    expect(() =>
      resolveRuntimeConfig({
        DEV: false,
        MODE: 'production',
        VITE_BASE_CHAIN_ID: '8453',
      }),
    ).toThrow(/VITE_WALLETCONNECT_PROJECT_ID/)
  })

  it('rejects missing base chain ids outside development', () => {
    expect(() =>
      resolveRuntimeConfig({
        DEV: false,
        MODE: 'production',
        VITE_WALLETCONNECT_PROJECT_ID: 'wc-mainnet',
      }),
    ).toThrow(/VITE_BASE_CHAIN_ID/)
  })

  it('rejects unsupported base chain ids', () => {
    expect(() =>
      resolveRuntimeConfig({
        DEV: false,
        MODE: 'production',
        VITE_BASE_CHAIN_ID: '1',
        VITE_WALLETCONNECT_PROJECT_ID: 'wc-mainnet',
      }),
    ).toThrow(/unsupported Base chain id/)
  })

  it('builds a mainnet config when required env is present', () => {
    const cfg = resolveRuntimeConfig({
      DEV: false,
      MODE: 'production',
      VITE_BASE_CHAIN_ID: '8453',
      VITE_WALLETCONNECT_PROJECT_ID: 'wc-mainnet',
      VITE_BRIDGE_API_BASE_URL: 'https://bridge.example/',
    })
    expect(cfg.baseChain.id).toBe(8453)
    expect(cfg.walletConnectProjectId).toBe('wc-mainnet')
    expect(cfg.apiBaseUrl).toBe('https://bridge.example')
    expect(cfg.isMainnet).toBe(true)
  })
})
