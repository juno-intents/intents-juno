import { useState } from 'react'
import { ConnectButton } from '@rainbow-me/rainbowkit'
import { useQuery } from '@tanstack/react-query'
import { getConfig } from '../api/bridge'
import DepositFlow from './DepositFlow'
import WithdrawFlow from './WithdrawFlow'
import Explorer from './Explorer'
import ApiDocs from './ApiDocs'

type RightPanel = 'explorer' | 'docs'

export default function Layout() {
  const [tab, setTab] = useState<'deposit' | 'withdraw'>('deposit')
  const [rightPanel, setRightPanel] = useState<RightPanel>('explorer')

  const { data: cfg } = useQuery({
    queryKey: ['bridge-config'],
    queryFn: getConfig,
  })

  const chainLabel = cfg?.baseChainId === 8453 ? 'BASE MAINNET' : cfg?.baseChainId === 84532 ? 'BASE SEPOLIA' : cfg ? `CHAIN ${cfg.baseChainId}` : ''

  return (
    <>
      <header>
        <div className="header-left">
          <div className="brand">
            <span className="brand-dot" />
            <span>JUNO INTENTS</span>
          </div>
          {chainLabel && (
            <span className="status-pill">
              <span className="dot" />
              {chainLabel}
            </span>
          )}
        </div>
        <ConnectButton showBalance={false} />
      </header>
      <div className="layout">
        <div className="panel-left">
          <div className="section-label">Core Bridge</div>
          <div className="section-title">Transfer Assets</div>
          <div className="pill-tabs" style={{ marginBottom: 20 }}>
            <button className={`pill-tab ${tab === 'deposit' ? 'active' : ''}`} onClick={() => setTab('deposit')}>
              Deposit
            </button>
            <button className={`pill-tab ${tab === 'withdraw' ? 'active' : ''}`} onClick={() => setTab('withdraw')}>
              Withdraw
            </button>
          </div>
          {tab === 'deposit' ? <DepositFlow /> : <WithdrawFlow />}
        </div>
        <div className="panel-right">
          <div className="section-label">Bridge</div>
          <div className="pill-tabs" style={{ marginBottom: 20 }}>
            <button className={`pill-tab ${rightPanel === 'explorer' ? 'active' : ''}`} onClick={() => setRightPanel('explorer')}>
              Explorer
            </button>
            <button className={`pill-tab ${rightPanel === 'docs' ? 'active' : ''}`} onClick={() => setRightPanel('docs')}>
              API Docs
            </button>
          </div>
          {rightPanel === 'explorer' ? <Explorer /> : <ApiDocs />}
        </div>
      </div>
    </>
  )
}
