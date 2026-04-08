import { useState } from 'react'
import { ConnectButton } from '@rainbow-me/rainbowkit'
import { useQuery } from '@tanstack/react-query'
import { getConfig } from '../api/bridge'
import DepositFlow from './DepositFlow'
import WithdrawFlow from './WithdrawFlow'
import Explorer from './Explorer'
import NetworkActivity from './NetworkActivity'
import ApiDocs from './ApiDocs'
import GuideModal from './GuideModal'
import ContractsModal from './ContractsModal'
import { runtimeConfig } from '../config/runtime'
import { baseChainDisplayName } from '../lib/bridgeUi'

type RightPanel = 'my-activity' | 'recent-activity' | 'docs'

export default function Layout() {
  const [tab, setTab] = useState<'deposit' | 'withdraw'>('deposit')
  const [rightPanel, setRightPanel] = useState<RightPanel>('my-activity')
  const [guideOpen, setGuideOpen] = useState(false)
  const [contractsOpen, setContractsOpen] = useState(false)

  const { data: cfg } = useQuery({
    queryKey: ['bridge-config'],
    queryFn: getConfig,
  })

  const chainLabel = baseChainDisplayName(cfg?.baseChainId ?? runtimeConfig.baseChain.id)

  return (
    <>
      <header>
        <div className="header-left">
          <div className="brand">
            <img className="brand-logo" src={runtimeConfig.junoLogoUrl} alt="Junocash" />
            <span>JUNOCASH BRIDGE</span>
          </div>
          {chainLabel && (
            <span className="status-pill">
              <span className="dot" />
              {chainLabel}
            </span>
          )}
          <span className="status-pill status-pill-neutral">{runtimeConfig.junoNetworkLabel}</span>
        </div>
        <div className="header-actions">
          <button className="secondary-btn" onClick={() => setGuideOpen(true)}>
            Guide
          </button>
          <a className="secondary-btn" href="/whitepaper.pdf" target="_blank" rel="noreferrer">
            Whitepaper
          </a>
          <button className="secondary-btn" onClick={() => setContractsOpen(true)}>
            Contracts
          </button>
          <ConnectButton showBalance={false} />
        </div>
      </header>
      <div className="layout">
        <div className="panel-left">
          <div className="section-label">Core Bridge</div>
          <div className="section-title">Bridge Assets</div>
          <div className="pill-tabs" style={{ marginBottom: 20 }}>
            <button className={`pill-tab ${tab === 'deposit' ? 'active' : ''}`} onClick={() => setTab('deposit')}>
              Junocash -&gt; Base
            </button>
            <button className={`pill-tab ${tab === 'withdraw' ? 'active' : ''}`} onClick={() => setTab('withdraw')}>
              Base -&gt; Junocash
            </button>
          </div>
          {tab === 'deposit' ? <DepositFlow /> : <WithdrawFlow />}
        </div>
        <div className="panel-right">
          <div className="section-label">Activity</div>
          <div className="pill-tabs" style={{ marginBottom: 20 }}>
            <button className={`pill-tab ${rightPanel === 'my-activity' ? 'active' : ''}`} onClick={() => setRightPanel('my-activity')}>
              My Activity
            </button>
            <button className={`pill-tab ${rightPanel === 'recent-activity' ? 'active' : ''}`} onClick={() => setRightPanel('recent-activity')}>
              Recent Activity
            </button>
            <button className={`pill-tab ${rightPanel === 'docs' ? 'active' : ''}`} onClick={() => setRightPanel('docs')}>
              API Docs
            </button>
          </div>
          {rightPanel === 'my-activity' ? <Explorer /> : rightPanel === 'recent-activity' ? <NetworkActivity /> : <ApiDocs />}
        </div>
      </div>
      <GuideModal open={guideOpen} onClose={() => setGuideOpen(false)} />
      <ContractsModal open={contractsOpen} chainId={cfg?.baseChainId ?? runtimeConfig.baseChain.id} onClose={() => setContractsOpen(false)} />
    </>
  )
}
