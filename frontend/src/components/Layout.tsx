import { useState } from 'react'
import { ConnectButton } from '@rainbow-me/rainbowkit'
import { useQuery } from '@tanstack/react-query'
import { getConfig } from '../api/bridge'
import DepositFlow from './DepositFlow'
import WithdrawFlow from './WithdrawFlow'
import Explorer from './Explorer'
import ApiDocs from './ApiDocs'
import GuideModal from './GuideModal'
import { runtimeConfig } from '../config/runtime'
import { baseChainDisplayName } from '../lib/bridgeUi'

type RightPanel = 'explorer' | 'docs'

export default function Layout() {
  const [tab, setTab] = useState<'deposit' | 'withdraw'>('deposit')
  const [rightPanel, setRightPanel] = useState<RightPanel>('explorer')
  const [guideOpen, setGuideOpen] = useState(false)

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
            <img className="brand-logo" src={runtimeConfig.junoLogoUrl} alt="Juno" />
            <span>JUNO BRIDGE</span>
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
          <ConnectButton showBalance={false} />
        </div>
      </header>
      <div className="layout">
        <div className="panel-left">
          <div className="section-label">Core Bridge</div>
          <div className="section-title">Bridge Assets</div>
          <div className="pill-tabs" style={{ marginBottom: 20 }}>
            <button className={`pill-tab ${tab === 'deposit' ? 'active' : ''}`} onClick={() => setTab('deposit')}>
              Juno -&gt; Base
            </button>
            <button className={`pill-tab ${tab === 'withdraw' ? 'active' : ''}`} onClick={() => setTab('withdraw')}>
              Base -&gt; Juno
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
      <GuideModal open={guideOpen} onClose={() => setGuideOpen(false)} />
    </>
  )
}
