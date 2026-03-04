import { useState } from 'react'
import { ConnectButton } from '@rainbow-me/rainbowkit'
import DepositFlow from './DepositFlow'
import WithdrawFlow from './WithdrawFlow'
import Explorer from './Explorer'
import ApiDocs from './ApiDocs'

type RightPanel = 'explorer' | 'docs'

export default function Layout() {
  const [tab, setTab] = useState<'deposit' | 'withdraw'>('deposit')
  const [rightPanel, setRightPanel] = useState<RightPanel>('explorer')

  return (
    <>
      <header>
        <div className="brand">
          <span className="brand-dot" />
          <span>Juno Bridge</span>
        </div>
        <ConnectButton showBalance={false} />
      </header>
      <div className="layout">
        <div className="panel-left">
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
