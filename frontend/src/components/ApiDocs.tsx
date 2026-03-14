import { runtimeConfig } from '../config/runtime'

export default function ApiDocs() {
  const baseUrl = runtimeConfig.apiBaseUrl || window.location.origin

  return (
    <div className="card api-docs">
      <h3>Bridge API Reference</h3>

      <div style={{ marginBottom: 16, padding: '8px 12px', background: 'var(--bg-card)', borderRadius: 6, border: '1px solid var(--border)' }}>
        <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>Base URL</span>
        <div className="mono" style={{ fontSize: 14, marginTop: 2 }}>{baseUrl}</div>
      </div>

      <h4 style={{ marginTop: 16, marginBottom: 8, color: 'var(--accent)' }}>Configuration</h4>
      <p><code>GET /v1/config</code> &mdash; Bridge configuration (chain ID, addresses, limits)</p>

      <h4 style={{ marginTop: 16, marginBottom: 8, color: 'var(--accent)' }}>Juno -&gt; Base</h4>
      <p><code>GET /v1/deposit-memo?baseRecipient=0x...</code> &mdash; Generate the memo and shielded deposit destination</p>
      <p><code>GET /v1/status/deposit/&#123;depositId&#125;</code> &mdash; Deposit status</p>
      <p><code>GET /v1/deposits?baseRecipient=0x...&amp;limit=20</code> &mdash; List deposits by recipient</p>
      <p><code>GET /v1/deposits?txHash=0x...</code> &mdash; Lookup deposit by tx hash</p>

      <h4 style={{ marginTop: 16, marginBottom: 8, color: 'var(--accent)' }}>Base -&gt; Juno</h4>
      <p><code>GET /v1/status/withdrawal/&#123;withdrawalId&#125;</code> &mdash; Withdrawal status</p>
      <p><code>GET /v1/withdrawals?requester=0x...&amp;limit=20</code> &mdash; List by requester</p>
      <p><code>GET /v1/withdrawals?junoTxId=...</code> &mdash; Lookup by Juno tx ID</p>
      <p><code>GET /v1/withdrawals?baseTxHash=0x...</code> &mdash; Lookup by Base tx hash</p>

      <h4 style={{ marginTop: 16, marginBottom: 8, color: 'var(--accent)' }}>Response Format</h4>
      <p>All responses include <code>"version": "v1"</code>.</p>
      <p>List endpoints return <code>&#123;"data": [...], "total": N, "limit": L, "offset": O&#125;</code>.</p>
      <p>Amounts are in zatoshi (1 JUNO = 10^8 zatoshi). IDs/hashes are 0x-prefixed hex.</p>
    </div>
  )
}
