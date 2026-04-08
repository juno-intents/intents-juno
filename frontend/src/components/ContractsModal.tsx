import { publicContractsForChain } from '../config/contracts'
import { basescanAddressUrl } from '../lib/bridgeUi'

interface Props {
  open: boolean
  chainId?: number
  onClose: () => void
}

export default function ContractsModal({ open, chainId, onClose }: Props) {
  if (!open) {
    return null
  }

  const contracts = publicContractsForChain(chainId)

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content contracts-modal" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">Contracts</span>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body contracts-body">
          {contracts.length === 0 ? (
            <div className="empty-state">No public contract set is configured for this chain.</div>
          ) : (
            contracts.map((contract) => (
              <div className="contract-row" key={contract.address}>
                <div className="contract-name">{contract.name}</div>
                <a
                  className="contract-link mono"
                  href={basescanAddressUrl(contract.address)}
                  target="_blank"
                  rel="noreferrer"
                >
                  {contract.address}
                </a>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
