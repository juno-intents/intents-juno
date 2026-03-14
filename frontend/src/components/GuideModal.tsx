interface Props {
  open: boolean
  onClose: () => void
}

export default function GuideModal({ open, onClose }: Props) {
  if (!open) {
    return null
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content guide-modal" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">Bridge Guide</span>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body guide-body">
          <section>
            <h3>Juno -&gt; Base</h3>
            <p>Generate the deposit instructions, then send JUNO to the shielded bridge wallet with the exact memo shown.</p>
            <p>The amount field is optional. It only pre-fills the QR code and CLI example. The memo is mandatory.</p>
          </section>
          <section>
            <h3>Base -&gt; Juno</h3>
            <p>Connect the Base wallet holding wJUNO, approve the bridge if needed, then request the withdrawal to a Juno unified address.</p>
            <p>Use the recent-recipient chips if you repeat withdrawals to the same Juno wallet.</p>
          </section>
          <section>
            <h3>Safety Rules</h3>
            <p>Only use valid Base and Juno addresses. The bridge will reject deposits below the minimum and withdrawals below the minimum.</p>
            <p>Wait for the tracker to move to finalized before treating a bridge as complete.</p>
          </section>
        </div>
      </div>
    </div>
  )
}
