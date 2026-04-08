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
            <h3>Junocash (JUNO) -&gt; Base (wJUNO)</h3>
            <p>Generate the deposit instructions, then send native Junocash (JUNO) to the shielded bridge wallet with the exact full memo shown. The QR code only carries the destination and amount. Copy the memo separately and paste it exactly as shown.</p>
          </section>
          <section>
            <h3>Base (wJUNO) -&gt; Junocash (JUNO)</h3>
            <p>Connect the Base wallet holding Wrapped JUNO (wJUNO), approve the bridge if needed, then request the withdrawal to a Junocash native j1 address. Use the recent-recipient chips if you repeat withdrawals to the same Junocash wallet.</p>
          </section>
          <section>
            <h3>Safety Rules</h3>
            <p>Only use valid Base and Junocash j1 addresses. The bridge will not recognize deposits below the minimum and withdrawals below the minimum and those amounts will be PERMANENTLY lost and unrecoverable.</p>
            <p>Wait for the tracker to move to finalized before treating a bridge as complete.</p>
          </section>
        </div>
      </div>
    </div>
  )
}
