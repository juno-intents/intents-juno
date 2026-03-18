import { useId } from 'react'

interface Props {
  label: string
}

export default function InfoHint({ label }: Props) {
  const tooltipId = useId()

  return (
    <span className="info-hint-wrap">
      <button type="button" className="info-hint" aria-label={label} aria-describedby={tooltipId}>
        <span aria-hidden="true">i</span>
      </button>
      <span id={tooltipId} className="info-hint-bubble" role="tooltip">
        {label}
      </span>
    </span>
  )
}
