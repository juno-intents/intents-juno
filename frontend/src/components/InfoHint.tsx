interface Props {
  label: string
}

export default function InfoHint({ label }: Props) {
  return (
    <span className="info-hint" title={label} aria-label={label}>
      i
    </span>
  )
}
