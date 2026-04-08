type Props = {
  onClick: () => void
  label?: string
  copied?: boolean
  copiedLabel?: string
}

function CopyGlyph() {
  return (
    <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path
        d="M7.5 5.83333C7.5 4.91286 8.24619 4.16667 9.16667 4.16667H14.1667C15.0871 4.16667 15.8333 4.91286 15.8333 5.83333V13.3333C15.8333 14.2538 15.0871 15 14.1667 15H9.16667C8.24619 15 7.5 14.2538 7.5 13.3333V5.83333Z"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="M4.16667 10.8333V6.66667C4.16667 5.74619 4.91286 5 5.83333 5H10"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  )
}

function CheckGlyph() {
  return (
    <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path
        d="M5 10.4167L8.33333 13.75L15 7.08334"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export default function CopyIconButton({
  onClick,
  label = 'Copy',
  copied = false,
  copiedLabel = 'Copied',
}: Props) {
  const accessibleLabel = copied ? copiedLabel : label

  return (
    <button
      className={`copy-btn ${copied ? 'is-copied' : ''}`}
      type="button"
      aria-label={accessibleLabel}
      title={accessibleLabel}
      onClick={onClick}
    >
      {copied ? <CheckGlyph /> : <CopyGlyph />}
    </button>
  )
}
