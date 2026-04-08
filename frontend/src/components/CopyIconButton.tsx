type Props = {
  onClick: () => void
  label?: string
  copied?: boolean
  copiedLabel?: string
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
      {copied ? (
        <CheckGlyph />
      ) : (
        <img
          className="copy-btn-icon"
          width="24"
          height="24"
          src="https://img.icons8.com/material-outlined/24/FFFFFF/copy.png"
          alt="copy"
        />
      )}
    </button>
  )
}
