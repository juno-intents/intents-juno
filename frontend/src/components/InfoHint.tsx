import { useEffect, useId, useRef, useState } from 'react'

interface Props {
  label: string
}

export default function InfoHint({ label }: Props) {
  const tooltipId = useId()
  const rootRef = useRef<HTMLSpanElement>(null)
  const touchHandledRef = useRef(false)
  const [hovered, setHovered] = useState(false)
  const [focused, setFocused] = useState(false)
  const [pinned, setPinned] = useState(false)

  const open = hovered || focused || pinned

  useEffect(() => {
    if (!open) {
      return undefined
    }

    const handlePointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        setHovered(false)
        setFocused(false)
        setPinned(false)
      }
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setHovered(false)
        setFocused(false)
        setPinned(false)
      }
    }

    document.addEventListener('pointerdown', handlePointerDown)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open])

  const togglePinned = () => {
    setPinned((current) => !current)
  }

  const handleClick = () => {
    if (touchHandledRef.current) {
      touchHandledRef.current = false
      return
    }
    togglePinned()
  }

  const handleTouchStart = (event: React.TouchEvent<HTMLButtonElement>) => {
    event.preventDefault()
    touchHandledRef.current = true
    togglePinned()
  }

  return (
    <span
      ref={rootRef}
      className="info-hint-wrap"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <button
        type="button"
        className={`info-hint ${open ? 'is-open' : ''}`}
        aria-label={label}
        aria-describedby={open ? tooltipId : undefined}
        aria-expanded={open}
        onFocus={() => setFocused(true)}
        onBlur={(event) => {
          if (!rootRef.current?.contains(event.relatedTarget as Node | null)) {
            setFocused(false)
          }
        }}
        onClick={handleClick}
        onTouchStart={handleTouchStart}
      >
        <span aria-hidden="true">i</span>
      </button>
      {open ? (
        <span id={tooltipId} className="info-hint-bubble" role="tooltip">
          {label}
        </span>
      ) : null}
    </span>
  )
}
