import { useState } from 'react'

interface Props {
  steps: string[]
  current: string
}

export default function StatusTracker({ steps, current }: Props) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null)
  const idx = steps.indexOf(current)
  const isFinalized = current === 'finalized'
  const isRejected = current === 'rejected'

  return (
    <div className="tracker-wrap">
      <div className="progress-track">
        {steps.map((step, i) => (
          <div
            key={i}
            className={`progress-step ${isFinalized ? 'done' : i < idx ? 'done' : i === idx ? 'active' : ''}`}
            onMouseEnter={() => setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
          >
            {hoveredIdx === i && (
              <div className="step-tooltip">{step}</div>
            )}
          </div>
        ))}
      </div>
      <div className="progress-label-row">
        <span className={isFinalized ? 'progress-label-done' : isRejected ? 'progress-label-rejected' : ''}>
          {isFinalized ? 'finalized' : current || steps[0]}
        </span>
      </div>
    </div>
  )
}
