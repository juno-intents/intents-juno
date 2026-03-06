interface Props {
  steps: string[]
  current: string
}

export default function StatusTracker({ steps, current }: Props) {
  const idx = steps.indexOf(current)

  return (
    <div>
      <div className="progress-track">
        {steps.map((_, i) => (
          <div
            key={i}
            className={`progress-step ${i < idx ? 'done' : i === idx ? 'active' : ''}`}
          />
        ))}
      </div>
      <div className="progress-labels">
        <span>{steps[0]}</span>
        {idx > 0 && idx < steps.length - 1 && <span style={{ color: 'var(--accent)' }}>{steps[idx]}</span>}
        <span>{steps[steps.length - 1]}</span>
      </div>
    </div>
  )
}
