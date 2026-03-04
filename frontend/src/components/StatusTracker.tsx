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
        {steps.map((s) => (
          <span key={s}>{s}</span>
        ))}
      </div>
    </div>
  )
}
