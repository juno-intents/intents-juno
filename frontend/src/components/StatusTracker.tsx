interface Props {
  steps: string[]
  current: string
  confirmations?: number
  requiredConfirmations?: number
}

export default function StatusTracker({ steps, current, confirmations, requiredConfirmations }: Props) {
  const idx = steps.indexOf(current)
  const isFinalized = current === 'finalized'
  const isRejected = current === 'rejected'
  const showConfirmations = current === 'seen' && confirmations !== undefined && requiredConfirmations !== undefined
  const label = showConfirmations
    ? `seen - pending ${requiredConfirmations} confirmations`
    : (isFinalized ? 'finalized' : current || steps[0])

  return (
    <div className="tracker-wrap">
      <div className="progress-track">
        {steps.map((step, i) => {
          const stateClass = isFinalized ? 'done' : i < idx ? 'done' : i === idx ? 'active' : ''

          return (
            <div key={step} className="progress-step-shell">
              <div
                className={`progress-step-hitbox ${stateClass}`.trim()}
                tabIndex={0}
                aria-label={`Status step ${i + 1} of ${steps.length}: ${step}`}
                aria-current={i === idx ? 'step' : undefined}
              >
                <div className={`progress-step ${stateClass}`.trim()} />
                <div className="progress-step-tooltip" role="tooltip">
                  {step}
                </div>
              </div>
            </div>
          )
        })}
      </div>
      <div className="progress-label-row">
        <span className={isFinalized ? 'progress-label-done' : isRejected ? 'progress-label-rejected' : ''}>
          {label}
        </span>
      </div>
    </div>
  )
}
