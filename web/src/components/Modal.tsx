import { useState, type ReactNode } from 'react'

interface Props {
  title: string
  trigger: ReactNode
  children: ReactNode
  onSubmit?: () => void
  onCancel?: () => void
  narrow?: boolean
  footer?: ReactNode
}

export default function Modal({ title, trigger, children, onSubmit, onCancel, narrow, footer }: Props) {
  const [open, setOpen] = useState(false)

  const close = () => {
    setOpen(false)
    onCancel?.()
  }

  return (
    <>
      <span onClick={() => setOpen(true)} style={{ display: 'inline-flex' }}>
        {trigger}
      </span>
      {open && (
        <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && close()}>
          <div className={`modal${narrow ? ' narrow' : ''}`} role="dialog" aria-modal="true">
            <div className="modal-head">
              <strong>{title}</strong>
              <button className="btn ghost sm" onClick={close} aria-label="Fermer">
                ✕
              </button>
            </div>
            <div className="modal-body">{children}</div>
            {(footer || onSubmit) && (
              <div className="modal-foot">
                <button className="btn" onClick={close}>
                  Annuler
                </button>
                {onSubmit && (
                  <button
                    className="btn primary"
                    onClick={() => {
                      onSubmit()
                      close()
                    }}
                  >
                    Confirmer
                  </button>
                )}
                {footer}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  )
}
