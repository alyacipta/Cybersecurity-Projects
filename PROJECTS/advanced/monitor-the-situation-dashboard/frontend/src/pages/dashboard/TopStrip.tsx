// ©AngelaMos | 2026
// TopStrip.tsx

import { useEffect, useState } from 'react'
import { FiHelpCircle, FiSettings, FiUser } from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'
import { ROUTES } from '@/config'
import { useAuthStore } from '@/core/lib/auth.store'
import { useUIStore } from '@/stores/ui'
import styles from './TopStrip.module.scss'

const CLOCK_TICK_MS = 1000

export function TopStrip(): React.ReactElement | null {
  const [now, setNow] = useState(() => new Date())
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const openAbout = useUIStore((s) => s.openAbout)
  const isPresentation = useUIStore((s) => s.presentationMode)
  const navigate = useNavigate()

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), CLOCK_TICK_MS)
    return () => clearInterval(id)
  }, [])

  if (isPresentation) return null

  return (
    <header className={styles.strip}>
      <div className={styles.left}>
        <span className={styles.title}>MONITORING THE SITUATION</span>
        <button
          type="button"
          className={styles.iconButton}
          onClick={openAbout}
          aria-label="About"
        >
          <FiHelpCircle aria-hidden />
        </button>
      </div>

      <div className={styles.clock}>{formatUTC(now)}</div>

      <div className={styles.right}>
        {isAuthenticated ? (
          <button
            type="button"
            className={styles.iconButton}
            onClick={() => navigate(ROUTES.SETTINGS)}
            aria-label="Preferences"
          >
            <FiSettings aria-hidden />
          </button>
        ) : (
          <button
            type="button"
            className={styles.iconButton}
            onClick={() => navigate(ROUTES.LOGIN)}
            aria-label="Login"
          >
            <FiUser aria-hidden />
          </button>
        )}
      </div>
    </header>
  )
}

TopStrip.displayName = 'TopStrip'

function formatUTC(d: Date): string {
  return `${d.toISOString().slice(11, 19)} UTC`
}
