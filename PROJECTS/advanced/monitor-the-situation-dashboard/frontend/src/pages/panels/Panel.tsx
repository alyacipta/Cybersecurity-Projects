// ©AngelaMos | 2026
// Panel.tsx

import type { ReactNode } from 'react'
import { FiExternalLink } from 'react-icons/fi'
import styles from './Panel.module.scss'
import { StaleIndicator } from './shared/StaleIndicator'

export interface PanelProps {
  title: string
  subtitle?: string
  rawHref?: string
  rawLabel?: string
  isStale?: boolean
  lastTickAt?: number
  children: ReactNode
}

export function Panel({
  title,
  subtitle,
  rawHref,
  rawLabel,
  isStale,
  lastTickAt,
  children,
}: PanelProps): React.ReactElement {
  return (
    <article className={styles.panel}>
      <header className={styles.head}>
        <span className={styles.title}>
          {title}
          {subtitle && <span className={styles.subtitle}> · {subtitle}</span>}
        </span>
        <span className={styles.meta}>
          <StaleIndicator stale={isStale} lastTickAt={lastTickAt} />
          {rawHref && (
            <a
              className={styles.rawLink}
              href={rawHref}
              target="_blank"
              rel="noreferrer noopener"
              aria-label={rawLabel ?? 'Raw source'}
            >
              <FiExternalLink aria-hidden />
            </a>
          )}
        </span>
      </header>
      <div className={styles.body}>{children}</div>
    </article>
  )
}

Panel.displayName = 'Panel'
