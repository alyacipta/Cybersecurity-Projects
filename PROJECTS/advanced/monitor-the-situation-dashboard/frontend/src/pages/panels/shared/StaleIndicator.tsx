// ©AngelaMos | 2026
// StaleIndicator.tsx

import styles from './StaleIndicator.module.scss'

export interface StaleIndicatorProps {
  stale?: boolean
  lastTickAt?: number
}

export function StaleIndicator({
  stale,
  lastTickAt,
}: StaleIndicatorProps): React.ReactElement {
  const className =
    stale === undefined
      ? `${styles.dot} ${styles.unknown}`
      : stale
        ? `${styles.dot} ${styles.stale}`
        : `${styles.dot} ${styles.live}`

  const title = lastTickAt
    ? `Last update ${new Date(lastTickAt).toISOString().slice(11, 19)} UTC`
    : undefined

  return <span className={className} title={title} aria-hidden />
}

StaleIndicator.displayName = 'StaleIndicator'
