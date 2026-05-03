// ©AngelaMos | 2026
// BottomTicker.tsx

import { useTicker } from '@/stores/ticker'
import styles from './BottomTicker.module.scss'

const MS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600

export function BottomTicker(): React.ReactElement {
  const items = useTicker((s) => s.items)
  return (
    <div className={styles.ticker}>
      {items.length > 0 && (
        <div className={styles.track}>
          {items.map((item) => (
            <span key={item.id} className={styles.item}>
              <span className={styles.source}>{item.source}</span>
              <span>{item.headline}</span>
              <span className={styles.ts}>{formatRel(item.ts)}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

BottomTicker.displayName = 'BottomTicker'

function formatRel(ts: number): string {
  const diff = (Date.now() - ts) / MS_PER_SECOND
  if (diff < SECONDS_PER_MINUTE) {
    return `${Math.floor(diff)}s ago`
  }
  if (diff < SECONDS_PER_HOUR) {
    return `${Math.floor(diff / SECONDS_PER_MINUTE)}m ago`
  }
  return `${Math.floor(diff / SECONDS_PER_HOUR)}h ago`
}
