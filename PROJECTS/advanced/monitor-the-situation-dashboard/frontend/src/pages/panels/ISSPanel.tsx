// ©AngelaMos | 2026
// ISSPanel.tsx

import { useSnapshot } from '@/api/snapshot'
import styles from './ISSPanel.module.scss'
import { Panel } from './Panel'

const STALE_AFTER_MS = 30_000
const COORDS_DECIMALS = 2
const ALT_DECIMALS = 0

interface IssPositionData {
  latitude: number
  longitude: number
  altitude: number
  velocity: number
  timestamp: number
  fetched_at?: string
}

export function ISSPanel(): React.ReactElement {
  const { data } = useSnapshot()
  const iss = data?.iss_position as IssPositionData | undefined

  const lastTickAt = iss?.fetched_at
    ? new Date(iss.fetched_at).getTime()
    : undefined
  const isStale =
    lastTickAt !== undefined
      ? Date.now() - lastTickAt > STALE_AFTER_MS
      : undefined

  return (
    <Panel
      title="ISS"
      subtitle="POSITION"
      rawHref="https://wheretheiss.at/"
      rawLabel="wheretheiss.at"
      isStale={isStale}
      lastTickAt={lastTickAt}
    >
      <div className={styles.row}>
        <span className={styles.label}>Lat, Lon</span>
        <span className={styles.value}>
          {iss
            ? `${iss.latitude.toFixed(COORDS_DECIMALS)}°, ${iss.longitude.toFixed(COORDS_DECIMALS)}°`
            : '—'}
        </span>
      </div>
      <div className={styles.row}>
        <span className={styles.label}>Alt</span>
        <span className={styles.value}>
          {iss ? `${iss.altitude.toFixed(ALT_DECIMALS)} km` : '—'}
        </span>
      </div>
      <div className={styles.row}>
        <span className={styles.label}>Vel</span>
        <span className={styles.value}>
          {iss ? `${Math.round(iss.velocity).toLocaleString()} km/h` : '—'}
        </span>
      </div>
      <div className={styles.row}>
        <span className={styles.label}>Next Pass</span>
        <span className={styles.muted}>—</span>
      </div>
    </Panel>
  )
}

ISSPanel.displayName = 'ISSPanel'
