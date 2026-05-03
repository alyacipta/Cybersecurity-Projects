// ©AngelaMos | 2026
// OutagePanel.tsx

import { useEffect, useRef, useState } from 'react'
import { useOutageData } from '@/api/hooks'
import { Panel } from './Panel'
import styles from './OutagePanel.module.scss'

const OUTAGE_ROW_LIMIT = 6
const FLASH_DURATION_MS = 600
const MS_PER_HOUR = 3_600_000
const MS_PER_MINUTE = 60_000
const HOURS_PER_DAY = 24

export function OutagePanel(): React.ReactElement {
  const { items } = useOutageData()
  const seenIds = useRef<Set<string>>(new Set())
  const [flashIds, setFlashIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    const isFirstSeed = seenIds.current.size === 0
    const newIds: string[] = []
    for (const o of items) {
      if (!seenIds.current.has(o.id)) {
        seenIds.current.add(o.id)
        if (!isFirstSeed) newIds.push(o.id)
      }
    }
    if (newIds.length > 0) setFlashIds(new Set(newIds))
  }, [items])

  useEffect(() => {
    if (flashIds.size === 0) return
    const t = setTimeout(() => setFlashIds(new Set()), FLASH_DURATION_MS)
    return () => clearTimeout(t)
  }, [flashIds])

  const recent = items.slice(0, OUTAGE_ROW_LIMIT)
  const now = Date.now()

  return (
    <Panel
      title="OUTAGES"
      subtitle="CF RADAR"
      rawHref="https://radar.cloudflare.com/outage-center"
      rawLabel="Cloudflare Radar Outage Center"
    >
      <table className={styles.table}>
        <thead>
          <tr>
            <th className={styles.cc}>CC</th>
            <th className={styles.info}>Cause</th>
            <th className={styles.state}>State</th>
            <th className={styles.ago}>Started</th>
          </tr>
        </thead>
        <tbody>
          {recent.map((o) => {
            const isFlashing = flashIds.has(o.id)
            return (
              <tr key={o.id} className={isFlashing ? styles.flash : undefined}>
                <td className={styles.cc}>{fmtCC(o.locations)}</td>
                <td
                  className={styles.info}
                  title={o.reason ?? o.outageType ?? ''}
                >
                  {fmtCause(o.reason, o.outageType)}
                </td>
                <td className={styles.state}>{fmtState(o.endDate)}</td>
                <td className={styles.ago}>{fmtAgo(o.startDate, now)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </Panel>
  )
}

OutagePanel.displayName = 'OutagePanel'

function fmtCC(locations: string[] | undefined): string {
  if (!locations || locations.length === 0) return '—'
  const first = locations[0] ?? '—'
  if (locations.length === 1) return first
  return `${first} +${locations.length - 1}`
}

function fmtCause(
  reason: string | undefined,
  outageType: string | undefined
): string {
  if (reason && reason.trim()) return reason
  if (outageType && outageType.trim()) return outageType
  return '—'
}

function fmtState(endDate: string | null | undefined): string {
  if (endDate === null || endDate === undefined) return 'active'
  const t = new Date(endDate).getTime()
  if (!Number.isFinite(t)) return 'ended'
  return 'ended'
}

function fmtAgo(iso: string | undefined, now: number): string {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (!Number.isFinite(t)) return '—'
  const diff = now - t
  if (diff < 0) return '—'
  if (diff < MS_PER_HOUR) {
    return `${Math.max(Math.floor(diff / MS_PER_MINUTE), 0)}m`
  }
  if (diff < HOURS_PER_DAY * MS_PER_HOUR) {
    return `${Math.floor(diff / MS_PER_HOUR)}h`
  }
  return `${Math.floor(diff / (HOURS_PER_DAY * MS_PER_HOUR))}d`
}
