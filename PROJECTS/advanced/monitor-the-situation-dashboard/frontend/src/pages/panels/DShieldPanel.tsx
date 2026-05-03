// ©AngelaMos | 2026
// DShieldPanel.tsx

import { type DShieldDailySummary, type DShieldPort } from '@/api/types'
import { useDShieldData } from '@/api/hooks'
import styles from './DShieldPanel.module.scss'
import { Panel } from './Panel'

const PORT_ROW_LIMIT = 8
const SOURCE_ROW_LIMIT = 8
const THOUSAND = 1_000
const MILLION = 1_000_000

export function DShieldPanel(): React.ReactElement {
  const ds = useDShieldData()

  const ports = toArray(ds.topports)
    .filter(isPort)
    .slice()
    .sort((a, b) => a.rank - b.rank)
    .slice(0, PORT_ROW_LIMIT)

  const sources = (ds.topips ?? [])
    .slice()
    .sort((a, b) => a.rank - b.rank)
    .slice(0, SOURCE_ROW_LIMIT)

  const summary = pickLatestSummary(ds.dailysummary)

  return (
    <Panel
      title="DSHIELD"
      subtitle="MASS SCAN"
      rawHref="https://isc.sans.edu/api/"
      rawLabel="DShield API"
    >
      <div className={styles.row}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Port</th>
              <th>Hits</th>
              <th>Src</th>
            </tr>
          </thead>
          <tbody>
            {ports.map((p) => (
              <tr key={p.targetport}>
                <td className={styles.mono}>{p.targetport}</td>
                <td className={styles.mono}>{fmtN(p.records)}</td>
                <td className={styles.mono}>{fmtN(p.sources)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <table className={styles.table}>
          <thead>
            <tr>
              <th>Source IP</th>
              <th>Reports</th>
              <th>Tgt</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => (
              <tr key={s.source}>
                <td className={styles.mono}>{s.source}</td>
                <td className={styles.mono}>{fmtN(s.reports)}</td>
                <td className={styles.mono}>{fmtN(s.targets)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {summary && (
        <p className={styles.summary}>
          {fmtN(summary.records)} records · {fmtN(summary.sources)} sources ·{' '}
          {fmtN(summary.targets)} targets — {summary.date}
        </p>
      )}
    </Panel>
  )
}

DShieldPanel.displayName = 'DShieldPanel'

function toArray<T>(v: Record<string, T> | T[] | undefined): T[] {
  if (!v) return []
  if (Array.isArray(v)) return v
  return Object.values(v)
}

function isPort(v: unknown): v is DShieldPort {
  if (!v || typeof v !== 'object') return false
  const p = v as Record<string, unknown>
  return (
    typeof p.targetport === 'number' &&
    typeof p.records === 'number' &&
    typeof p.sources === 'number' &&
    typeof p.rank === 'number'
  )
}

function pickLatestSummary(
  list: DShieldDailySummary[] | undefined
): DShieldDailySummary | undefined {
  if (!list || list.length === 0) return undefined
  return list.reduce((latest, entry) =>
    entry.date > latest.date ? entry : latest
  )
}

function fmtN(n: number): string {
  if (n >= MILLION) return `${(n / MILLION).toFixed(1)}M`
  if (n >= THOUSAND) return `${(n / THOUSAND).toFixed(1)}k`
  return String(n)
}
