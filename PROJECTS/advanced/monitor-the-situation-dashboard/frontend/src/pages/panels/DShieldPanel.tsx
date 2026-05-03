// ©AngelaMos | 2026
// DShieldPanel.tsx

import { useSnapshot } from '@/api/snapshot'
import styles from './DShieldPanel.module.scss'
import { Panel } from './Panel'

const PORT_ROW_LIMIT = 8
const SOURCE_ROW_LIMIT = 8
const THOUSAND = 1_000
const MILLION = 1_000_000

interface DShieldPort {
  port: number
  records: number
}

interface DShieldSource {
  ip: string
  country?: string
  records: number
}

interface DShieldDailySummary {
  records: number
  sources: number
  targets: number
}

interface DShieldData {
  topports?: DShieldPort[]
  topips?: DShieldSource[]
  dailysummary?: DShieldDailySummary[]
}

export function DShieldPanel(): React.ReactElement {
  const { data } = useSnapshot()
  const ds = (data?.scan_firehose as DShieldData | undefined) ?? {}
  const summary = ds.dailysummary?.[0]

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
              <th>Hits / 24h</th>
            </tr>
          </thead>
          <tbody>
            {(ds.topports ?? []).slice(0, PORT_ROW_LIMIT).map((p) => (
              <tr key={p.port}>
                <td className={styles.mono}>{p.port}</td>
                <td className={styles.mono}>{p.records.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <table className={styles.table}>
          <thead>
            <tr>
              <th>Source IP</th>
              <th>CC</th>
              <th>Hits</th>
            </tr>
          </thead>
          <tbody>
            {(ds.topips ?? []).slice(0, SOURCE_ROW_LIMIT).map((s) => (
              <tr key={s.ip}>
                <td className={styles.mono}>{s.ip}</td>
                <td>{s.country ?? '—'}</td>
                <td className={styles.mono}>{s.records.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {summary && (
        <p className={styles.summary}>
          {fmtN(summary.records)} records · {fmtN(summary.sources)} sources ·{' '}
          {fmtN(summary.targets)} targets — last 24h
        </p>
      )}
    </Panel>
  )
}

DShieldPanel.displayName = 'DShieldPanel'

function fmtN(n: number): string {
  if (n >= MILLION) return `${(n / MILLION).toFixed(1)}M`
  if (n >= THOUSAND) return `${(n / THOUSAND).toFixed(1)}k`
  return String(n)
}
