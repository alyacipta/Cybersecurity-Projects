// ©AngelaMos | 2026
// KEVPanel.tsx

import { useEffect } from 'react'
import { useSnapshot } from '@/api/snapshot'
import { type KevEntry, useKevStore } from '@/stores/kev'
import styles from './KEVPanel.module.scss'
import { Panel } from './Panel'

const KEV_ROW_LIMIT = 6

export function KEVPanel(): React.ReactElement {
  const { data } = useSnapshot()
  const items = useKevStore((s) => s.items)
  const push = useKevStore((s) => s.push)

  const seed = data?.kev_added as KevEntry | undefined
  useEffect(() => {
    if (seed?.cveID) push(seed)
  }, [seed, push])

  const recent = items.slice(0, KEV_ROW_LIMIT)

  return (
    <Panel
      title="KEV"
      subtitle="CISA EXPLOITED"
      rawHref="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
      rawLabel="CISA KEV catalog"
    >
      <table className={styles.table}>
        <thead>
          <tr>
            <th className={styles.cveId}>CVE</th>
            <th className={styles.vp}>Vendor · Product</th>
            <th className={styles.date}>Added</th>
          </tr>
        </thead>
        <tbody>
          {recent.map((k) => (
            <tr key={k.cveID}>
              <td className={styles.cveId}>{k.cveID}</td>
              <td className={styles.vp}>
                {k.vendorProject} · {k.product}
              </td>
              <td className={styles.date}>{k.dateAdded}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}

KEVPanel.displayName = 'KEVPanel'
