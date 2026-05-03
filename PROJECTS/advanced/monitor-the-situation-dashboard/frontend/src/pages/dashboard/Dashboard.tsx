// ©AngelaMos | 2026
// Dashboard.tsx

import { AlertBanner } from './AlertBanner'
import styles from './Dashboard.module.scss'
import { TopStrip } from './TopStrip'

export function Dashboard(): React.ReactElement {
  return (
    <div className={styles.root}>
      <TopStrip />
      <AlertBanner />
      <main className={styles.grid}>
        <aside className={styles.left} />
        <section className={styles.center} />
        <aside className={styles.right} />
      </main>
    </div>
  )
}

Dashboard.displayName = 'Dashboard'
