// ©AngelaMos | 2026
// Dashboard.tsx

import styles from './Dashboard.module.scss'

export function Dashboard(): React.ReactElement {
  return (
    <div className={styles.root}>
      <main className={styles.grid}>
        <aside className={styles.left} />
        <section className={styles.center} />
        <aside className={styles.right} />
      </main>
    </div>
  )
}

Dashboard.displayName = 'Dashboard'
