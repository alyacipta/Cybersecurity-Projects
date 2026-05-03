// ©AngelaMos | 2026
// Dashboard.tsx

import { Globe } from '@/pages/globe/Globe'
import { CVEVelocityPanel } from '@/pages/panels/CVEVelocityPanel'
import { DShieldPanel } from '@/pages/panels/DShieldPanel'
import { useUIStore } from '@/stores/ui'
import { AlertBanner } from './AlertBanner'
import { BottomTicker } from './BottomTicker'
import styles from './Dashboard.module.scss'
import { presentationMode } from './presentationMode'
import { TopStrip } from './TopStrip'

export function Dashboard(): React.ReactElement {
  presentationMode.useGlobalShortcut()
  const isPresentation = useUIStore((s) => s.presentationMode)

  const rootClass = isPresentation
    ? `${styles.root} ${styles.presentation}`
    : styles.root

  return (
    <div className={rootClass}>
      <TopStrip />
      <AlertBanner />
      <main className={styles.grid}>
        <aside className={styles.left} />
        <section className={styles.center}>
          <Globe />
        </section>
        <aside className={styles.right}>
          <CVEVelocityPanel />
          <DShieldPanel />
        </aside>
      </main>
      <BottomTicker />
    </div>
  )
}

Dashboard.displayName = 'Dashboard'
