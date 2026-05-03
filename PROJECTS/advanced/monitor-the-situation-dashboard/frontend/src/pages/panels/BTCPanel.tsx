// ©AngelaMos | 2026
// BTCPanel.tsx

import { useEffect } from 'react'
import { useSnapshot } from '@/api/snapshot'
import { usePrices } from '@/stores/prices'
import styles from './BTCPanel.module.scss'
import { Panel } from './Panel'
import { Sparkline } from './shared/Sparkline'

const SYMBOL = 'BTC-USD'
const SPARKLINE_WIDTH = 280
const SPARKLINE_HEIGHT = 22
const PERCENT_DECIMALS = 2
const PRICE_DECIMALS = 2
const STALE_AFTER_MS = 60_000

interface CoinbaseSnapshotTick {
  symbol: string
  ts: string
  price: string
  volume_24h?: string
}

export function BTCPanel(): React.ReactElement {
  const { data } = useSnapshot()
  const latest = usePrices((s) => s.latest[SYMBOL])
  const history = usePrices((s) => s.history[SYMBOL])
  const pushTick = usePrices((s) => s.pushTick)

  const seed = data?.coinbase_price as CoinbaseSnapshotTick | undefined
  useEffect(() => {
    if (!seed || seed.symbol !== SYMBOL) return
    pushTick({
      symbol: seed.symbol,
      ts: new Date(seed.ts).getTime(),
      price: seed.price,
      volume24h: seed.volume_24h,
    })
  }, [seed, pushTick])

  const priceNum = latest ? Number(latest.price) : null
  const closes = (history ?? []).map((b) => Number(b.close))
  const pct1h = computeChangePct(closes)

  const lastTickAt = latest?.ts
  const isStale =
    latest === undefined ? undefined : Date.now() - latest.ts > STALE_AFTER_MS

  return (
    <Panel
      title="BTC"
      subtitle="USD"
      rawHref="https://www.coinbase.com/price/bitcoin"
      rawLabel="Coinbase BTC"
      isStale={isStale}
      lastTickAt={lastTickAt}
    >
      <div className={styles.hero}>
        <span className={styles.price}>{fmtPrice(priceNum)}</span>
        <span className={styles.unit}>USD</span>
      </div>
      <div className={styles.changes}>
        <ChangeRow label="1H" pct={pct1h} />
      </div>
      <div className={styles.spark}>
        <Sparkline
          data={closes}
          width={SPARKLINE_WIDTH}
          height={SPARKLINE_HEIGHT}
        />
      </div>
    </Panel>
  )
}

BTCPanel.displayName = 'BTCPanel'

function ChangeRow({
  label,
  pct,
}: {
  label: string
  pct: number | null
}): React.ReactElement {
  return (
    <div className={styles.change}>
      <span className={styles.changeLabel}>{label}</span>
      <span className={styles.changeValue}>{fmtPct(pct)}</span>
    </div>
  )
}

function computeChangePct(closes: number[]): number | null {
  if (closes.length < 2) return null
  const first = closes[0]
  const last = closes[closes.length - 1]
  if (
    first === undefined ||
    last === undefined ||
    !Number.isFinite(first) ||
    !Number.isFinite(last) ||
    first === 0
  ) {
    return null
  }
  return ((last - first) / first) * 100
}

function fmtPct(pct: number | null): string {
  if (pct === null) return '—'
  const glyph = pct >= 0 ? '△' : '▽'
  return `${glyph} ${Math.abs(pct).toFixed(PERCENT_DECIMALS)} %`
}

function fmtPrice(n: number | null): string {
  if (n === null || !Number.isFinite(n)) return '—'
  return n.toLocaleString(undefined, {
    minimumFractionDigits: PRICE_DECIMALS,
    maximumFractionDigits: PRICE_DECIMALS,
  })
}
