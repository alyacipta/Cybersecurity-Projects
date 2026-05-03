// ©AngelaMos | 2026
// lifecycle.ts

import { type QueryClient, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import { SNAPSHOT_KEY, type Snapshot, useSnapshot } from '@/api/snapshot'
import { browserDriver, createDashboardWS, type WSEvent } from '@/api/ws'
import { unlockOnFirstGesture } from '@/lib/audio'
import { type CveEvent, useCveStore } from '@/stores/cve'
import { useGlobeEvents } from '@/stores/globeEvents'
import { type KevEntry, useKevStore } from '@/stores/kev'
import { usePrices } from '@/stores/prices'
import { type RansomwareVictim, useRansomwareStore } from '@/stores/ransomware'
import { useTicker } from '@/stores/ticker'

const ALL_TOPICS: readonly string[] = [
  'heartbeat',
  'scan_firehose',
  'internet_outage',
  'bgp_hijack',
  'cve_new',
  'kev_added',
  'ransomware_victim',
  'coinbase_price',
  'earthquake',
  'space_weather',
  'wiki_itn',
  'gdelt_spike',
  'iss_position',
]

const WS_URL = '/api/v1/ws'
const GLOBE_RING_TTL_MS = 4_000
const GLOBE_EVICT_INTERVAL_MS = 5 * 60_000

interface CoinbaseTickPayload {
  symbol: string
  ts: string
  price: string
  volume_24h?: string
}

interface IssPositionPayload {
  latitude: number
  longitude: number
  altitude: number
  velocity: number
  timestamp: number
  fetched_at?: string
}

interface EarthquakePayload {
  id: string
  geometry?: { coordinates?: number[] }
  properties?: Record<string, unknown>
}

interface WikiItnPayload {
  text: string
  slug: string
}

interface GdeltSpikePayload {
  theme: string
  time: string
  count: number
  zscore: number
}

export function useDashboardLifecycle(): void {
  const { data: snapshot, isSuccess } = useSnapshot()
  const queryClient = useQueryClient()
  const wsRef = useRef<ReturnType<typeof createDashboardWS> | null>(null)
  const globeSeededRef = useRef(false)

  useEffect(() => {
    unlockOnFirstGesture()
  }, [])

  useEffect(() => {
    if (!snapshot || globeSeededRef.current) return
    globeSeededRef.current = true
    seedGlobeFromSnapshot(snapshot)
  }, [snapshot])

  useEffect(() => {
    if (!isSuccess) return

    const ws = createDashboardWS({
      driver: () => browserDriver(WS_URL, [...ALL_TOPICS]),
      topics: [...ALL_TOPICS],
      onEvent: (ev) => routeEvent(ev, queryClient),
    })
    wsRef.current = ws
    ws.connect()
    ws.setReady()

    return () => {
      ws.disconnect()
      wsRef.current = null
    }
  }, [isSuccess, queryClient])

  useEffect(() => {
    const id = setInterval(() => {
      useGlobeEvents.getState().evict(Date.now())
    }, GLOBE_EVICT_INTERVAL_MS)
    return () => clearInterval(id)
  }, [])

  void snapshot
}

function routeEvent(ev: WSEvent, queryClient: QueryClient): void {
  const data = ev.payload
  if (data === undefined || data === null) return

  switch (ev.topic) {
    case 'cve_new':
      handleCve(data as CveEvent)
      break
    case 'kev_added':
      handleKev(data as KevEntry)
      break
    case 'ransomware_victim':
      handleRansomware(data as RansomwareVictim)
      break
    case 'coinbase_price':
      handleCoinbase(data as CoinbaseTickPayload)
      break
    case 'earthquake':
      handleEarthquake(data as EarthquakePayload)
      break
    case 'iss_position':
      handleIss(data as IssPositionPayload, queryClient)
      break
    case 'wiki_itn':
      handleWiki(data as WikiItnPayload)
      break
    case 'gdelt_spike':
      handleGdelt(data as GdeltSpikePayload)
      break
    case 'space_weather':
    case 'internet_outage':
    case 'bgp_hijack':
    case 'scan_firehose':
      mergeIntoSnapshot(queryClient, ev.topic, data)
      break
    default:
      break
  }
}

function handleCve(p: CveEvent): void {
  if (!p.CveID) return
  useCveStore.getState().push(p)
}

function handleKev(p: KevEntry): void {
  if (!p.cveID) return
  useKevStore.getState().push(p)
}

function handleRansomware(p: RansomwareVictim): void {
  if (!p.post_title) return
  useRansomwareStore.getState().push(p)
}

function handleCoinbase(p: CoinbaseTickPayload): void {
  if (!p.symbol || !p.ts) return
  usePrices.getState().pushTick({
    symbol: p.symbol,
    ts: new Date(p.ts).getTime(),
    price: p.price,
    volume24h: p.volume_24h,
  })
}

function handleEarthquake(p: EarthquakePayload): void {
  const coords = p.geometry?.coordinates
  if (!Array.isArray(coords)) return
  const lng = coords[0]
  const lat = coords[1]
  if (typeof lat !== 'number' || typeof lng !== 'number') return
  const now = Date.now()
  useGlobeEvents.getState().pushPoint({
    id: `eq-${p.id}`,
    type: 'earthquake',
    lat,
    lng,
    emittedAt: now,
    meta: p.properties,
  })
  useGlobeEvents.getState().pushRing({
    id: `eq-ring-${p.id}-${now}`,
    lat,
    lng,
    emittedAt: now,
    ttlMs: GLOBE_RING_TTL_MS,
  })
}

function handleIss(p: IssPositionPayload, queryClient: QueryClient): void {
  if (typeof p.latitude !== 'number' || typeof p.longitude !== 'number') return
  useGlobeEvents.getState().pushPoint({
    id: 'iss-current',
    type: 'iss',
    lat: p.latitude,
    lng: p.longitude,
    emittedAt: Date.now(),
  })
  mergeIntoSnapshot(queryClient, 'iss_position', p)
}

function handleWiki(p: WikiItnPayload): void {
  if (!p.text) return
  const id = `wiki-${p.slug || p.text}`
  useTicker.getState().push({
    id,
    source: 'Wikipedia',
    headline: p.text,
    ts: Date.now(),
  })
}

function handleGdelt(p: GdeltSpikePayload): void {
  if (!p.theme) return
  useTicker.getState().push({
    id: `gdelt-${p.theme}-${p.time}`,
    source: 'GDELT',
    headline: `${p.theme} spike (z=${p.zscore.toFixed(2)}, n=${p.count})`,
    ts: Date.now(),
  })
}

function mergeIntoSnapshot(
  queryClient: QueryClient,
  topic: string,
  data: unknown
): void {
  queryClient.setQueryData<Record<string, unknown>>(SNAPSHOT_KEY, (prev) => ({
    ...(prev ?? {}),
    [topic]: data,
  }))
}

function seedGlobeFromSnapshot(snap: Snapshot): void {
  const eq = snap.earthquake as EarthquakePayload | undefined
  if (eq) {
    const coords = eq.geometry?.coordinates
    if (Array.isArray(coords)) {
      const lng = coords[0]
      const lat = coords[1]
      if (typeof lat === 'number' && typeof lng === 'number') {
        useGlobeEvents.getState().pushPoint({
          id: `eq-${eq.id}`,
          type: 'earthquake',
          lat,
          lng,
          emittedAt: Date.now(),
          meta: eq.properties,
        })
      }
    }
  }

  const iss = snap.iss_position as IssPositionPayload | undefined
  if (
    iss &&
    typeof iss.latitude === 'number' &&
    typeof iss.longitude === 'number'
  ) {
    useGlobeEvents.getState().pushPoint({
      id: 'iss-current',
      type: 'iss',
      lat: iss.latitude,
      lng: iss.longitude,
      emittedAt: Date.now(),
    })
  }
}
