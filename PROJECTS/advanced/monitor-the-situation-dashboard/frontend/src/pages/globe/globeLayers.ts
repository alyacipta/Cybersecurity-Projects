// ©AngelaMos | 2026
// globeLayers.ts

import { useMemo } from 'react'
import { type GlobePointType, useGlobeEvents } from '@/stores/globeEvents'

const COLOR_BY_TYPE: Record<GlobePointType, string> = {
  earthquake: '#a3a3a3',
  ransomware: '#e5e5e5',
  scan: '#404040',
  iss: '#4ade80',
  outage: '#f59e0b',
  hijack: '#f59e0b',
}

const ALTITUDE_BY_TYPE: Record<GlobePointType, number> = {
  earthquake: 0.01,
  ransomware: 0.01,
  scan: 0.005,
  iss: 0.06,
  outage: 0.005,
  hijack: 0.005,
}

const RADIUS_BY_TYPE: Record<GlobePointType, number> = {
  earthquake: 0.4,
  ransomware: 0.3,
  scan: 0.15,
  iss: 0.5,
  outage: 0.4,
  hijack: 0.4,
}

export interface GlobePointDatum {
  id: string
  type: GlobePointType
  lat: number
  lng: number
  color: string
  altitude: number
  radius: number
}

export interface GlobeRingDatum {
  id: string
  lat: number
  lng: number
}

export function useGlobePoints(): GlobePointDatum[] {
  const points = useGlobeEvents((s) => s.points)
  return useMemo(
    () =>
      points.map((p) => ({
        id: p.id,
        type: p.type,
        lat: p.lat,
        lng: p.lng,
        color: COLOR_BY_TYPE[p.type],
        altitude: ALTITUDE_BY_TYPE[p.type],
        radius: RADIUS_BY_TYPE[p.type],
      })),
    [points]
  )
}

export function useGlobeRings(): GlobeRingDatum[] {
  const rings = useGlobeEvents((s) => s.rings)
  return useMemo(
    () =>
      rings.map((r) => ({
        id: r.id,
        lat: r.lat,
        lng: r.lng,
      })),
    [rings]
  )
}
