// ©AngelaMos | 2026
// useEarthquakeData.ts

import { useEffect } from 'react'
import { isValidEarthquakePayload, type EarthquakePayload } from '@/api/types'
import { useSnapshot } from '@/api/snapshot'
import { useEarthquakeStore } from '@/stores/earthquake'

interface EarthquakeData {
  items: EarthquakePayload[]
}

export function useEarthquakeData(): EarthquakeData {
  const { data } = useSnapshot()
  const items = useEarthquakeStore((s) => s.items)
  const push = useEarthquakeStore((s) => s.push)

  const raw = data?.earthquake
  const seed = isValidEarthquakePayload(raw) ? raw : undefined
  useEffect(() => {
    if (seed) push(seed)
  }, [seed, push])

  return { items }
}
