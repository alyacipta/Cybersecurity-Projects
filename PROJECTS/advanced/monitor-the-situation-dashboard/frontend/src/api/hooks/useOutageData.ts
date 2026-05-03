// ©AngelaMos | 2026
// useOutageData.ts

import { useEffect } from 'react'
import { isValidInternetOutage, type InternetOutage } from '@/api/types'
import { useSnapshot } from '@/api/snapshot'
import { useOutageStore } from '@/stores/outage'

interface OutageData {
  items: InternetOutage[]
}

export function useOutageData(): OutageData {
  const { data } = useSnapshot()
  const items = useOutageStore((s) => s.items)
  const push = useOutageStore((s) => s.push)

  const raw = data?.internet_outage
  const seed = isValidInternetOutage(raw) ? raw : undefined
  useEffect(() => {
    if (seed) push(seed)
  }, [seed, push])

  return { items }
}
