// ©AngelaMos | 2026
// useBgpHijackData.ts

import { useEffect } from 'react'
import { isValidBgpHijack, type BgpHijack } from '@/api/types'
import { useSnapshot } from '@/api/snapshot'
import { useBgpHijackStore } from '@/stores/bgpHijack'

interface BgpHijackData {
  items: BgpHijack[]
}

export function useBgpHijackData(): BgpHijackData {
  const { data } = useSnapshot()
  const items = useBgpHijackStore((s) => s.items)
  const push = useBgpHijackStore((s) => s.push)

  const raw = data?.bgp_hijack
  const seed = isValidBgpHijack(raw) ? raw : undefined
  useEffect(() => {
    if (seed) push(seed)
  }, [seed, push])

  return { items }
}
