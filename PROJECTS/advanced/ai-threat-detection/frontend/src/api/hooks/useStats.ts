// ===================
// © AngelaMos | 2026
// useStats.ts
// ===================

import { useQuery } from '@tanstack/react-query'
import { QUERY_KEYS, API_ENDPOINTS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'
import type { StatsResponse } from '@/api/types'

export function useStats(range = '24h') {
  return useQuery<StatsResponse>({
    queryKey: QUERY_KEYS.STATS.BY_RANGE(range),
    queryFn: async () => {
      const { data } = await apiClient.get<StatsResponse>(
        API_ENDPOINTS.STATS,
        { params: { range } },
      )
      return data
    },
    ...QUERY_STRATEGIES.frequent,
  })
}
