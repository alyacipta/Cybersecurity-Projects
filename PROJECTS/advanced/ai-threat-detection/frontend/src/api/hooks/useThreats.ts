// ===================
// © AngelaMos | 2026
// useThreats.ts
// ===================

import { useQuery } from '@tanstack/react-query'
import { QUERY_KEYS, API_ENDPOINTS, PAGINATION } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'
import type { ThreatList, ThreatEvent } from '@/api/types'

interface ThreatParams {
  limit?: number
  offset?: number
  severity?: 'HIGH' | 'MEDIUM' | 'LOW'
  source_ip?: string
  since?: string
  until?: string
}

export function useThreats(params: ThreatParams = {}) {
  const queryParams = {
    limit: params.limit ?? PAGINATION.DEFAULT_LIMIT,
    offset: params.offset ?? 0,
    ...params,
  }

  return useQuery<ThreatList>({
    queryKey: QUERY_KEYS.THREATS.LIST(queryParams),
    queryFn: async () => {
      const { data } = await apiClient.get<ThreatList>(
        API_ENDPOINTS.THREATS.LIST,
        { params: queryParams },
      )
      return data
    },
    ...QUERY_STRATEGIES.frequent,
  })
}

export function useThreat(id: string | null) {
  return useQuery<ThreatEvent>({
    queryKey: QUERY_KEYS.THREATS.BY_ID(id ?? ''),
    queryFn: async () => {
      const { data } = await apiClient.get<ThreatEvent>(
        API_ENDPOINTS.THREATS.BY_ID(id!),
      )
      return data
    },
    enabled: id !== null,
    ...QUERY_STRATEGIES.standard,
  })
}
