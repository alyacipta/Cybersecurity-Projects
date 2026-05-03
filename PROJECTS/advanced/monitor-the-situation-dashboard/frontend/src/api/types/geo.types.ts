// ©AngelaMos | 2026
// geo.types.ts

import { z } from 'zod'

export const issPositionSchema = z.object({
  latitude: z.number(),
  longitude: z.number(),
  altitude: z.number(),
  velocity: z.number(),
  timestamp: z.number(),
  fetched_at: z.string().optional(),
})

export type IssPosition = z.infer<typeof issPositionSchema>

export const earthquakePayloadSchema = z.object({
  id: z.string(),
  geometry: z
    .object({ coordinates: z.array(z.number()).optional() })
    .optional(),
  properties: z.record(z.string(), z.unknown()).optional(),
})

export type EarthquakePayload = z.infer<typeof earthquakePayloadSchema>

export const internetOutageSchema = z.object({
  id: z.string(),
  startDate: z.string().optional(),
  endDate: z.string().nullable().optional(),
  locations: z.array(z.string()).optional(),
  asns: z.array(z.number()).optional(),
  reason: z.string().optional(),
  outageType: z.string().optional(),
})

export type InternetOutage = z.infer<typeof internetOutageSchema>

export const bgpEnrichmentSchema = z.object({
  country: z.string().optional(),
  abuse_confidence: z.number().optional(),
  isp: z.string().optional(),
  checked_ip: z.string().optional(),
})

export type BgpEnrichment = z.infer<typeof bgpEnrichmentSchema>

export const bgpHijackSchema = z.object({
  id: z.number(),
  detectedAt: z.string().optional(),
  startedAt: z.string().optional(),
  duration: z.number().optional(),
  confidenceScore: z.number().optional(),
  hijackerAsn: z.number().optional(),
  victimAsns: z.array(z.number()).nullable().optional(),
  prefixes: z.array(z.string()).optional(),
  enrichment: bgpEnrichmentSchema.optional(),
})

export type BgpHijack = z.infer<typeof bgpHijackSchema>

export const isValidIssPosition = (data: unknown): data is IssPosition => {
  if (data === null || data === undefined || typeof data !== 'object') return false
  return issPositionSchema.safeParse(data).success
}

export const isValidEarthquakePayload = (
  data: unknown
): data is EarthquakePayload => {
  if (data === null || data === undefined || typeof data !== 'object') return false
  return earthquakePayloadSchema.safeParse(data).success
}

export const isValidInternetOutage = (data: unknown): data is InternetOutage => {
  if (data === null || data === undefined || typeof data !== 'object') return false
  return internetOutageSchema.safeParse(data).success
}

export const isValidBgpHijack = (data: unknown): data is BgpHijack => {
  if (data === null || data === undefined || typeof data !== 'object') return false
  return bgpHijackSchema.safeParse(data).success
}
