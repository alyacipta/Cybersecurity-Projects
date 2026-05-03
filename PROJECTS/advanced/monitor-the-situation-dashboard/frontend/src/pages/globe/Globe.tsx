// ©AngelaMos | 2026
// Globe.tsx

import { memo, useEffect, useRef, useState } from 'react'
import GlobeGL, { type GlobeMethods } from 'react-globe.gl'
import { useGlobeEvents } from '@/stores/globeEvents'
import styles from './Globe.module.scss'
import { panTo } from './globeCamera'
import { useGlobePoints, useGlobeRings } from './globeLayers'

const ATMOSPHERE_COLOR = '#1f2937'
const ATMOSPHERE_ALTITUDE = 0.12
const RING_COLOR = '#e5e5e5'
const RING_MAX_RADIUS = 4
const RING_PROPAGATION_SPEED = 4
const RING_REPEAT_PERIOD = 0
const COUNTRIES_URL = '/world-countries-110m.geo.json'
const COUNTRY_OUTLINE_COLOR = '#404040'
const COUNTRY_FILL_TRANSPARENT = 'rgba(0,0,0,0)'
const COUNTRY_ALTITUDE = 0.005

interface CountryFeature {
  type: 'Feature'
  properties: Record<string, unknown>
  geometry: {
    type: string
    coordinates: unknown
  }
}

interface CountriesData {
  type: 'FeatureCollection'
  features: CountryFeature[]
}

export const Globe = memo(function Globe(): React.ReactElement {
  const wrapRef = useRef<HTMLDivElement>(null)
  const globeRef = useRef<GlobeMethods | undefined>(undefined)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const [countries, setCountries] = useState<CountryFeature[]>([])

  const points = useGlobePoints()
  const rings = useGlobeRings()
  const focusEvent = useGlobeEvents((s) => s.focusEvent)

  useEffect(() => {
    let cancelled = false
    fetch(COUNTRIES_URL)
      .then((res) => res.json() as Promise<CountriesData>)
      .then((fc) => {
        if (cancelled) return
        setCountries(fc.features)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    const wrap = wrapRef.current
    if (!wrap) return
    const ro = new ResizeObserver((entries) => {
      const entry = entries[0]
      if (!entry) return
      setSize({
        w: entry.contentRect.width,
        h: entry.contentRect.height,
      })
    })
    ro.observe(wrap)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    if (size.w === 0) return
    const controls = globeRef.current?.controls()
    if (!controls) return
    controls.autoRotate = false
  }, [size.w])

  useEffect(() => {
    if (!focusEvent) return
    panTo(globeRef, focusEvent.lat, focusEvent.lng)
  }, [focusEvent])

  return (
    <div ref={wrapRef} className={styles.globeWrap}>
      {size.w > 0 && size.h > 0 && (
        <GlobeGL
          ref={globeRef}
          width={size.w}
          height={size.h}
          polygonsData={countries}
          polygonAltitude={COUNTRY_ALTITUDE}
          polygonCapColor={() => COUNTRY_FILL_TRANSPARENT}
          polygonSideColor={() => COUNTRY_FILL_TRANSPARENT}
          polygonStrokeColor={() => COUNTRY_OUTLINE_COLOR}
          polygonsTransitionDuration={0}
          pointsData={points}
          pointsMerge
          pointLat="lat"
          pointLng="lng"
          pointColor="color"
          pointAltitude="altitude"
          pointRadius="radius"
          ringsData={rings}
          ringLat="lat"
          ringLng="lng"
          ringColor={() => RING_COLOR}
          ringMaxRadius={RING_MAX_RADIUS}
          ringPropagationSpeed={RING_PROPAGATION_SPEED}
          ringRepeatPeriod={RING_REPEAT_PERIOD}
          atmosphereColor={ATMOSPHERE_COLOR}
          atmosphereAltitude={ATMOSPHERE_ALTITUDE}
          backgroundColor="rgba(0,0,0,0)"
        />
      )}
    </div>
  )
})

Globe.displayName = 'Globe'
