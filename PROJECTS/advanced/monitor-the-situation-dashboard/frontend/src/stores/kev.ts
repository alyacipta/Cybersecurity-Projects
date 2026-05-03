// ©AngelaMos | 2026
// kev.ts

import { create } from 'zustand'

export interface KevEntry {
  cveID: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  dateAdded: string
  dueDate?: string
  knownRansomwareCampaignUse?: string
  shortDescription?: string
  requiredAction?: string
}

interface KevStore {
  items: KevEntry[]
  push: (item: KevEntry) => void
  clear: () => void
}

const KEV_CAP = 200

export const useKevStore = create<KevStore>((set) => ({
  items: [],
  push: (item) =>
    set((s) => {
      const filtered = s.items.filter((i) => i.cveID !== item.cveID)
      return { items: [item, ...filtered].slice(0, KEV_CAP) }
    }),
  clear: () => set({ items: [] }),
}))
