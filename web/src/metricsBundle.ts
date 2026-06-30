// web/src/metricsBundle.ts
// TypeScript mirror of the Go internal/metrics bundle (the GET /api/metrics payload).
// Field names are the Go JSON tags verbatim so the SPA can render the server-computed
// metrics without recomputing. Keep in lockstep with internal/metrics/*.go.
import type { Summary, ReportAccount } from "./api"

export type Tier = "Critical" | "High" | "Medium" | "Low"

export interface Slice { name: string; value: number; color: string }
export interface Bar { name: string; value: number }
export interface Point { x: number; y: number }
export interface Series { name: string; color: string; points: Point[] }

export interface AccountRef {
  username: string
  domain: string
  risk_level: string
  risk_score: number
  hibp_breach_count: number
  has_da: boolean
  controlled_object_count: number
}

export interface AxisFactor { name: string; value: number; color: string }
export interface TierFactorBars {
  tier: string
  color: string
  exposure: AxisFactor[]
  impact: AxisFactor[]
  impact_known: boolean
}

export interface GraphNode { id: string; label: string; size: number; color: string; x: number; y: number }
export interface GraphEdge { source: string; target: string; weight: number; label?: string }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[] }

export interface Matrix {
  counts: Record<Tier, Record<string, number>>
  total: number
  max: number
}

export interface ChartSeries {
  risk_distribution: Slice[]
  hibp_split: Slice[]
  expiration_split: Slice[]
  length_buckets: Bar[]
  score_buckets: Bar[]
  sharing_distribution: Bar[]
  controlled_objects_buckets: Bar[]
  similarity_buckets: Bar[]
  da_exposure_by_domain: Bar[]
  complexity_counts: Bar[]
  hibp_vs_risk: Series[]
  password_age_buckets: Bar[]
  password_age_scatter: Series[]
  axis_factor_bars: TierFactorBars[]
  top_riskiest: AccountRef[]
  escalated_by_shared_da: AccountRef[]
  top_controllers: AccountRef[]
  top_controllers_more_over_100: number
}

export interface ExposureHeadline {
  cracked_da: number
  cracked_hibp: number
  cross_domain_groups: number
  domains_spanned: number
}
export interface BridgeCluster {
  domains: string[]
  size: number
  cracked: boolean
  has_da: boolean
  hibp_max: number
  members: ReportAccount[]
}
export interface CrossDomain { clusters: BridgeCluster[]; domains: string[] }
export interface HIBPTriage { tier1: ReportAccount[]; tier2: ReportAccount[] }
export interface WorklistRow { account: AccountRef; priority: number; reasons: string[] }

export interface ReportSeries {
  exposure_headline: ExposureHeadline
  cross_domain: CrossDomain
  hibp_triage: HIBPTriage
  worklist: WorklistRow[]
  reuse_graph: Graph
  similarity_graph: Graph
}

export interface DomainMetrics {
  domain: string
  summary: Summary
  matrix: Matrix
  charts: ChartSeries
}

export interface MetricsBundle {
  summary: Summary
  matrix: Matrix
  charts: ChartSeries
  reports: ReportSeries
  domains: DomainMetrics[]
}
