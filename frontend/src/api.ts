export type PathHop = { name: string; version: string; id?: number };

export type ExposedService = {
  id: number;
  name: string;
  application: string;
  env: string;
  criticality: string;
  team: string;
  deployed_at: number;
  resolved_at: number;
  commit: string;
  depth: number;
  direct_pin: boolean;
  score: number;
  path: PathHop[];
  path_packages: string[];
};

export type ContainedService = {
  id: number;
  name: string;
  env: string;
  criticality: string;
  team: string;
  exposed: boolean;
  why: string;
  pinned_version?: string;
  resolved_at?: number;
};

export type GraphNode = {
  id: number;
  label: string;
  kind: string;
  name: string;
  version?: string;
  criticality?: string;
  env?: string;
};

export type GraphEdge = { source: number; target: number; rel: string };

export type QueryLog = {
  name: string;
  cypher: string;
  parameters: Record<string, unknown>;
  row_count: number;
};

export type AnalyzeResponse = {
  engine: "hydradb";
  briefing: string;
  contrast: {
    scanner_name_hits: number;
    scanner_version_hits: number;
    hydrashield_exposed: number;
    false_positives: string[];
    why: string;
  };
  contained: ContainedService[];
  next_hop: { reason: string; packages: { name: string; infra: string }[] };
  incident: {
    slug: string;
    title: string;
    package: string;
    version: string;
    safe_version: string;
    published_at: string;
    yanked_at: string;
    advisory: string;
    start_ts: number;
    end_ts: number;
  };
  summary: {
    services_total: number;
    services_exposed: number;
    services_safe: number;
    production_exposed: number;
    p0_exposed: number;
    ecosystem_dependents: number;
    shared_maintainers: number;
    typosquats: number;
    window_seconds: number;
    scanner_false_positives: number;
  };
  exposed: ExposedService[];
  ecosystem: { id: number; name: string; version: string }[];
  maintainers: { name: string; maintainer: string; npm_user: string }[];
  infrastructure: { name: string; infra: string; infra_slug: string }[];
  typosquats: { name: string; downloads: number }[];
  remediation: {
    summary: string;
    steps: {
      action: string;
      package: string;
      to_version?: string;
      reason: string;
      services_fixed?: number;
      residual?: number;
    }[];
    review: { action: string; package: string; reason: string }[];
    block: { action: string; package: string; reason: string }[];
    rotate: { action: string; reason: string };
    residual_services: string[];
  };
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  replay: Replay;
  queries: QueryLog[];
};

export type ReplayFrame = {
  at: number;
  offset_s: number;
  clock: string;
  exposed_count: number;
  p0_count: number;
  new: string[];
  exposed_names: string[];
};

export type DelayCost = {
  minutes: number;
  yank_at: number;
  clock: string;
  exposed: number;
  saved: number;
  saved_p0: string[];
  saved_names: string[];
};

export type Replay = {
  t0: number;
  t1: number;
  duration_s: number;
  frames: ReplayFrame[];
  delay_cost: DelayCost[];
  headline: string;
};

export async function ingest(): Promise<void> {
  const res = await fetch("/api/ingest", { method: "POST" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || "Ingest failed — HydraDB must be running.");
  }
}

export async function analyze(): Promise<AnalyzeResponse> {
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || "Analyze failed");
  }
  return res.json();
}

export function fmtTime(unix: number): string {
  return new Date(unix * 1000).toISOString().slice(11, 19) + "Z";
}

export function whyLabel(why: string): string {
  if (why === "before_window") return "Pinned before 09:00";
  if (why === "after_yank") return "Resolved after yank";
  if (why === "other_version") return "Different version in-window";
  if (why === "no_pin") return "Never resolved signal-bus";
  return why;
}
