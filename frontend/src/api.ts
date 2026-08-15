export type PathHop = { name: string; version: string };

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
    production_exposed: number;
    p0_exposed: number;
    ecosystem_dependents: number;
    shared_maintainers: number;
    typosquats: number;
    window_seconds: number;
  };
  exposed: ExposedService[];
  ecosystem: { id: number; name: string; version: string }[];
  maintainers: { name: string; maintainer: string; npm_user: string }[];
  infrastructure: { name: string; infra: string; infra_slug: string }[];
  typosquats: { name: string; downloads: number }[];
  remediation: {
    summary: string;
    steps: { action: string; package: string; to_version?: string; reason: string; services_fixed?: number; residual?: number }[];
    review: { action: string; package: string; reason: string }[];
    block: { action: string; package: string; reason: string }[];
    rotate: { action: string; reason: string };
    residual_services: string[];
  };
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  queries: QueryLog[];
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
