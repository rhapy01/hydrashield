import type { AnalyzeResponse, GraphNode } from "./api";

type Props = {
  data: AnalyzeResponse;
  selected?: string;
  onSelect: (name: string) => void;
};

const KIND_FILL: Record<string, string> = {
  compromised: "#ff4d6d",
  service: "#3ee0b4",
  package: "#5aa7ff",
  ecosystem: "#7d8d9c",
};

function radiusFor(kind: string, index: number): number {
  if (kind === "compromised") return 0;
  if (kind === "package" || kind === "ecosystem") return 130 + (index % 3) * 8;
  return 230;
}

export function BlastGraph({ data, selected, onSelect }: Props) {
  const width = 920;
  const height = 520;
  const cx = width / 2;
  const cy = height / 2 + 8;
  const nodes = data.graph.nodes;
  const byKind = (kind: string) => nodes.filter((n) => n.kind === kind);
  const layout = new Map<number, { x: number; y: number; node: GraphNode }>();

  const compromised = byKind("compromised")[0];
  if (compromised) layout.set(compromised.id, { x: cx, y: cy, node: compromised });

  const place = (list: GraphNode[], r: number, start = -Math.PI / 2) => {
    list.forEach((node, i) => {
      const angle = start + (i * 2 * Math.PI) / Math.max(list.length, 1);
      const jitter = radiusFor(node.kind, i);
      layout.set(node.id, {
        x: cx + Math.cos(angle) * (r || jitter),
        y: cy + Math.sin(angle) * (r || jitter),
        node,
      });
    });
  };

  place(byKind("package"), 140);
  place(byKind("ecosystem"), 140, Math.PI / 8);
  place(byKind("service"), 230);

  const edges = data.graph.edges.filter((e) => layout.has(e.source) && layout.has(e.target));

  return (
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Blast radius graph">
      {edges.map((edge, i) => {
        const a = layout.get(edge.source)!;
        const b = layout.get(edge.target)!;
        const hot = a.node.kind === "compromised" || b.node.kind === "compromised";
        return (
          <line
            key={`${edge.source}-${edge.target}-${i}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke={hot ? "rgba(255,77,109,0.45)" : "rgba(90,167,255,0.22)"}
            strokeWidth={hot ? 1.6 : 1}
          />
        );
      })}
      {[...layout.values()].map(({ x, y, node }) => {
        const active = selected === node.name || selected === node.label;
        const r = node.kind === "compromised" ? 11 : node.kind === "service" ? 7 : 5.5;
        return (
          <g
            key={node.id}
            transform={`translate(${x},${y})`}
            style={{ cursor: node.kind === "service" ? "pointer" : "default" }}
            onClick={() => node.kind === "service" && onSelect(node.name)}
          >
            <circle
              r={r + (active ? 3 : 0)}
              fill={KIND_FILL[node.kind] || "#5aa7ff"}
              opacity={active ? 1 : 0.9}
            />
            <text
              y={r + 12}
              textAnchor="middle"
              fill={active ? "#e6eef5" : "#7d8d9c"}
              fontSize={10}
              fontFamily="IBM Plex Mono, monospace"
            >
              {node.kind === "service" ? node.name : node.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
