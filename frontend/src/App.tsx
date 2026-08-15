import { useEffect, useMemo, useState } from "react";
import { analyze, fmtTime, ingest, type AnalyzeResponse, type ExposedService } from "./api";
import { BlastGraph } from "./BlastGraph";

function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 28 8v9c0 8-5.4 13.6-12 15C9.4 30.6 4 25 4 17V8l12-6Z" fill="#10241d" stroke="#3ee0b4" />
      <path d="M16 7c3 3 5 6 5 10 0 3-1.4 5.4-5 8-3.6-2.6-5-5-5-8 0-4 2-7 5-10Z" fill="#3ee0b4" />
    </svg>
  );
}

export function App() {
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string>("checkout-api");
  const [showPlan, setShowPlan] = useState(false);
  const [queryName, setQueryName] = useState<string>("direct_lockfile_hits");

  async function run(seed: boolean) {
    setBusy(true);
    setError(null);
    try {
      if (seed) await ingest();
      const result = await analyze();
      setData(result);
      const first = result.exposed[0]?.name;
      if (first) setSelected(first);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void run(false);
  }, []);

  const selectedRow: ExposedService | undefined = useMemo(
    () => data?.exposed.find((row) => row.name === selected),
    [data, selected],
  );

  const query = data?.queries.find((item) => item.name === queryName) ?? data?.queries[0];

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Mark />
          <div className="wordmark">
            Hydra<span>Shield</span>
          </div>
        </div>
        <div className="tag">Incident response for dependency graphs</div>
        <div className="top-meta">
          <span>VantaPay · npm</span>
          <span className="pill live">{data?.engine === "hydradb" ? "HydraDB · live" : "HydraDB required"}</span>
        </div>
      </header>

      <section className="alert">
        <div>
          <h1>
            Package <span className="pkg">signal-bus@2.4.1</span> compromised at 09:00
          </h1>
          <p>
            Which VantaPay services were exposed by 09:06, through which dependency path, and what
            should we upgrade first? Temporal reverse-closure over HydraDB — not a scanner match list.
          </p>
        </div>
        <div className="actions">
          <button className="btn" disabled={busy} onClick={() => void run(true)}>
            {busy ? "Querying…" : "Ingest + analyze"}
          </button>
          <button className="btn primary" disabled={!data} onClick={() => setShowPlan(true)}>
            Generate remediation plan
          </button>
        </div>
      </section>

      {!data && (
        <div className={`status ${error ? "error" : ""}`}>
          {error
            ? error
            : "Waiting for HydraDB. Every query in this product is OpenCypher on graph-node — there is no local graph."}
        </div>
      )}

      {data && (
        <main className="workspace">
          <section className="stage">
            <div className="kpis">
              <div className="kpi hot">
                <b>{data.summary.services_exposed}</b>
                <span>services exposed</span>
              </div>
              <div className="kpi hot">
                <b>{data.summary.p0_exposed}</b>
                <span>P0 production</span>
              </div>
              <div className="kpi">
                <b>{data.summary.ecosystem_dependents}</b>
                <span>ecosystem dependents</span>
              </div>
              <div className="kpi">
                <b>{data.summary.window_seconds}s</b>
                <span>live malicious window</span>
              </div>
            </div>
            <div className="graph-wrap">
              <BlastGraph data={data} selected={selected} onSelect={setSelected} />
              <div className="legend">
                <span>
                  <i className="swatch" style={{ background: "#ff4d6d" }} /> compromised
                </span>
                <span>
                  <i className="swatch" style={{ background: "#5aa7ff" }} /> package path
                </span>
                <span>
                  <i className="swatch" style={{ background: "#3ee0b4" }} /> service
                </span>
              </div>
            </div>
            <div className="timeline">
              <div className="tl-item">
                <i className="tl-dot" /> 08:41 ledger-worker still on 2.4.0
              </div>
              <div className="tl-line" />
              <div className="tl-item">
                <i className="tl-dot bad" /> 09:00 publish 2.4.1
              </div>
              <div className="tl-line" />
              <div className="tl-item">
                <i className="tl-dot bad" /> 09:02–09:05 CI lockfiles
              </div>
              <div className="tl-line" />
              <div className="tl-item">
                <i className="tl-dot ok" /> 09:06 yanked
              </div>
              <div className="tl-line" />
              <div className="tl-item">
                <i className="tl-dot ok" /> 09:12 webhook-relay on 2.4.2
              </div>
            </div>
          </section>

          <aside className="side">
            <h2>Ranked exposure</h2>
            <div className="list">
              {data.exposed.map((row) => (
                <button
                  key={row.name}
                  className={`svc ${selected === row.name ? "active" : ""}`}
                  onClick={() => {
                    setSelected(row.name);
                    setShowPlan(false);
                  }}
                >
                  <span className={`crit ${row.criticality}`}>{row.criticality}</span>
                  <span>
                    <div className="name">{row.name}</div>
                    <div className="meta">
                      {row.env} · {row.team} · depth {row.depth} · {fmtTime(row.resolved_at)}
                    </div>
                  </span>
                  <span className="score">{row.score.toFixed(2)}</span>
                </button>
              ))}
            </div>
            {showPlan ? (
              <div className="plan">
                <h3>Remediation sequence</h3>
                <p>{data.remediation.summary}</p>
                <ol>
                  {data.remediation.steps.map((step) => (
                    <li key={step.package}>
                      <code>{step.package}</code>
                      {step.to_version ? `@${step.to_version}` : ""} — {step.reason} Residual{" "}
                      {step.residual}.
                    </li>
                  ))}
                  <li>{data.remediation.rotate.reason}</li>
                  {data.remediation.review.map((item) => (
                    <li key={item.package}>
                      Review <code>{item.package}</code>: {item.reason}
                    </li>
                  ))}
                  {data.remediation.block.map((item) => (
                    <li key={item.package}>
                      Block <code>{item.package}</code> at the proxy.
                    </li>
                  ))}
                </ol>
              </div>
            ) : (
              selectedRow && (
                <div className="evidence">
                  <h3>
                    Evidence · {selectedRow.name} · {selectedRow.env}
                  </h3>
                  <div className="path">
                    <span className="hop">{selectedRow.name}</span>
                    <span className="arrow">→</span>
                    <span className="hop">{selectedRow.application}</span>
                    {selectedRow.path.map((hop) => (
                      <span key={`${hop.name}@${hop.version}`}>
                        <span className="arrow"> → </span>
                        <span className={`hop ${hop.name === "signal-bus" ? "bad" : ""}`}>
                          {hop.name}@{hop.version}
                        </span>
                      </span>
                    ))}
                  </div>
                </div>
              )
            )}
          </aside>
        </main>
      )}

      {data && (
        <>
          <section className="neighborhood">
            <div className="nb">
              <h3>Shared maintainers</h3>
              <ul>
                {data.maintainers.slice(0, 6).map((row) => (
                  <li key={row.name}>
                    <code>{row.name}</code> · {row.npm_user}
                  </li>
                ))}
              </ul>
            </div>
            <div className="nb">
              <h3>Shared publishing infra</h3>
              <ul>
                {data.infrastructure.slice(0, 6).map((row) => (
                  <li key={row.name + row.infra}>
                    <code>{row.name}</code> · {row.infra}
                  </li>
                ))}
              </ul>
            </div>
            <div className="nb">
              <h3>Typosquat neighborhood</h3>
              <ul>
                {data.typosquats.map((row) => (
                  <li key={row.name}>
                    <code>{row.name}</code>
                  </li>
                ))}
              </ul>
            </div>
          </section>
          <section className="drawer">
            <h2>
              OpenCypher on HydraDB ·{" "}
              <select
                value={query?.name}
                onChange={(event) => setQueryName(event.target.value)}
                className="pill"
              >
                {data.queries.map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name}
                  </option>
                ))}
              </select>
            </h2>
            {query && (
              <pre>
                {query.cypher}
                {"\n\n"}
                {JSON.stringify(query.parameters, null, 2)}
                {"\n\n"}
                {query.row_count} rows · snapshot-consistent read
              </pre>
            )}
          </section>
        </>
      )}
    </div>
  );
}
