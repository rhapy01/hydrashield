import { useEffect, useMemo, useState } from "react";
import {
  analyze,
  fmtTime,
  ingest,
  whyLabel,
  type AnalyzeResponse,
  type DelayCost,
  type ExposedService,
  type Replay,
} from "./api";
import { BlastGraph } from "./BlastGraph";

function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 28 8v9c0 8-5.4 13.6-12 15C9.4 30.6 4 25 4 17V8l12-6Z" fill="#10241d" stroke="#3ee0b4" />
      <path d="M16 7c3 3 5 6 5 10 0 3-1.4 5.4-5 8-3.6-2.6-5-5-5-8 0-4 2-7 5-10Z" fill="#3ee0b4" />
    </svg>
  );
}

function frameAt(replay: Replay, playhead: number) {
  let current = replay.frames[0];
  for (const frame of replay.frames) {
    if (frame.at <= playhead) current = frame;
    else break;
  }
  return current;
}

export function App() {
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string>("checkout-api");
  const [showPlan, setShowPlan] = useState(false);
  const [tab, setTab] = useState<"exposed" | "contained">("exposed");
  const [queryName, setQueryName] = useState<string>("direct_lockfile_hits");
  const [ring, setRing] = useState<"org" | "ecosystem" | "adjacent">("org");
  const [playhead, setPlayhead] = useState<number>(0);
  const [playing, setPlaying] = useState(false);
  const [yankMinutes, setYankMinutes] = useState<number | null>(null);

  async function run(seed: boolean) {
    setBusy(true);
    setError(null);
    setPlaying(false);
    setYankMinutes(null);
    try {
      if (seed) await ingest();
      const result = await analyze();
      setData(result);
      setPlayhead(result.replay.t1);
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

  const replay = data?.replay;
  const frame = replay ? frameAt(replay, playhead) : undefined;
  const liveNames = frame?.exposed_names ?? data?.exposed.map((row) => row.name);
  const counterfactual = yankMinutes != null ? replay?.delay_cost.find((row) => row.minutes === yankMinutes) : undefined;

  useEffect(() => {
    if (!playing || !replay) return;
    const id = window.setInterval(() => {
      setPlayhead((head) => {
        const next = head + 2;
        if (next >= replay.t1) {
          setPlaying(false);
          return replay.t1;
        }
        return next;
      });
    }, 40);
    return () => window.clearInterval(id);
  }, [playing, replay]);

  useEffect(() => {
    if (!playing || !frame?.new.length) return;
    setSelected(frame.new[0]);
    setTab("exposed");
  }, [playing, frame?.at, frame?.new]);

  const selectedRow: ExposedService | undefined = useMemo(
    () => data?.exposed.find((row) => row.name === selected),
    [data, selected],
  );

  const hotIds = useMemo(() => {
    if (!selectedRow || (liveNames && !liveNames.includes(selectedRow.name))) return [];
    const ids = [selectedRow.id, ...selectedRow.path.map((hop) => hop.id).filter((id): id is number => id != null)];
    return ids;
  }, [selectedRow, liveNames]);

  const liveExposed = useMemo(() => {
    if (!data) return [];
    if (!liveNames) return data.exposed;
    return data.exposed.filter((row) => liveNames.includes(row.name));
  }, [data, liveNames]);

  const query = data?.queries.find((item) => item.name === queryName) ?? data?.queries[0];
  const featured = ["direct_lockfile_hits", "package_releases", "ms_paths", "sp_path", "reverse_dependents", "shared_infra", "typosquats"];

  function startReplay() {
    if (!replay) return;
    setYankMinutes(null);
    setPlayhead(replay.t0);
    setPlaying(true);
    setTab("exposed");
  }

  function jumpYank(row: DelayCost) {
    if (!replay) return;
    setPlaying(false);
    setYankMinutes(row.minutes);
    setPlayhead(row.yank_at);
    setTab("exposed");
    const firstLive = [...replay.frames].reverse().find((frame) => frame.at <= row.yank_at);
    const live = firstLive?.exposed_names[firstLive.exposed_names.length - 1];
    if (live) setSelected(live);
  }

  const spark = useMemo(() => {
    if (!replay?.frames.length) return "";
    const w = 160;
    const h = 28;
    const max = Math.max(...replay.frames.map((item) => item.exposed_count), 1);
    return replay.frames
      .map((item, i) => {
        const x = (i / Math.max(replay.frames.length - 1, 1)) * w;
        const y = h - (item.exposed_count / max) * (h - 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }, [replay]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Mark />
          <div className="wordmark">
            Hydra<span>Shield</span>
          </div>
        </div>
        <div className="tag">360-second blast radius</div>
        <div className="top-meta">
          <span>VantaPay · npm · Track 2A</span>
          <span className={`pill live`}>{data?.engine === "hydradb" ? "HydraDB · live graph" : "HydraDB required"}</span>
        </div>
      </header>

      <section className="alert">
        <div>
          <h1>
            <span className="pkg">signal-bus@2.4.1</span> was live for six minutes. Who was actually exposed?
          </h1>
          <p>
            {counterfactual
              ? `Counterfactual: yank at ${counterfactual.clock} instead of 09:06:00. ${counterfactual.saved} services stay clean` +
                (counterfactual.saved_p0.length ? `, including P0 ${counterfactual.saved_p0.join(", ")}.` : ".")
              : data?.briefing ||
                "Temporal reverse-closure on HydraDB: Service → Lockfile → PackageVersion, only where lock.resolved_at sits inside 09:00–09:06 UTC."}
          </p>
        </div>
        <div className="actions">
          <button className="btn" disabled={busy} onClick={() => void run(true)}>
            {busy ? "Querying HydraDB…" : "Ingest + analyze"}
          </button>
          <button className="btn" disabled={!replay} onClick={startReplay}>
            {playing ? "Replaying…" : "Replay 360s"}
          </button>
          <button className="btn primary" disabled={!data} onClick={() => setShowPlan(true)}>
            Containment plan
          </button>
        </div>
      </section>

      {!data && (
        <div className={`status ${error ? "error" : ""}`}>
          {error
            ? error
            : "Waiting for HydraDB. Every number on this page is OpenCypher or algo.SPpaths / MSpaths / SSpaths — there is no local graph."}
        </div>
      )}

      {data && replay && frame && (
        <main className="workspace">
          <section className="stage">
            <div className="kpis">
              <div className="kpi hot">
                <b>{frame.exposed_count}</b>
                <span>{counterfactual ? `exposed if yanked +${yankMinutes}m` : "exposed at this second"}</span>
              </div>
              <div className="kpi hot">
                <b>{frame.p0_count}</b>
                <span>P0 production</span>
              </div>
              <div className="kpi">
                <b>{counterfactual ? counterfactual.saved : data.summary.services_safe}</b>
                <span>{counterfactual ? "saved by earlier yank" : "contained / not in window"}</span>
              </div>
              <div className="kpi">
                <b>{data.summary.scanner_false_positives}</b>
                <span>scanner over-flags</span>
              </div>
            </div>
            <div className="contrast">
              <b>Why not grep?</b> A lockfile name search hits {data.contrast.scanner_name_hits} services.
              HydraDB’s time window keeps {data.contrast.hydrashield_exposed}. The extras —
              {data.contrast.false_positives.slice(0, 4).map((name) => ` ${name}`).join(",")}
              {data.contrast.false_positives.length > 4 ? "…" : ""} — pinned before 09:00 or after the yank.
            </div>
            <div className={`replay ${counterfactual ? "cf" : ""}`}>
              <div className="replay-top">
                <button className="btn compact" onClick={() => (playing ? setPlaying(false) : startReplay())}>
                  {playing ? "Pause" : "Play"}
                </button>
                <div className={`replay-clock ${counterfactual ? "cf" : ""}`}>{fmtTime(playhead)}</div>
                <div className="replay-arrivals">
                  {playing && frame.new.length
                    ? `CI lock · ${frame.new.join(", ")}`
                    : `${Math.max(playhead - replay.t0, 0)}s after publish`}
                </div>
                <svg className="spark" viewBox="0 0 160 28" aria-hidden="true">
                  <polyline fill="none" stroke="#ff4d6d" strokeWidth="1.6" points={spark} />
                </svg>
              </div>
              <input
                className="replay-scrub"
                type="range"
                min={replay.t0}
                max={replay.t1}
                value={playhead}
                onChange={(event) => {
                  setPlaying(false);
                  setYankMinutes(null);
                  setPlayhead(Number(event.target.value));
                }}
              />
              <div className="yank-row">
                <span className="yank-label">If yanked at</span>
                {replay.delay_cost.map((row) => (
                  <button
                    key={row.minutes}
                    className={`yank-chip ${yankMinutes === row.minutes ? "on" : ""}`}
                    onClick={() => jumpYank(row)}
                  >
                    +{row.minutes}m · save {row.saved}
                    {row.saved_p0.length ? ` · ${row.saved_p0[0]}` : ""}
                  </button>
                ))}
              </div>
              <p className="replay-headline">{replay.headline}</p>
            </div>
            <div className="graph-wrap">
              <BlastGraph
                data={data}
                selected={selected}
                hotIds={hotIds}
                liveNames={liveNames}
                onSelect={setSelected}
              />
              <div className="legend">
                <span>
                  <i className="swatch" style={{ background: "#ff4d6d" }} /> compromised
                </span>
                <span>
                  <i className="swatch" style={{ background: "#5aa7ff" }} /> package path
                </span>
                <span>
                  <i className="swatch" style={{ background: "#3ee0b4" }} /> live this second
                </span>
                <span>play the six minutes · dimmed nodes have not resolved yet</span>
              </div>
            </div>
            {data.blast?.introducing.releases.length ? (
            <div className="timeline releases">
              {data.blast.introducing.releases.map((rel, index) => (
                <span key={rel.version} className="release-pair">
                  {index > 0 ? <span className="tl-line" /> : null}
                  <div className={`tl-item ${rel.role}`}>
                    <i className={`tl-dot ${rel.role === "introduced" ? "bad" : rel.role === "patched" ? "ok" : ""}`} />
                    {data.blast.introducing.package}@{rel.version}
                    {rel.role === "introduced" ? " · introduced" : rel.role === "prior_clean" ? " · clean" : rel.role === "patched" ? " · patched" : ""}
                  </div>
                </span>
              ))}
            </div>
            ) : null}
          </section>

          <aside className="side">
            <div className="tabs">
              <button className={tab === "exposed" ? "on" : ""} onClick={() => setTab("exposed")}>
                Exposed ({liveExposed.length}
                {liveExposed.length !== data.exposed.length ? `/${data.exposed.length}` : ""})
              </button>
              <button className={tab === "contained" ? "on" : ""} onClick={() => setTab("contained")}>
                Contained ({data.contained.length})
              </button>
            </div>
            {tab === "exposed" ? (
              <div className="list">
                {liveExposed.map((row) => (
                  <button
                    key={row.name}
                    className={`svc ${selected === row.name ? "active" : ""} ${frame.new.includes(row.name) ? "arriving" : ""}`}
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
            ) : (
              <div className="list">
                {data.contained.map((row) => (
                  <div key={row.name} className="svc contained">
                    <span className={`crit ${row.criticality}`}>{row.criticality}</span>
                    <span>
                      <div className="name">{row.name}</div>
                      <div className="meta">
                        {whyLabel(row.why)}
                        {row.pinned_version ? ` · signal-bus@${row.pinned_version}` : ""}
                        {row.resolved_at ? ` · ${fmtTime(row.resolved_at)}` : ""}
                      </div>
                    </span>
                  </div>
                ))}
              </div>
            )}
            {showPlan ? (
              <div className="plan">
                <h3>Containment sequence</h3>
                <p>{data.remediation.summary}</p>
                <ol>
                  {data.remediation.steps.map((step) => (
                    <li key={step.package}>
                      <code>{step.package}</code>
                      {step.to_version ? `@${step.to_version}` : ""} — {step.reason} Residual {step.residual}.
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
              selectedRow &&
              tab === "exposed" &&
              liveNames?.includes(selectedRow.name) && (
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
            {counterfactual && !showPlan && (
              <div className="plan cf-note">
                <h3>Still clean at {counterfactual.clock}</h3>
                <p>
                  {counterfactual.saved_names.slice(0, 8).join(", ")}
                  {counterfactual.saved_names.length > 8 ? "…" : ""}
                </p>
              </div>
            )}
          </aside>
        </main>
      )}

      {data?.blast && (
        <>
          <section className="blast-board">
            <div className="blast-head">
              <h2>Complete blast radius</h2>
              <p>{data.blast.answers[5]?.a}</p>
            </div>
            <div className="rings">
              {(
                [
                  ["org", data.blast.rings.org],
                  ["ecosystem", data.blast.rings.ecosystem],
                  ["adjacent", data.blast.rings.adjacent],
                ] as const
              ).map(([key, item]) => (
                <button key={key} className={`ring ${ring === key ? "on" : ""}`} onClick={() => setRing(key)}>
                  <b>{item.count}</b>
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
            <p className="ring-why">{data.blast.rings[ring].why}</p>
            <div className="ring-names">
              {data.blast.rings[ring].names.slice(0, 16).map((name) => (
                <code key={name}>{name}</code>
              ))}
              {data.blast.rings[ring].names.length > 16 ? <span>…</span> : null}
            </div>
            <div className="answers">
              {data.blast.answers.slice(0, 5).map((item) => (
                <div key={item.q}>
                  <b>{item.q}</b>
                  <span>{item.a}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="drawer">
            <h2>
              HydraDB queries this page ran ·{" "}
              <select
                value={query?.name}
                onChange={(event) => setQueryName(event.target.value)}
                className="pill"
              >
                {data.queries.map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name}
                    {featured.includes(item.name) ? " ★" : ""}
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
                {query.row_count} rows · snapshot-consistent read · engine {data.engine}
              </pre>
            )}
          </section>
        </>
      )}
    </div>
  );
}
