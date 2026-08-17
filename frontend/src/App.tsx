import { useEffect, useMemo, useRef, useState } from "react";
import {
  analyze,
  clockOf,
  clockToTs,
  fmtTime,
  ingest,
  listPackages,
  listVersions,
  health,
  uploadLockfile,
  whyLabel,
  whyDetail,
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
  const lockInput = useRef<HTMLInputElement>(null);
  const [playhead, setPlayhead] = useState<number>(0);
  const [playing, setPlaying] = useState(false);
  const [yankMinutes, setYankMinutes] = useState<number | null>(null);
  const [pkg, setPkg] = useState("signal-bus");
  const [ver, setVer] = useState("2.4.1");
  const [t0clock, setT0clock] = useState("09:00:00");
  const [t1clock, setT1clock] = useState("09:06:00");
  const [packages, setPackages] = useState<string[]>(["signal-bus"]);
  const [versions, setVersions] = useState<string[]>(["2.4.0", "2.4.1", "2.4.2"]);
  const [hydra, setHydra] = useState<{ hydradb: boolean; ingested: boolean } | null>(null);
  const [screen, setScreen] = useState<"home" | "desk">(() =>
    new URLSearchParams(window.location.search).get("open") === "1" ? "desk" : "home",
  );
  const [helpOpen, setHelpOpen] = useState(false);

  function enterDesk() {
    setScreen("desk");
    history.replaceState(null, "", `${window.location.pathname}?open=1`);
  }

  function leaveDesk() {
    setScreen("home");
    setHelpOpen(false);
    history.replaceState(null, "", window.location.pathname);
  }

  function applyResult(result: AnalyzeResponse) {
    setData(result);
    setPlayhead(result.replay.t1);
    setPkg(result.incident.package);
    setVer(result.incident.version);
    setT0clock(clockOf(result.incident.start_ts));
    setT1clock(clockOf(result.incident.end_ts));
    const rels = result.blast?.introducing.releases.map((row) => row.version).filter(Boolean);
    if (rels?.length) setVersions(rels);
    setYankMinutes(null);
    setPlaying(false);
    setSelected((current) => {
      const names = result.exposed.map((row) => row.name);
      if (current && names.includes(current)) return current;
      if (names.includes("checkout-api")) return "checkout-api";
      return names[0] || current;
    });
  }

  async function run(seed: boolean) {
    setBusy(true);
    setError(null);
    setPlaying(false);
    setYankMinutes(null);
    try {
      if (seed) await ingest();
      const body: { package: string; version: string; start_ts?: number; end_ts?: number } = {
        package: pkg,
        version: ver,
      };
      if (data) {
        const base = data.incident.start_ts;
        body.start_ts = clockToTs(base, t0clock);
        body.end_ts = clockToTs(base, t1clock);
      }
      applyResult(await analyze(body));
      enterDesk();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void listPackages().then((names) => {
      if (names.length) setPackages([...new Set(names)].sort());
    });
    if (new URLSearchParams(window.location.search).get("open") === "1") void run(false);
  }, []);

  useEffect(() => {
    let alive = true;
    async function ping() {
      try {
        const body = await health();
        if (alive) setHydra({ hydradb: body.hydradb, ingested: body.ingested });
      } catch {
        if (alive) setHydra({ hydradb: false, ingested: false });
      }
    }
    void ping();
    const id = window.setInterval(ping, 15000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
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
          setTab("exposed");
          setSelected("checkout-api");
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

  const selectedContained = useMemo(
    () => data?.contained.find((row) => row.name === selected),
    [data, selected],
  );

  const selectedRow: ExposedService | undefined = useMemo(
    () => data?.exposed.find((row) => row.name === selected),
    [data, selected],
  );

  useEffect(() => {
    document.querySelector(".svc.active")?.scrollIntoView({ block: "nearest" });
  }, [selected, tab]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const tag = (event.target as HTMLElement | null)?.tagName;
      if (screen !== "desk") return;
      if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
      if (event.key === " " || event.code === "Space") {
        event.preventDefault();
        if (playing) setPlaying(false);
        else startReplay();
        return;
      }
      if (event.key === "2" && replay) {
        const row = replay.delay_cost.find((item) => item.minutes === 2);
        if (row) jumpYank(row);
        return;
      }
      if (event.key === "Escape" || event.key === "6") {
        setYankMinutes(null);
        if (replay) setPlayhead(replay.t1);
        return;
      }
      if (event.key === "c" || event.key === "C") {
        setTab("contained");
        setShowPlan(false);
        const preferred = data?.contained.find((row) => row.name === "ledger-worker") || data?.contained[0];
        if (preferred) setSelected(preferred.name);
        return;
      }
      if (event.key === "e" || event.key === "E") {
        setTab("exposed");
        setShowPlan(false);
        if (data?.exposed.some((row) => row.name === "checkout-api")) setSelected("checkout-api");
        return;
      }
      if (event.key === "p" || event.key === "P") setShowPlan((open) => !open);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [playing, replay, data, screen]);

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

  const reportHref = (() => {
    const params = new URLSearchParams({ package: pkg, version: ver });
    if (data) {
      const base = data.incident.start_ts;
      params.set("start_ts", String(clockToTs(base, t0clock)));
      params.set("end_ts", String(clockToTs(base, t1clock)));
    }
    return `/api/analyze/report?${params.toString()}`;
  })();

  const query = data?.queries.find((item) => item.name === queryName) ?? data?.queries[0];
  const featured = ["compromised_in", "direct_lockfile_hits", "lockfile_pins", "package_releases", "ms_paths", "sp_path", "reverse_dependents", "shared_infra", "typosquats"];

  async function onLockfile(file: File | undefined) {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      await uploadLockfile(file);
      applyResult(await analyze(data ? { package: pkg, version: ver, start_ts: data.incident.start_ts, end_ts: data.incident.end_ts } : {}));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
      if (lockInput.current) lockInput.current.value = "";
    }
  }

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
    <div className={`app ${busy ? "is-busy" : ""} ${screen === "home" ? "is-home" : "is-desk"}`}>
      {busy ? <div className="busy-mask">{screen === "home" ? "Opening incident…" : "Querying HydraDB…"}</div> : null}
      <header className="topbar">
        <button className="brand" type="button" onClick={leaveDesk} aria-label="HydraShield home">
          <Mark />
          <div className="wordmark">
            Hydra<span>Shield</span>
          </div>
        </button>
        {screen === "desk" ? (
          <button className="crumb" type="button" onClick={leaveDesk}>
            Incidents
          </button>
        ) : (
          <div className="tag">Workspace · VantaPay</div>
        )}
        <div className="top-meta">
          <span className={`pill ${hydra?.hydradb ? "live" : ""}`}>
            {hydra?.hydradb ? "HydraDB connected" : "HydraDB required"}
          </span>
          {screen === "desk" ? (
            <button className="help-btn" type="button" onClick={() => setHelpOpen((open) => !open)} aria-expanded={helpOpen}>
              Help
            </button>
          ) : null}
        </div>
      </header>
      {helpOpen && screen === "desk" ? (
        <div className="help-pop">
          <p>Space play/pause · 2 yank +2m · C contained · E exposed · P plan · Esc full window</p>
          <a href="/hydradb-story.html" target="_blank" rel="noreferrer">
            How HydraDB is queried
          </a>
        </div>
      ) : null}

      {screen === "home" ? (
        <section className="home">
          <div className="home-copy">
            <p className="eyebrow">Supply-chain incident desk</p>
            <h1>A dependency just went bad. Who in this fleet pulled it while it was live?</h1>
            <p className="lede">
              Open an incident for the package and the minutes it was on the registry. You get who actually
              resolved that version, the path from a direct dependency, and what to upgrade first.
            </p>
          </div>
          <div className="home-grid">
            <article className="ticket">
              <div className="ticket-kicker">
                <span className="sev">SEV-1</span>
                <span className="mono">INC-2026-0514-SIGNAL-BUS</span>
              </div>
              <h2>
                <span className="pkg">signal-bus@2.4.1</span> on the registry for six minutes
              </h2>
              <dl className="ticket-facts">
                <div>
                  <dt>Published</dt>
                  <dd>09:00 UTC</dd>
                </div>
                <div>
                  <dt>Yanked</dt>
                  <dd>09:06 UTC</dd>
                </div>
                <div>
                  <dt>Org</dt>
                  <dd>VantaPay</dd>
                </div>
              </dl>
              <p>
                Published at 09:00, yanked at 09:06. Open it to see which services resolved{" "}
                <code>2.4.1</code> in those six minutes, and the upgrade order.
              </p>
              <button className="btn primary lg" disabled={busy} onClick={() => void run(false)}>
                Open incident
              </button>
            </article>
            <article className="ask">
              <h2>Different package or window</h2>
              <p>Uses this workspace’s lockfiles. Same question: who resolved it while it was live?</p>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void run(false);
                }}
              >
                <label>
                  Package
                  <select
                    value={pkg}
                    onChange={(event) => {
                      const name = event.target.value;
                      setPkg(name);
                      void listVersions(name).then((rels) => {
                        if (!rels.length) return;
                        setVersions(rels);
                        setVer((current) => (rels.includes(current) ? current : rels[rels.length - 1]));
                      });
                    }}
                  >
                    {(packages.includes(pkg) ? packages : [pkg, ...packages]).map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Version
                  <select value={ver} onChange={(event) => setVer(event.target.value)}>
                    {(versions.includes(ver) ? versions : [ver, ...versions]).map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="ask-row">
                  <label>
                    From
                    <input value={t0clock} onChange={(event) => setT0clock(event.target.value)} spellCheck={false} />
                  </label>
                  <label>
                    To
                    <input value={t1clock} onChange={(event) => setT1clock(event.target.value)} spellCheck={false} />
                  </label>
                </div>
                <button className="btn" type="submit" disabled={busy}>
                  Analyze window
                </button>
              </form>
            </article>
          </div>
          <ol className="home-steps">
            <li>
              <b>Pick the version and the clock</b>
              <span>From publish until yank — only that window counts as exposure.</span>
            </li>
            <li>
              <b>See who was in the blast</b>
              <span>Only services that resolved that version during the window.</span>
            </li>
            <li>
              <b>Follow the path, then contain</b>
              <span>From the package.json pin to the upgrade that removes it.</span>
            </li>
          </ol>
          {error ? <div className="status error banner">{error}</div> : null}
        </section>
      ) : (
        <>
      <section className="incident">
        <div>
          <p className="incident-id">{data?.incident.slug || "INC-2026-0514-SIGNAL-BUS"}</p>
          <h1>
            <span className="pkg">
              {data?.incident.package || pkg}@{data?.incident.version || ver}
            </span>
            <span className="incident-window">
              {t0clock.slice(0, 5)}–{t1clock.slice(0, 5)} UTC
            </span>
          </h1>
          <p>
            {counterfactual
              ? `If yanked at ${counterfactual.clock}: ${counterfactual.saved} services stay clean` +
                (counterfactual.saved_p0.length ? `, including ${counterfactual.saved_p0.join(", ")}.` : ".")
              : data?.briefing || "Services that resolved this version while it was on the registry."}
          </p>
        </div>
        <div className="actions">
          <button className="btn" disabled={!replay} onClick={startReplay}>
            {playing ? "Replaying…" : "Replay window"}
          </button>
          <button className="btn primary" disabled={!data} onClick={() => setShowPlan(true)}>
            Containment plan
          </button>
          <a className="btn" href={reportHref} download="hydrashield-report.md">
            Report
          </a>
        </div>
      </section>

      <form
        className="incident-bar"
        onSubmit={(event) => {
          event.preventDefault();
          void run(false);
        }}
      >
        <label>
          Package
          <select
            value={pkg}
            onChange={(event) => {
              const name = event.target.value;
              setPkg(name);
              void listVersions(name).then((rels) => {
                if (!rels.length) return;
                setVersions(rels);
                setVer((current) => (rels.includes(current) ? current : rels[rels.length - 1]));
              });
            }}
          >
            {(packages.includes(pkg) ? packages : [pkg, ...packages]).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Version
          <select value={ver} onChange={(event) => setVer(event.target.value)}>
            {(versions.includes(ver) ? versions : [ver, ...versions]).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label>
          From
          <input value={t0clock} onChange={(event) => setT0clock(event.target.value)} spellCheck={false} />
        </label>
        <label>
          To
          <input value={t1clock} onChange={(event) => setT1clock(event.target.value)} spellCheck={false} />
        </label>
        <button className="btn compact" type="submit" disabled={busy}>
          Apply window
        </button>
        <button
          className="btn compact"
          type="button"
          disabled={!data || busy}
          onClick={() => {
            setT0clock("09:00:00");
            setT1clock("09:06:00");
            if (!data) return;
            const base = data.incident.start_ts;
            setBusy(true);
            void analyze({
              package: pkg,
              version: ver,
              start_ts: clockToTs(base, "09:00:00"),
              end_ts: clockToTs(base, "09:06:00"),
            })
              .then(applyResult)
              .catch((err) => setError(err instanceof Error ? err.message : String(err)))
              .finally(() => setBusy(false));
          }}
        >
          Full window
        </button>
        <button
          className="btn compact"
          type="button"
          disabled={!data || busy}
          onClick={() => {
            setT0clock("09:00:00");
            setT1clock("09:02:00");
            if (!data) return;
            const base = data.incident.start_ts;
            setBusy(true);
            void analyze({
              package: pkg,
              version: ver,
              start_ts: clockToTs(base, "09:00:00"),
              end_ts: clockToTs(base, "09:02:00"),
            })
              .then(applyResult)
              .catch((err) => setError(err instanceof Error ? err.message : String(err)))
              .finally(() => setBusy(false));
          }}
        >
          Yank +2m
        </button>
        <button className="btn compact ghost" disabled={busy} onClick={() => void run(true)} type="button">
          Re-ingest
        </button>
        <button className="btn compact ghost" disabled={busy} type="button" onClick={() => lockInput.current?.click()}>
          Add lockfile
        </button>
        <input
          ref={lockInput}
          type="file"
          accept="application/json,.json"
          hidden
          onChange={(event) => void onLockfile(event.target.files?.[0])}
        />
      </form>

      {error && data && <div className="status error banner">{error}</div>}

      {!data && (
        <div className={`status ${error ? "error" : ""}`}>
          {error
            ? error
            : "Connecting to HydraDB…"}
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
            <div className="insight">
              A lockfile name search hits {data.contrast.scanner_name_hits} services.
              This window keeps {data.contrast.hydrashield_exposed}. The rest pinned before
              publish or after the yank.
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
                arriving={frame.new}
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
              <p className="release-why">{data.blast.introducing.why}</p>
              <div className="release-row">
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
            </div>
            ) : null}
          </section>

          <aside className="side">
            <div className="tabs">
              <button
                className={tab === "exposed" ? "on" : ""}
                onClick={() => {
                  setTab("exposed");
                  setShowPlan(false);
                  if (data.exposed.some((row) => row.name === "checkout-api")) setSelected("checkout-api");
                }}
              >
                Exposed ({liveExposed.length}
                {liveExposed.length !== data.exposed.length ? `/${data.exposed.length}` : ""})
              </button>
              <button
                className={tab === "contained" ? "on" : ""}
                onClick={() => {
                  setTab("contained");
                  setShowPlan(false);
                  const preferred = data.contained.find((row) => row.name === "ledger-worker") || data.contained[0];
                  if (preferred) setSelected(preferred.name);
                }}
              >
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
                  <button
                    key={row.name}
                    className={`svc contained ${selected === row.name ? "active" : ""}`}
                    onClick={() => {
                      setSelected(row.name);
                      setShowPlan(false);
                    }}
                  >
                    <span className={`crit ${row.criticality}`}>{row.criticality}</span>
                    <span>
                      <div className="name">{row.name}</div>
                      <div className="meta">
                        {whyLabel(row.why)}
                        {row.pinned_version ? ` · ${data.incident.package}@${row.pinned_version}` : ""}
                        {row.resolved_at ? ` · ${fmtTime(row.resolved_at)}` : ""}
                      </div>
                    </span>
                  </button>
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
                  {data.next_hop.packages.length ? (
                    <li>
                      {data.next_hop.reason}{" "}
                      {data.next_hop.packages
                        .map((item) => item.name)
                        .slice(0, 6)
                        .join(", ")}
                    </li>
                  ) : null}
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
            ) : tab === "contained" && selectedContained ? (
              <div className="evidence">
                <h3>
                  Contained · {selectedContained.name} · {selectedContained.env}
                </h3>
                <p className="evidence-why">{whyDetail(selectedContained, data.incident.package)}</p>
                <div className="path">
                  <span className="hop">{selectedContained.name}</span>
                  {selectedContained.pinned_version ? (
                    <>
                      <span className="arrow">→</span>
                      <span className="hop">
                        {data.incident.package}@{selectedContained.pinned_version}
                      </span>
                    </>
                  ) : null}
                  {selectedContained.resolved_at ? (
                    <>
                      <span className="arrow">→</span>
                      <span className="hop">{fmtTime(selectedContained.resolved_at)}</span>
                    </>
                  ) : null}
                </div>
              </div>
            ) : (
              selectedRow &&
              tab === "exposed" &&
              liveNames?.includes(selectedRow.name) && (
                <div className="evidence">
                  <h3>
                    Evidence · {selectedRow.name} · {selectedRow.env}
                    <button
                      className="btn compact"
                      type="button"
                      onClick={() => {
                        const hops = [
                          selectedRow.name,
                          selectedRow.application,
                          ...selectedRow.path.map((hop) => `${hop.name}@${hop.version}`),
                        ];
                        void navigator.clipboard.writeText(hops.join(" → "));
                      }}
                    >
                      Copy path
                    </button>
                  </h3>
                  <p className="evidence-why">
                    Starts at a package.json pin (<code>Lockfile-[:PINS]-&gt;</code>), not a
                    flattened transitive hop. Path from HydraDB{" "}
                    <code>
                      {data.path_engine === "ms_paths"
                        ? "algo.MSpaths"
                        : data.path_engine === "sp_path"
                          ? "algo.SPpaths"
                          : "MATCH"}
                    </code>
                    .
                  </p>
                  <div className="path">
                    <span className="hop">{selectedRow.name}</span>
                    <span className="arrow">→</span>
                    <span className="hop">{selectedRow.application}</span>
                    {selectedRow.path.map((hop) => (
                      <span key={`${hop.name}@${hop.version}`}>
                        <span className="arrow"> → </span>
                        <span className={`hop ${hop.name === data.incident.package ? "bad" : ""}`}>
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
            {ring === "adjacent" ? (
              <div className="ring-split">
                <div>
                  <h3>Shared maintainers</h3>
                  {(data.blast.rings.adjacent.maintainers || []).map((name) => (
                    <code key={name}>{name}</code>
                  ))}
                </div>
                <div>
                  <h3>Same publishing infra</h3>
                  {(data.blast.rings.adjacent.infra || []).map((name) => (
                    <code key={name}>{name}</code>
                  ))}
                </div>
                <div>
                  <h3>Typosquats</h3>
                  {(data.blast.rings.adjacent.typosquats || []).map((name) => (
                    <code key={name}>{name}</code>
                  ))}
                </div>
              </div>
            ) : (
              <div className="ring-names">
                {data.blast.rings[ring].names.slice(0, 16).map((name) => (
                  <code key={name}>{name}</code>
                ))}
                {data.blast.rings[ring].names.length > 16 ? <span>…</span> : null}
              </div>
            )}
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
                {data.queries.map((item, idx) => (
                  <option key={`${item.name}-${idx}`} value={item.name}>
                    {item.name}
                    {featured.includes(item.name) ? " ★" : ""}
                  </option>
                ))}
              </select>
              {query ? (
                <button
                  className="btn compact drawer-copy"
                  type="button"
                  onClick={() => void navigator.clipboard.writeText(query.cypher)}
                >
                  Copy Cypher
                </button>
              ) : null}
            </h2>
            {query && (
              <pre>
                {query.cypher}
                {"\n\n"}
                {JSON.stringify(query.parameters, null, 2)}
                {"\n\n"}
                {query.row_count} rows · snapshot-consistent read · engine {data.engine}
                {typeof query.parameters?.error === "string" ? `\n\nprocedure error: ${query.parameters.error}` : ""}
              </pre>
            )}
          </section>
        </>
      )}
        </>
      )}
    </div>
  );
}
