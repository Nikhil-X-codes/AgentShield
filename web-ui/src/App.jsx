import { useCallback, useEffect, useMemo, useState } from "react";

const API = "http://127.0.0.1:8000/api";
const statusLabel = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

async function request(path, options) {
  const response = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

function timeLabel(value) {
  return value ? new Date(value).toLocaleString() : "—";
}

function App() {
  const [profiles, setProfiles] = useState([]);
  const [runs, setRuns] = useState([]);
  const [profile, setProfile] = useState("finance-mock");
  const [categories, setCategories] = useState([]);
  const [maxCases, setMaxCases] = useState(10);
  const [selectedId, setSelectedId] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const selectedProfile = useMemo(
    () => profiles.find((item) => item.id === profile),
    [profiles, profile],
  );
  const selectedRun = useMemo(
    () => runs.find((item) => item.id === selectedId),
    [runs, selectedId],
  );

  const refresh = useCallback(async () => {
    try {
      const [profileRows, runRows] = await Promise.all([
        request("/profiles"),
        request("/runs"),
      ]);
      setProfiles(profileRows);
      setRuns(runRows);
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);
  useEffect(() => {
    const timer = window.setInterval(refresh, 1200);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    setCategories([]);
  }, [profile]);

  useEffect(() => {
    let active = true;
    if (!selectedId || selectedRun?.status !== "completed") {
      setReport(null);
      return () => {
        active = false;
      };
    }
    request(`/runs/${selectedId}/report`)
      .then((value) => {
        if (active) setReport(value);
      })
      .catch((err) => {
        if (active) setError(err.message);
      });
    return () => {
      active = false;
    };
  }, [selectedId, selectedRun?.status]);

  async function startRun(event) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const run = await request("/runs", {
        method: "POST",
        body: JSON.stringify({
          profile,
          categories: categories.length ? categories : null,
          max_cases: Number(maxCases),
        }),
      });
      setSelectedId(run.id);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  function toggleCategory(category) {
    setCategories((current) =>
      current.includes(category)
        ? current.filter((item) => item !== category)
        : [...current, category],
    );
  }

  const findings = report?.findings || [];
  const confirmedCount = findings.filter(
    (item) => item.outcome === "confirmed",
  ).length;
  const highCount = findings.filter((item) =>
    ["critical", "high"].includes(item.severity),
  ).length;

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <span className="brand-mark">A</span>
          <span>AgentShield</span>
        </div>
        <div className="rail-divider" />
        <div className="rail-label">Workspace</div>
        <div className="rail-link active">
          <span className="rail-icon">◈</span> Assessments
        </div>
        <div className="rail-link muted">
          <span className="rail-icon">▤</span> Reports
        </div>
        <div className="rail-bottom">
          <span className="live-dot" /> Local synthetic mode
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <div className="eyebrow">
              SECURITY WORKSPACE <span className="slash">/</span> OVERVIEW
            </div>
            <h1>Assessment control room</h1>
          </div>
          <div className="local-pill">
            <span className="live-dot" /> LOCAL ONLY{" "}
            <span className="pill-separator" /> API connected
          </div>
        </header>

        {error && (
          <div className="alert" role="alert">
            <span>!</span>
            {error}
            <button onClick={() => setError("")} aria-label="Dismiss">
              ×
            </button>
          </div>
        )}

        <section className="metrics">
          <div className="metric-card">
            <div className="metric-top">
              <span>Total runs</span>
              <span className="metric-icon blue">▣</span>
            </div>
            <strong>{runs.length}</strong>
            <small>Latest 50 assessments</small>
          </div>
          <div className="metric-card">
            <div className="metric-top">
              <span>In progress</span>
              <span className="metric-icon amber">◷</span>
            </div>
            <strong>
              {
                runs.filter((run) => ["queued", "running"].includes(run.status))
                  .length
              }
            </strong>
            <small>Queued or executing</small>
          </div>
          <div className="metric-card">
            <div className="metric-top">
              <span>Confirmed findings</span>
              <span className="metric-icon red">⌁</span>
            </div>
            <strong>{confirmedCount}</strong>
            <small>{highCount} high or critical in selected report</small>
          </div>
          <div className="metric-card">
            <div className="metric-top">
              <span>Runtime boundary</span>
              <span className="metric-icon green">⌖</span>
            </div>
            <strong>Mock</strong>
            <small>Registered synthetic profiles only</small>
          </div>
        </section>

        <section className="content-grid">
          <div className="panel launch-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">NEW SECURITY RUN</div>
                <h2>Configure assessment</h2>
              </div>
              <span className="step-badge">
                01 <span>/ 01</span>
              </span>
            </div>
            <p className="panel-copy">
              Choose a bundled mock agent. Scope is fixed by the server profile;
              URLs and commands cannot be submitted here.
            </p>
            <form onSubmit={startRun}>
              <label className="field-label" htmlFor="profile">
                Target profile
              </label>
              <select
                id="profile"
                value={profile}
                onChange={(event) => setProfile(event.target.value)}
                disabled={loading}
              >
                {profiles.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
              <div className="profile-note">
                {selectedProfile?.description || "Loading registered profiles…"}
              </div>
              <div className="field-row">
                <div className="field-block">
                  <label className="field-label" htmlFor="max-cases">
                    Maximum cases
                  </label>
                  <div className="number-wrap">
                    <input
                      id="max-cases"
                      type="number"
                      min="1"
                      max="40"
                      value={maxCases}
                      onChange={(event) => setMaxCases(event.target.value)}
                    />
                    <span>cases</span>
                  </div>
                </div>
                <div className="field-block">
                  <span className="field-label">Execution mode</span>
                  <div className="mode-chip">
                    <span className="live-dot" /> Static baseline
                  </div>
                </div>
              </div>
              <div className="field-label category-label">
                Attack categories{" "}
                <span>Optional · choose none to use profile defaults</span>
              </div>
              <div className="category-list">
                {(selectedProfile?.categories || []).map((category) => (
                  <label
                    className={`category-option ${categories.includes(category) ? "checked" : ""}`}
                    key={category}
                  >
                    <input
                      type="checkbox"
                      checked={categories.includes(category)}
                      onChange={() => toggleCategory(category)}
                    />
                    <span className="checkmark">✓</span>
                    {category.replaceAll("_", " ")}
                  </label>
                ))}
              </div>
              <div className="scope-callout">
                <span className="shield">⬡</span>
                <div>
                  <strong>Scope guard active</strong>
                  <small>
                    Mock adapters only · real side effects disabled · bounded
                    test budget
                  </small>
                </div>
              </div>
              <button
                className="primary-button"
                type="submit"
                disabled={submitting || loading}
              >
                <span>
                  {submitting ? "Queueing assessment…" : "Start assessment"}
                </span>
                <span className="button-arrow">→</span>
              </button>
            </form>
          </div>

          <div className="panel activity-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">RUN HISTORY</div>
                <h2>Recent assessments</h2>
              </div>
              <span className="count-badge">{runs.length} / 50</span>
            </div>
            <div className="run-list">
              {runs.length === 0 && (
                <div className="empty-state">
                  <span className="empty-icon">⌁</span>
                  <strong>No assessments yet</strong>
                  <span>
                    Start a synthetic run to see progress and findings here.
                  </span>
                </div>
              )}
              {runs.map((run) => (
                <button
                  className={`run-row ${selectedId === run.id ? "selected" : ""}`}
                  key={run.id}
                  onClick={() => setSelectedId(run.id)}
                >
                  <span className={`status-marker ${run.status}`} />
                  <span className="run-details">
                    <strong>{run.profile.replaceAll("-", " ")}</strong>
                    <small>{timeLabel(run.created_at)}</small>
                    <span className="progress-track">
                      <i style={{ width: `${run.progress}%` }} />
                    </span>
                  </span>
                  <span className="run-meta">
                    <span className={`status-text ${run.status}`}>
                      {statusLabel[run.status]}
                    </span>
                    <small>
                      {run.status === "completed"
                        ? `${run.findings_count} findings`
                        : `${run.progress}%`}
                    </small>
                  </span>
                </button>
              ))}
            </div>
          </div>
        </section>

        <section className="panel findings-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">EVIDENCE REVIEW</div>
              <h2>
                {selectedRun
                  ? `Assessment · ${selectedRun.id.slice(0, 8)}`
                  : "Findings and report"}
              </h2>
            </div>
            {selectedRun && (
              <span className={`status-tag ${selectedRun.status}`}>
                {statusLabel[selectedRun.status]}
              </span>
            )}
          </div>
          {!selectedRun && (
            <div className="report-placeholder">
              <span className="report-glyph">⌘</span>
              <div>
                <strong>Select a run to inspect its report</strong>
                <span>
                  Trace-backed findings and policy decisions will appear here
                  when the run completes.
                </span>
              </div>
            </div>
          )}
          {selectedRun && selectedRun.status !== "completed" && (
            <div className="progress-view">
              <div className="progress-copy">
                <span>
                  {selectedRun.status === "failed"
                    ? selectedRun.error || "Run failed."
                    : "Assessment running against synthetic fixtures"}
                </span>
                <strong>{selectedRun.progress}%</strong>
              </div>
              <div className="large-track">
                <i style={{ width: `${selectedRun.progress}%` }} />
              </div>
            </div>
          )}
          {selectedRun?.status === "completed" && report && (
            <div className="finding-list">
              {findings.length === 0 && (
                <div className="no-findings">
                  <span>✓</span>
                  <div>
                    <strong>No findings observed</strong>
                    <small>
                      This means no configured test produced a finding; it does
                      not prove the agent is secure.
                    </small>
                  </div>
                </div>
              )}
              {findings.map((finding) => (
                <article className="finding-row" key={finding.finding_id}>
                  <span className={`severity ${finding.severity}`}>
                    {finding.severity}
                  </span>
                  <div className="finding-text">
                    <strong>{finding.title}</strong>
                    <span>{finding.rationale}</span>
                    <small>
                      {finding.category} · {finding.outcome} ·{" "}
                      {finding.evidence_refs.join(", ")}
                    </small>
                  </div>
                </article>
              ))}
              <details className="report-json">
                <summary>View redacted JSON report</summary>
                <pre>{JSON.stringify(report, null, 2)}</pre>
              </details>
            </div>
          )}
        </section>
        <footer>
          <span>AgentShield local console</span>
          <span>Assessments run in-process · no shell execution</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
