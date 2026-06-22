import React, { useState } from 'react';
import UploadSection from './components/UploadSection';
import SummaryCards from './components/SummaryCards';
import GraphView from './components/GraphView';
import RiskTable from './components/RiskTable';
import './App.css';

function App() {
  const [result, setResult]     = useState(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState(null);
  const [selected, setSelected] = useState(null);

  return (
    <div className="app">

      {/* ── HEADER ── */}
      <header className="header">
        <div className="header-left">
          <span className="header-icon">🔐</span>
          <div>
            <h1>GraphVuln Analyzer</h1>
            <p>Graph-Based Vulnerability Propagation Analyzer</p>
          </div>
        </div>
        {result && (
          <button className="btn-reset" onClick={() => {
            setResult(null); setSelected(null); setError(null);
          }}>
            ↩ Analyze Another
          </button>
        )}
      </header>

      {/* ── UPLOAD ── */}
      {!result && (
        <UploadSection
          setResult={setResult}
          setLoading={setLoading}
          setError={setError}
          loading={loading}
          error={error}
        />
      )}

      {/* ── LOADING ── */}
      {loading && (
        <div className="loading-screen">
          <div className="spinner" />
          <p>Analyzing dependency graph...</p>
          <small>Fetching CVEs from NVD + OSV • Computing blast radius</small>
        </div>
      )}

      {/* ── RESULTS ── */}
      {result && !loading && (
        <div className="results">
          <SummaryCards summary={result.summary} ecosystem={result.ecosystem} />
          <div className="main-panel">
            <GraphView
              nodes={result.graph.nodes}
              edges={result.graph.edges}
              selected={selected}
              setSelected={setSelected}
            />
            <RiskTable
              ranking={result.risk_ranking}
              selected={selected}
              setSelected={setSelected}
            />
          </div>
        </div>
      )}
    </div>
  );
}

export default App;