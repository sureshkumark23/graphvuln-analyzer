import React from 'react';

function severity(cvss) {
  if (cvss >= 9) return 'CRITICAL';
  if (cvss >= 7) return 'HIGH';
  if (cvss >= 4) return 'MEDIUM';
  if (cvss >  0) return 'LOW';
  return 'NONE';
}

function RiskTable({ ranking, selected, setSelected }) {
  return (
    <div className="risk-panel">
      <div className="panel-header">
        <h3>🏆 Fix Priority Ranking</h3>
        <span style={{ fontSize: 11, color: '#64748b' }}>
          {ranking.length} packages
        </span>
      </div>
      <div className="risk-scroll">
        {ranking.map(pkg => {
          const sev = severity(pkg.cvss_max);
          const isSelected = selected?.id === pkg.node_id;
          return (
            <div
              key={pkg.node_id}
              className={`risk-row ${isSelected ? 'selected' : ''}`}
              onClick={() => setSelected({ id: pkg.node_id, ...pkg })}
            >
              <div className={`rank-badge ${pkg.fix_priority <= 3 ? 'top3' : ''}`}>
                #{pkg.fix_priority}
              </div>
              <div className="pkg-info">
                <div className="pkg-name">
                  {pkg.has_cve ? '🚨 ' : '⚠️ '}{pkg.name}
                </div>
                <div className="pkg-meta">
                  v{pkg.version} · {pkg.cve_count} CVEs · {pkg.dependent_count} dependents
                </div>
              </div>
              <span className={`severity-badge ${sev}`}>{sev}</span>
              <span className="risk-score-val">{pkg.risk_score.toFixed(1)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default RiskTable;