import React from 'react';

function SummaryCards({ summary, ecosystem }) {
  const cards = [
    {
      label: 'Total Packages',
      value: summary.total_packages,
      sub: `${ecosystem.toUpperCase()} ecosystem`,
      cls: 'blue'
    },
    {
      label: 'Vulnerable',
      value: summary.vulnerable_count,
      sub: 'Have direct CVEs',
      cls: 'red'
    },
    {
      label: 'Affected',
      value: summary.affected_count,
      sub: 'Via propagation',
      cls: 'orange'
    },
    {
      label: 'Clean',
      value: summary.clean_count,
      sub: 'No CVEs found',
      cls: 'green'
    },
    {
      label: 'Dependencies',
      value: summary.total_edges,
      sub: 'Total edges in graph',
      cls: 'purple'
    },
  ];

  return (
    <div className="summary-cards">
      {cards.map(c => (
        <div key={c.label} className={`card ${c.cls}`}>
          <div className="card-label">{c.label}</div>
          <div className="card-value">{c.value}</div>
          <div className="card-sub">{c.sub}</div>
        </div>
      ))}
    </div>
  );
}

export default SummaryCards;