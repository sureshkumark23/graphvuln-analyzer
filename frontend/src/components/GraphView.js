import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';

cytoscape.use(dagre);

function nodeColor(data) {
  if (data.has_cve)        return '#ef4444';
  if (data.risk_score > 0) return '#f97316';
  return '#22c55e';
}

function nodeSize(data) {
  if (data.risk_score > 20) return 40;
  if (data.risk_score > 10) return 32;
  if (data.has_cve)         return 28;
  return 20;
}

function GraphView({ nodes, edges, selected, setSelected }) {
  const cyRef      = useRef(null);
  const cyInstance = useRef(null);

  useEffect(() => {
    if (!nodes || nodes.length === 0) return;

    const elements = [
      ...nodes.map(n => ({
        data: {
          id:    n.id,
          label: n.name,
          ...n,
          color: nodeColor(n),
          size:  nodeSize(n)
        }
      })),
      ...edges.map(e => ({
        data: { source: e.source, target: e.target }
      }))
    ];

    cyInstance.current = cytoscape({
      container: cyRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'width':            'data(size)',
            'height':           'data(size)',
            'label':            'data(label)',
            'color':            '#e2e8f0',
            'font-size':        9,
            'text-valign':      'bottom',
            'text-margin-y':    4,
            'border-width':     1,
            'border-color':     '#334155',
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#3b82f6',
          }
        },
        {
          selector: 'edge',
          style: {
            'width':              1,
            'line-color':         '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style':        'bezier',
            'arrow-scale':        0.7,
          }
        }
      ],
      layout: {
        name:    'dagre',
        rankDir: 'TB',
        nodeSep: 40,
        rankSep: 60,
        animate: false,
        padding: 20,
      },
    });

    cyInstance.current.on('tap', 'node', evt => {
      setSelected(evt.target.data());
    });

    cyInstance.current.on('tap', evt => {
      if (evt.target === cyInstance.current) setSelected(null);
    });

    return () => {
      if (cyInstance.current) cyInstance.current.destroy();
    };
  }, [nodes, edges]);

  useEffect(() => {
    if (!cyInstance.current || !selected) return;
    cyInstance.current.nodes().forEach(n => {
      n.style('border-width', n.data('id') === selected.id ? 3 : 1);
      n.style('border-color', n.data('id') === selected.id ? '#3b82f6' : '#334155');
    });
  }, [selected]);

  return (
    <div className="graph-panel">
      <div className="panel-header">
        <h3>🕸️ Dependency Graph</h3>
        <div className="legend">
          <span><span className="dot red"/>Has CVE</span>
          <span><span className="dot orange"/>Affected</span>
          <span><span className="dot green"/>Clean</span>
        </div>
      </div>

      <div id="cy" ref={cyRef} />

      {selected && (
        <div className="node-detail">
          <h4>{selected.name}@{selected.version}</h4>
          <div className="detail-row">
            <span>Risk Score</span>
            <span>{selected.risk_score?.toFixed(4)}</span>
          </div>
          <div className="detail-row">
            <span>CVSS Max</span>
            <span>{selected.cvss_max || 'N/A'}</span>
          </div>
          <div className="detail-row">
            <span>Dependents</span>
            <span>{selected.dependent_count}</span>
          </div>
          <div className="detail-row">
            <span>PageRank</span>
            <span>{selected.pagerank?.toFixed(6)}</span>
          </div>
          <div className="detail-row">
            <span>Depth</span>
            <span>{selected.depth}</span>
          </div>
          {selected.cve_list?.length > 0 && (
            <div className="cve-list">
              {selected.cve_list.slice(0, 3).map(cve => (
                <div key={cve.id} className="cve-item">
                  <div className="cve-id">{cve.id} — {cve.severity}</div>
                  <div className="cve-desc">{cve.summary}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default GraphView;