import React, { useState } from 'react';
import axios from 'axios';

function UploadSection({ setResult, setLoading, setError, loading, error }) {
  const [file, setFile] = useState(null);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await axios.post('http://127.0.0.1:8000/analyze', form);
      setResult(res.data);
    } catch (e) {
      setError(e.response?.data?.detail || 'Analysis failed. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="upload-screen">
      <div className="upload-card">
        <div className="upload-icon">📦</div>
        <h2>Analyze Your Dependencies</h2>
        <p>Upload your dependency file to find vulnerabilities,
          compute blast radius, and get a fix priority ranking.</p>

        <label className="file-input-label">
          Choose File
          <input
            type="file"
            accept=".json,.txt"
            onChange={e => setFile(e.target.files[0])}
          />
        </label>

        {file && (
          <div className="file-chosen">📄 {file.name}</div>
        )}

        <button
          className="btn-analyze"
          onClick={handleUpload}
          disabled={!file || loading}
        >
          {loading ? 'Analyzing...' : '🔍 Analyze Dependencies'}
        </button>

        {error && <div className="error-msg">⚠️ {error}</div>}

        <p className="supported">
          Supported: package.json (npm) · requirements.txt (PyPI)
        </p>
      </div>
    </div>
  );
}

export default UploadSection;