"use client";
import { useState, useRef, useEffect, useCallback } from 'react';
import { CheckCircle2, AlertCircle, Terminal, Activity, Wifi, WifiOff } from 'lucide-react';

const API_PORT = 5001;

function getApiBase() {
  if (typeof window === 'undefined') return '';
  return `http://${window.location.hostname}:${API_PORT}`;
}

function getWsBase() {
  if (typeof window === 'undefined') return '';
  return `ws://${window.location.hostname}:${API_PORT}`;
}

export default function Home() {
  const [objective, setObjective] = useState("jailbreak");
  const [target, setTarget] = useState(".");
  const [targetUrl, setTargetUrl] = useState("http://localhost:11434/api/generate");
  const [model, setModel] = useState("groq");
  
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<any>(null);
  const [duration, setDuration] = useState("0");
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  
  const consoleRef = useRef<HTMLDivElement>(null);
  const scanStartTime = useRef<number>(0);
  const wsRef = useRef<WebSocket | null>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [logs]);

  // Health check: ping the backend every 10 seconds
  const checkBackend = useCallback(async () => {
    try {
      const res = await fetch(`${getApiBase()}/api/results`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        setBackendStatus('online');
      } else {
        setBackendStatus('offline');
      }
    } catch {
      setBackendStatus('offline');
    }
  }, []);

  useEffect(() => {
    checkBackend();
    const interval = setInterval(checkBackend, 10000);
    return () => clearInterval(interval);
  }, [checkBackend]);

  // Load last results on mount
  useEffect(() => {
    const loadResults = async () => {
      try {
        const res = await fetch(`${getApiBase()}/api/results`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          const data = await res.json();
          if (data?.runs?.[0]?.results?.length > 0) {
            setResults(data);
          }
        }
      } catch { /* ignore */ }
    };
    loadResults();
  }, []);

  const startScan = async () => {
    if (backendStatus !== 'online') {
      setLogs(["Error: Backend API is offline. Please run ./start.sh first."]);
      return;
    }

    setIsScanning(true);
    setLogs(["System: Initializing scanner..."]);
    setResults(null);
    scanStartTime.current = Date.now();
    
    // Close any existing WebSocket
    if (wsRef.current) {
      wsRef.current.close();
    }

    const ws = new WebSocket(`${getWsBase()}/ws/logs`);
    wsRef.current = ws;

    ws.onopen = () => {
      setLogs((prev) => [...prev, "System: Connected to backend."]);
    };

    ws.onmessage = (event) => {
      setLogs((prev) => [...prev, event.data]);
    };

    ws.onerror = () => {
      setLogs((prev) => [...prev, "Error: WebSocket connection failed."]);
    };

    ws.onclose = () => {
      const elapsed = Math.round((Date.now() - scanStartTime.current) / 1000);
      setDuration(`${elapsed} seconds`);
      wsRef.current = null;
      fetchResults();
    };

    try {
      const res = await fetch(`${getApiBase()}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ objective, target, target_url: targetUrl, model }),
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (error) {
      setLogs((prev) => [...prev, `Error: Failed to contact backend: ${error}`]);
      setIsScanning(false);
    }
  };

  const fetchResults = async () => {
    try {
      const res = await fetch(`${getApiBase()}/api/results`);
      const data = await res.json();
      setResults(data);
    } catch (e) {
      console.error(e);
    }
    setIsScanning(false);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-10">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-neutral-100 tracking-tight">Active Scanning</h1>
          <p className="text-sm text-neutral-500 mt-1">Configure and launch security audits against your endpoints.</p>
        </div>
        <div className="flex items-center space-x-2 text-xs">
          {backendStatus === 'online' ? (
            <span className="flex items-center text-emerald-400">
              <Wifi className="w-3.5 h-3.5 mr-1.5" />
              API Online
            </span>
          ) : backendStatus === 'offline' ? (
            <span className="flex items-center text-red-400">
              <WifiOff className="w-3.5 h-3.5 mr-1.5" />
              API Offline
            </span>
          ) : (
            <span className="flex items-center text-neutral-500">
              <Wifi className="w-3.5 h-3.5 mr-1.5 animate-pulse" />
              Checking...
            </span>
          )}
        </div>
      </div>

      {/* Scan Configuration Card */}
      <div className="bg-[#09090b] border border-neutral-800 rounded-xl p-6 shadow-sm">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-neutral-200 mb-1.5">Target URL</label>
              <div className="relative">
                <input 
                  type="text" 
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full bg-[#111113] border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50 transition-all placeholder-neutral-600"
                  placeholder="http://localhost:11434/api/generate"
                />
                <div className="absolute right-3 top-3 flex space-x-1">
                  <div className="w-1.5 h-1.5 rounded-full bg-neutral-600"></div>
                  <div className="w-1.5 h-1.5 rounded-full bg-purple-500"></div>
                </div>
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-neutral-200 mb-1.5">Scan Objective</label>
              <input 
                type="text" 
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                className="w-full bg-[#111113] border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50 transition-all"
              />
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-neutral-200 mb-1.5">Verifier Model</label>
              <select 
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="w-full bg-[#111113] border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-purple-500/50 transition-all appearance-none cursor-pointer"
              >
                <option value="groq">Groq (Cloud)</option>
                <option value="ollama">Ollama (Local)</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-neutral-200 mb-1.5">Target Path (SAST)</label>
              <input 
                type="text" 
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full bg-[#111113] border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-purple-500/50 transition-all"
              />
            </div>
          </div>
        </div>

        <div className="mt-6 pt-6 border-t border-neutral-800/50 flex justify-end">
          <button 
            onClick={startScan}
            disabled={isScanning || backendStatus !== 'online'}
            className="bg-neutral-100 hover:bg-white text-neutral-900 text-sm font-medium py-2 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
          >
            {isScanning ? (
              <>
                <Activity className="w-4 h-4 mr-2 animate-pulse" />
                Scanning...
              </>
            ) : (
              "Scan Target"
            )}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        
        {/* Security Overview (Results) */}
        <div className="bg-[#111113] border border-neutral-800/80 rounded-xl p-6 shadow-sm h-full flex flex-col">
          <h2 className="text-sm font-medium text-neutral-200 mb-6">Security Overview</h2>
          
          {results ? (
            <div className="flex-1 flex flex-col justify-center">
              <div className="text-xs text-neutral-500 mb-6 space-y-1">
                <p>Scan Status: <span className="text-neutral-300">Completed</span></p>
                <p>Scan Duration: <span className="text-neutral-300">{duration}</span></p>
              </div>
              
              {results.runs?.[0]?.results?.length === 0 ? (
                <div>
                  <h3 className="text-2xl font-semibold text-neutral-100 tracking-tight">0 Vulnerabilities Found</h3>
                  <p className="text-sm text-neutral-500 mt-2 flex items-center">
                    Your target shows no known security risks. 
                    <CheckCircle2 className="w-4 h-4 ml-1.5 text-purple-500" />
                  </p>
                </div>
              ) : (
                <div>
                  <h3 className="text-2xl font-semibold text-neutral-100 tracking-tight">
                    {results.runs?.[0]?.results?.length || 0} Vulnerabilities
                  </h3>
                  <p className="text-sm text-neutral-500 mt-2 flex items-center">
                    Action required to secure target.
                    <AlertCircle className="w-4 h-4 ml-1.5 text-red-500" />
                  </p>
                  
                  <div className="mt-6 space-y-3 max-h-[200px] overflow-y-auto pr-2">
                    {results.runs?.[0]?.results?.map((finding: any, i: number) => (
                      <div key={i} className="text-sm border-l-2 border-red-500/50 pl-3 py-1">
                        <p className="font-medium text-neutral-200">{finding.ruleId}</p>
                        <p className="text-neutral-500 truncate">{finding.locations?.[0]?.physicalLocation?.artifactLocation?.uri}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-sm text-neutral-600">
              {isScanning ? "Analysis in progress..." : "No active scan data."}
            </div>
          )}
        </div>

        {/* Execution Log */}
        <div className="bg-[#111113] border border-neutral-800/80 rounded-xl overflow-hidden shadow-sm h-[320px] flex flex-col">
          <div className="px-4 py-3 border-b border-neutral-800 flex justify-between items-center bg-[#0c0c0e]">
            <span className="text-xs font-medium text-neutral-400 flex items-center">
              <Terminal className="w-3.5 h-3.5 mr-1.5" />
              Process Output
            </span>
          </div>
          <div 
            ref={consoleRef}
            className="flex-1 p-4 overflow-y-auto font-mono text-[11px] leading-relaxed text-neutral-400 bg-[#09090b]"
          >
            {logs.length === 0 ? (
              <span className="text-neutral-600">Waiting for process...</span>
            ) : (
              logs.map((log, i) => (
                <div key={i} className={`mb-1 ${log.includes('Error') || log.includes('ERROR') ? 'text-red-400' : ''}`}>
                  {log}
                </div>
              ))
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
