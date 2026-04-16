import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Shield, 
  Terminal, 
  GitPullRequest, 
  AlertCircle, 
  CheckCircle2, 
  AlertTriangle,
  Code2,
  Bug,
  LayoutDashboard,
  Settings,
  History,
  Rocket,
  ArrowRight,
  ClipboardCopy,
  Zap,
  Fingerprint,
  Info,
  Check,
  ListChecks,
  Activity,
  Server,
  Database,
  Lock,
  ArrowUpRight,
  Target,
  Workflow,
  Package,
  Layers,
  FileCode,
  Box,
  TrendingUp,
  Globe,
  Cpu,
  Search
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const SAMPLE_CODE = `--- old/api.py
+++ new/api.py
@@ -10,3 +10,3 @@
-def get_data(id):
-    return db.execute("SELECT * FROM entries WHERE id = %s", (id,))
+def get_data(user_id):
+    return db.execute("SELECT * FROM entries WHERE id = " + user_id)`;

const SAMPLE_DEPS = `apache-commons==1.1.2
requests==2.25.1
flask==1.1.2`;

const PipelineStep = ({ icon: Icon, label, status, sublabel }) => (
  <div className="flex flex-col items-center gap-2 group relative">
    <div className={`w-12 h-12 rounded-xl flex items-center justify-center border-2 transition-all duration-500 $\{status === 'active' ? 'bg-primary border-primary shadow-[0_0_20px_rgba(99,102,241,0.4)] scale-110' : status === 'complete' ? 'bg-low/20 border-low/40 text-low' : 'bg-zinc-900 border-border text-zinc-600'}`}>
       <Icon size={20} className={status === 'active' ? 'animate-pulse text-white' : ''} />
    </div>
    <div className="text-center">
       <p className={`text-[10px] font-black uppercase tracking-widest $\{status === 'active' ? 'text-white' : 'text-zinc-500'}`}>{label}</p>
       <p className="text-[8px] text-zinc-600 font-bold uppercase">{sublabel}</p>
    </div>
    {status === 'complete' && <div className="absolute -top-1 -right-1 bg-low rounded-full p-0.5 border-2 border-background"><Check size={8} className="text-white" strokeWidth={4} /></div>}
  </div>
);

const PipelineVisualizer = ({ step }) => {
  const steps = [
    { id: 'input', icon: GitPullRequest, label: 'Ingest', sub: 'Diff Parser' },
    { id: 'nvd', icon: Globe, label: 'NVD Intel', sub: 'services.nvd' },
    { id: 'rules', icon: Cpu, label: 'Analyzers', sub: 'Hybrid Scan' },
    { id: 'ai', icon: Zap, label: 'Remedia', sub: 'AI Engine' },
    { id: 'decision', icon: Shield, label: 'Decision', sub: 'CI Status' }
  ];

  return (
    <div className="flex items-center justify-between mb-12 px-10 py-8 glass-card border-primary/20 bg-primary/[0.02] relative overflow-hidden shadow-2xl">
       <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/5 to-transparent -translate-x-full animate-[shimmer_3s_infinite]" />
       {steps.map((s, i) => (
         <React.Fragment key={s.id}>
           <PipelineStep 
             icon={s.icon} 
             label={s.label} 
             sublabel={s.sub}
             status={step === s.id ? 'active' : steps.findIndex(x => x.id === step) > i ? 'complete' : 'pending'} 
           />
           {i < steps.length - 1 && (
             <div className="h-px w-full bg-border mx-4 relative overflow-hidden">
                <motion.div 
                  initial={{ x: '-100%' }}
                  animate={steps.findIndex(x => x.id === step) > i ? { x: '0%' } : { x: '-100%' }}
                  className="absolute inset-0 bg-primary shadow-[0_0_10px_rgba(99,102,241,0.5)]"
                />
             </div>
           )}
         </React.Fragment>
       ))}
    </div>
  );
};

export default function App() {
  const [codeDiff, setCodeDiff] = useState(SAMPLE_CODE);
  const [depContent, setDepContent] = useState(SAMPLE_DEPS);
  const [activeInput, setActiveInput] = useState("deps"); 
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [pipelineStep, setPipelineStep] = useState('input');
  const [intelligenceFeed, setIntelligenceFeed] = useState([]);

  const addToFeed = (msg) => setIntelligenceFeed(prev => [msg, ...prev].slice(0, 5));

  const runScan = async () => {
    setIsScanning(true);
    setScanResult(null);
    setIntelligenceFeed([]);
    
    // Smooth Pipeline Animation with Intelligence Feed updates
    const steps = [
      { id: 'input', msg: "Parsing source diff and dependency tree..." },
      { id: 'nvd', msg: "Calling NVD API v2.0 for package lookup..." },
      { id: 'rules', msg: "Executing hybrid heuristic analyzers..." },
      { id: 'ai', msg: "Generating remediation patch with AI..." },
      { id: 'decision', msg: "Finalizing CI/CD security blockade..." }
    ];

    for(let s of steps) {
      setPipelineStep(s.id);
      addToFeed(s.msg);
      await new Promise(r => setTimeout(r, 800));
    }

    try {
      const response = await axios.post('http://localhost:8000/scan', {
        code_diff: codeDiff,
        language: "python",
        dependency_content: depContent,
        dependency_type: "requirements"
      });
      setScanResult(response.data);
    } catch (error) {
       console.error("Scan failed", error);
       alert("Target production backend offline.");
    } finally {
      setIsScanning(false);
      setPipelineStep('decision');
    }
  };

  return (
    <div className="flex min-h-screen bg-[#070709] text-zinc-300 font-sans selection:bg-primary/40 leading-relaxed overflow-hidden">
      {/* Production Sidebar */}
      <aside className="w-72 border-r border-white/5 p-8 flex flex-col gap-12 bg-black/40 backdrop-blur-3xl z-50">
        <div className="flex items-center gap-4">
           <div className="w-12 h-12 bg-gradient-to-tr from-primary to-indigo-600 rounded-2xl flex items-center justify-center shadow-2xl shadow-primary/20">
              <Shield size={26} className="text-white" strokeWidth={3} />
           </div>
           <div>
              <h1 className="text-xl font-black tracking-tighter text-white">SECUREFLOW</h1>
              <span className="text-[10px] font-black text-primary uppercase tracking-[0.3em]">Titan Engine v4.0</span>
           </div>
        </div>

        <nav className="flex flex-col gap-2">
          <NavItem icon={LayoutDashboard} label="Enterprise HUD" active={activeTab === "dashboard"} onClick={() => setActiveTab("dashboard")} />
          <NavItem icon={Globe} label="Global Threat Intel" active={activeTab === "intel"} onClick={() => setActiveTab("intel")} />
          <NavItem icon={Layers} label="Supply Chain Audit" />
          <NavItem icon={History} label="Intelligence Logs" />
          <div className="my-6 h-px bg-white/5 mx-2" />
          <NavItem icon={Settings} label="Governance" />
        </nav>

        <div className="mt-auto space-y-6">
           <div className="glass-card p-5 border-white/5 bg-white/[0.02]">
              <div className="flex items-center justify-between mb-4">
                 <span className="text-[10px] font-black text-secondary uppercase">API Latency</span>
                 <div className="w-2 h-2 rounded-full bg-low" />
              </div>
              <p className="text-2xl font-black text-white">42ms</p>
           </div>
           <div className="p-5 rounded-2xl border border-primary/20 bg-primary/5">
              <p className="text-[10px] font-black text-primary uppercase mb-2">System Status</p>
              <p className="text-xs text-zinc-400 font-bold leading-tight">NVD Endpoint Reachable via Async Hub.</p>
           </div>
        </div>
      </aside>

      {/* Main Orchestration Hub */}
      <main className="flex-1 overflow-y-auto bg-gradient-to-br from-background via-black to-background flex flex-col">
        <header className="h-20 border-b border-white/5 flex items-center justify-between px-10 bg-black/20 backdrop-blur-xl sticky top-0 z-40">
           <div className="flex items-center gap-6">
              <div className="flex items-center gap-3">
                 <div className="w-2 h-2 rounded-full bg-low animate-pulse" />
                 <span className="text-xs font-black text-zinc-100 uppercase tracking-widest">Autonomous Inspector Online</span>
              </div>
              <div className="h-6 w-px bg-white/5" />
              <div className="flex items-center gap-2">
                 <Server size={14} className="text-zinc-500" />
                 <span className="text-[11px] text-zinc-500 font-bold uppercase tracking-tight">Node: prod-scan-cluster-x</span>
              </div>
           </div>
           
           <div className="flex gap-4">
              <button className="h-10 px-6 rounded-xl bg-zinc-900/50 border border-white/5 text-[10px] font-black uppercase tracking-widest flex items-center gap-2 hover:bg-zinc-800 transition-colors">
                 <Search size={14} /> Global CVE Search
              </button>
              <div className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center font-black text-white text-xs shadow-xl shadow-primary/20">JD</div>
           </div>
        </header>

        <div className="p-12 max-w-[1400px] mx-auto w-full flex-1">
          <PipelineVisualizer step={pipelineStep} />

          <div className="grid grid-cols-12 gap-12">
            {/* Input Section */}
            <div className="col-span-12 lg:col-span-7 space-y-10">
               <section className="glass-card p-0 overflow-hidden border-white/5 shadow-[0_22px_70px_8px_rgba(0,0,0,0.56)]">
                  <div className="bg-white/[0.03] border-b border-white/5 p-6 flex items-center justify-between">
                     <div className="flex gap-6">
                        <InputTab label="Requirements" icon={Package} active={activeInput === "deps"} onClick={() => setActiveInput("deps")} />
                        <InputTab label="Source Diff" icon={FileCode} active={activeInput === "code"} onClick={() => setActiveInput("code")} />
                     </div>
                  </div>
                  
                  <textarea 
                    value={activeInput === "code" ? codeDiff : depContent}
                    onChange={(e) => activeInput === "code" ? setCodeDiff(e.target.value) : setDepContent(e.target.value)}
                    className="w-full h-[450px] bg-[#0c0c0e] p-10 font-mono text-sm leading-loose text-zinc-400 outline-none resize-none"
                    spellCheck="false"
                  />

                  <div className="p-8 border-t border-white/5 bg-black/20 flex justify-between items-center">
                     <div className="flex items-center gap-4">
                        <div className="bg-zinc-900 px-4 py-2 rounded-xl text-[10px] font-black text-secondary tracking-widest uppercase border border-white/5">Auto-Detect: Python 3.11</div>
                     </div>
                     <button 
                        onClick={runScan}
                        disabled={isScanning}
                        className={`h-14 px-12 rounded-2xl font-black text-sm uppercase tracking-[0.3em] transition-all shadow-2xl shadow-primary/20 $\{isScanning ? 'bg-zinc-800 text-zinc-600' : 'bg-primary text-white hover:scale-105 active:scale-95 hover:shadow-primary/40'}`}
                     >
                        {isScanning ? 'Syncing NVD...' : 'Commit Security Audit'}
                     </button>
                  </div>
               </section>

               <div className="glass-card p-8 border-white/5 bg-black/40">
                  <div className="flex items-center gap-3 mb-6">
                     <Activity size={20} className="text-primary" />
                     <h3 className="text-sm font-black text-white uppercase tracking-widest">Live Intelligence Stream</h3>
                  </div>
                  <div className="space-y-4">
                     {intelligenceFeed.map((msg, i) => (
                        <motion.div key={i} initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="flex gap-4 items-center">
                           <span className="text-[10px] font-mono text-zinc-700 min-w-[80px]">{new Date().toLocaleTimeString([], {hour12: false})}</span>
                           <span className={`text-xs font-bold $\{i === 0 ? 'text-primary' : 'text-zinc-500'}`}>{msg}</span>
                        </motion.div>
                     ))}
                     {intelligenceFeed.length === 0 && <p className="text-xs text-zinc-700 italic">Waiting for pipeline trigger...</p>}
                  </div>
               </div>
            </div>

            {/* Results Section */}
            <div className="col-span-12 lg:col-span-5 space-y-10">
               <AnimatePresence mode="wait">
                  {!scanResult && !isScanning && (
                    <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="h-full flex flex-col items-center justify-center p-20 text-center border-2 border-dashed border-white/5 rounded-[40px] bg-white/[0.01]">
                       <div className="w-24 h-24 bg-zinc-900 border border-white/5 rounded-[32px] flex items-center justify-center mb-8 rotate-3">
                          <Target size={40} className="text-zinc-700" />
                       </div>
                       <h3 className="text-3xl font-black text-white tracking-tighter mb-4">Ingest Payload</h3>
                       <p className="text-sm text-zinc-600 font-bold uppercase tracking-widest leading-loose">The Titan Engine is idling. Commmit code or requirements to begin a deep-intel audit.</p>
                    </motion.div>
                  )}

                  {isScanning && <ProductionLoader />}

                  {scanResult && (
                    <motion.div key="results" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-10 pb-40">
                       {/* Decision Summary */}
                       <div className={`p-8 rounded-[40px] border-4 flex flex-col gap-6 shadow-[0_30px_90px_rgba(0,0,0,0.6)] animate-in fade-in zoom-in duration-500 $\{scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-critical/5 border-critical/20' : 'bg-low/5 border-low/20'}`}>
                          <div className="flex items-center gap-6">
                             <div className={`w-20 h-20 rounded-[28px] flex items-center justify-center $\{scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-critical/20 text-critical shadow-[0_0_40px_rgba(239,68,68,0.2)]' : 'bg-low/20 text-low shadow-[0_0_40px_rgba(34,197,94,0.2)]'}`}>
                                {scanResult.scan_summary.ci_status === 'FAIL' ? <AlertCircle size={44} strokeWidth={3} /> : <CheckCircle2 size={44} strokeWidth={3} />}
                             </div>
                             <div>
                                <h3 className="text-3xl font-black text-white uppercase tracking-tighter leading-none mb-3">{scanResult.scan_summary.ci_status}</h3>
                                <div className="flex items-center gap-2">
                                   <div className={`w-2 h-2 rounded-full $\{scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-critical' : 'bg-low'} animate-pulse`} />
                                   <p className="text-[11px] text-zinc-400 font-black uppercase tracking-widest">{scanResult.scan_summary.decision_reason}</p>
                                </div>
                             </div>
                          </div>
                          
                          <div className="grid grid-cols-4 gap-4 pt-4 border-t border-white/5">
                             <StatMini label="Critical" val={scanResult.scan_summary.critical} color="text-critical" />
                             <StatMini label="High" val={scanResult.scan_summary.high} color="text-high" />
                             <StatMini label="Risk Score" val={scanResult.scan_summary.risk_score} color="text-white" />
                             <StatMini label="Decision" val={scanResult.scan_summary.ci_status} color={scanResult.scan_summary.ci_status === 'FAIL' ? 'text-critical' : 'text-low'} />
                          </div>
                       </div>

                       {/* List Findings */}
                       <div className="space-y-8">
                          {scanResult.vulnerabilities.map((v, i) => (
                             <ProductionVulnCard key={v.id} v={v} i={i} />
                          ))}
                       </div>
                    </motion.div>
                  )}
               </AnimatePresence>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

const ProductionVulnCard = ({ v, i }) => (
  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.15 }} className="glass-card group p-0 overflow-hidden border-white/5 hover:border-primary/30 transition-all duration-500 shadow-2xl relative">
     <div className="absolute top-0 right-0 p-8 font-black text-9xl text-white/[0.02] pointer-events-none">{i+1}</div>
     <div className="p-8 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
        <div className="flex items-center gap-5">
           <div className={`w-14 h-14 rounded-2xl flex items-center justify-center border $\{v.type === 'code' ? 'bg-primary/20 border-primary/30 text-primary' : 'bg-indigo-500/20 border-indigo-500/30 text-indigo-400'}`}>
              {v.type === 'code' ? <Bug size={24} /> : <Package size={24} />}
           </div>
           <div>
              <h4 className="font-black text-white uppercase tracking-tight text-lg leading-none mb-2">
                 {v.type === 'code' ? v.title : v.file_or_package}
              </h4>
              <div className="flex items-center gap-3">
                 <span className="text-[10px] text-zinc-500 font-black uppercase tracking-[0.2em]">{v.type === 'code' ? 'Algorithmic Flaw' : `Version Audit: ${v.current_version}`}</span>
                 <div className="h-1 w-1 rounded-full bg-zinc-800" />
                 <span className="text-[10px] text-primary font-black uppercase tracking-widest">{v.cve_id}</span>
              </div>
           </div>
        </div>
        <SeverityBadge severity={v.severity} />
     </div>

     <div className="p-8 space-y-8">
        <div className="grid grid-cols-2 gap-8">
           <div className="space-y-4">
              <p className="text-[10px] font-black text-secondary uppercase tracking-[0.2em] flex items-center gap-2">
                 <Info size={12} /> Root Cause Analysis
              </p>
              <p className="text-xs font-bold leading-relaxed text-zinc-400">{v.explanation}</p>
           </div>
           <div className="space-y-4 border-l border-white/5 pl-8">
              <p className="text-[10px] font-black text-secondary uppercase tracking-[0.2em] flex items-center gap-2">
                 <TrendingUp size={12} /> Exploit Criticality
              </p>
              <div className="flex items-end gap-2">
                 <span className="text-4xl font-black text-white">{v.cvss_score}</span>
                 <span className="text-xs text-zinc-600 font-bold mb-1.5 capitalize">CVSS Severity</span>
              </div>
           </div>
        </div>

        <div className="p-6 rounded-3xl bg-zinc-950 border border-white/5 transition-all group-hover:bg-black/40">
           <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-2">
                 <Zap size={14} className="text-primary animate-pulse" />
                 <p className="text-[10px] font-black text-primary uppercase tracking-widest">Remediation Strategy</p>
              </div>
              <div className="text-[9px] font-black text-zinc-600 bg-zinc-900 px-2 py-1 rounded-lg border border-white/5 uppercase">SecureFlow Patch v4.1</div>
           </div>
           
           {v.type === 'dependency' ? (
              <div className="flex items-center justify-between">
                 <div className="flex flex-col gap-1">
                    <p className="text-xs font-black text-white">Upgrade recommended to avoid {v.cve_id}.</p>
                    <p className="text-[10px] text-zinc-500 font-bold">Stable Patch: <span className="text-low font-black">{v.safe_version}</span></p>
                 </div>
                 <button className="h-10 px-8 rounded-xl bg-white text-black text-[10px] font-black uppercase tracking-widest shadow-xl hover:scale-105 transition-all">Update Dependency</button>
              </div>
           ) : (
              <div className="space-y-4">
                 <div className="bg-black/60 p-4 rounded-xl border border-white/5 font-mono text-[11px] text-low overflow-hidden">
                    <pre className="truncate">{v.remediation}</pre>
                 </div>
                 <p className="text-[11px] text-zinc-500 font-medium italic">"{v.fix_steps?.[0] || 'Apply patch immediately to close exploit window.'}"</p>
              </div>
           )}
        </div>
     </div>
  </motion.div>
);

const InputTab = ({ label, icon: Icon, active, onClick }) => (
  <button onClick={onClick} className={`flex items-center gap-3 px-6 py-3 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] transition-all $\{active ? 'bg-primary text-white shadow-2xl shadow-primary/20 scale-105' : 'text-zinc-500 hover:text-zinc-300'}`}>
     <Icon size={16} /> {label}
  </button>
);

const StatMini = ({ label, val, color }) => (
   <div className="flex flex-col gap-1">
      <p className="text-[8px] font-black text-zinc-600 uppercase tracking-widest">{label}</p>
      <p className={`text-sm font-black $\{color}`}>{val}</p>
   </div>
);

const ProductionLoader = () => (
   <div className="space-y-10 py-10">
      {[1, 2, 3].map(i => (
         <div key={i} className="glass-card h-[280px] animate-pulse bg-white/[0.02] border-white/5" />
      ))}
   </div>
);

const SeverityBadge = ({ severity }) => {
  const styles = {
    Critical: "bg-critical/20 text-critical border-critical/30 shadow-[0_0_15px_rgba(239,68,68,0.2)]",
    High: "bg-high/20 text-high border-high/30",
    Low: "bg-low/20 text-low border-low/30"
  };
  return (
    <span className={`text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg border $\{styles[severity] || styles.Low}`}>
      {severity}
    </span>
  );
};

const NavItem = ({ icon: Icon, label, active, onClick }) => (
  <button 
    onClick={onClick}
    className={`flex items-center gap-4 px-5 py-4 rounded-2xl text-[11px] font-black transition-all group relative $\{active ? 'bg-primary text-white shadow-2xl shadow-primary/20 mx-[-4px]' : 'text-zinc-600 hover:text-zinc-300 hover:bg-white/[0.03]'}`}
  >
    <Icon size={18} strokeWidth={active ? 3 : 2} className={active ? 'scale-110' : 'group-hover:scale-110 transition-transform'} />
    <span className="uppercase tracking-widest">{label}</span>
  </button>
);
