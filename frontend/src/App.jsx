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
  Search,
  BookOpen,
  ChevronRight,
  X
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

export default function App() {
  const [codeDiff, setCodeDiff] = useState(SAMPLE_CODE);
  const [depContent, setDepContent] = useState(SAMPLE_DEPS);
  const [activeInput, setActiveInput] = useState("deps"); 
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [pipelineStep, setPipelineStep] = useState('input');
  const [topCVEs, setTopCVEs] = useState([]);
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [intelligenceFeed, setIntelligenceFeed] = useState([]);

  useEffect(() => {
    fetchTopCVEs();
  }, []);

  const fetchTopCVEs = async () => {
    try {
      const response = await axios.get('http://localhost:8000/cves/top');
      setTopCVEs(response.data);
    } catch (error) {
       console.error("Failed to fetch top CVEs", error);
    }
  };

  const loadCVEDetail = async (cveId) => {
    try {
      setPipelineStep('nvd');
      const response = await axios.get(`http://localhost:8000/cves/$\{cveId}`);
      setSelectedCVE(response.data);
    } catch (error) {
       alert("Error loading CVE intelligence.");
    }
  };

  const runScan = async () => {
    setIsScanning(true);
    setScanResult(null);
    setIntelligenceFeed([]);
    
    // Smooth Pipeline Animation
    const sequence = ['deps', 'scan', 'cve', 'ai', 'decision'];
    for(let s of sequence) {
      setPipelineStep(s);
      await new Promise(r => setTimeout(r, 600));
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
      {/* Platform Sidebar */}
      <aside className="w-64 border-r border-white/5 p-6 flex flex-col gap-10 bg-black/40 backdrop-blur-3xl z-50">
        <div className="flex items-center gap-3">
           <div className="w-10 h-10 bg-gradient-to-tr from-primary to-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-primary/20">
              <Shield size={22} className="text-white" strokeWidth={3} />
           </div>
           <h1 className="text-xl font-black tracking-tighter text-white uppercase">SECUREFLOW</h1>
        </div>

        <nav className="flex flex-col gap-1">
          <NavItem icon={LayoutDashboard} label="Platform HUD" active={activeTab === "dashboard"} onClick={() => setActiveTab("dashboard")} />
          <NavItem icon={Globe} label="Top Vulnerabilities" active={activeTab === "vulnerabilities"} onClick={() => setActiveTab("vulnerabilities")} />
          <NavItem icon={GitPullRequest} label="PR Simulation" active={activeTab === "pr"} onClick={() => setActiveTab("pr")} />
          <div className="my-4 h-px bg-white/5 mx-2" />
          <NavItem icon={History} label="Audit Logs" />
          <NavItem icon={Settings} label="System Config" />
        </nav>

        <div className="mt-auto space-y-4">
           <div className="p-4 rounded-xl border border-primary/20 bg-primary/5">
              <p className="text-[10px] font-black text-primary uppercase mb-1">Knowledge Base</p>
              <p className="text-[11px] text-zinc-500 font-bold leading-tight">{topCVEs.length} Critical entries pre-loaded.</p>
           </div>
        </div>
      </aside>

      {/* Main Orchestration Area */}
      <main className="flex-1 overflow-y-auto bg-gradient-to-br from-background via-black to-background flex flex-col">
        <header className="h-16 border-b border-white/5 flex items-center justify-between px-8 bg-black/20 backdrop-blur-md sticky top-0 z-40">
           <div className="flex items-center gap-4">
              <span className="text-xs font-black text-zinc-500 uppercase tracking-widest italic">DevSecOps Enterprise v3.0</span>
              <ArrowRight size={14} className="text-zinc-600" />
              <div className="flex items-center gap-2 px-3 py-1 bg-zinc-900 border border-border rounded-lg shadow-sm">
                 <Server size={12} className="text-primary" />
                 <span className="text-xs text-zinc-200 font-bold tracking-tight">Intelligence Node Active</span>
              </div>
           </div>
           
           <div className="flex items-center gap-4">
              <button className="h-9 px-4 rounded-lg bg-zinc-900 border border-white/5 text-[10px] font-black uppercase tracking-widest hover:border-primary/50 transition-colors">
                 Account Settings
              </button>
              <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/40 flex items-center justify-center font-black text-primary text-xs">A</div>
           </div>
        </header>

        <div className="p-10 max-w-7xl mx-auto w-full flex-1">
          {activeTab === "dashboard" && (
            <div className="grid grid-cols-12 gap-10">
              {/* Scan Configuration */}
              <div className="col-span-12 lg:col-span-7 space-y-8">
                 <section className="glass-card p-0 overflow-hidden border-white/5 shadow-2xl">
                    <div className="p-6 border-b border-white/5 bg-white/[0.02] flex items-center justify-between">
                       <div className="flex gap-4">
                          <button onClick={() => setActiveInput("code")} className={`text-[10px] font-black uppercase px-4 py-2 rounded-lg transition-all $\{activeInput === 'code' ? 'bg-primary text-white' : 'text-zinc-500'}`}>Code Diff</button>
                          <button onClick={() => setActiveInput("deps")} className={`text-[10px] font-black uppercase px-4 py-2 rounded-lg transition-all $\{activeInput === 'deps' ? 'bg-primary text-white' : 'text-zinc-500'}`}>Dependencies</button>
                       </div>
                       <div className="flex gap-2">
                          <button onClick={() => setDepContent("apache-commons==1.1.2")} className="text-[9px] font-black uppercase px-2 py-1 rounded bg-zinc-800 border border-white/5 text-zinc-500 hover:text-white transition-colors">Test Log4Shell</button>
                          <button onClick={() => setDepContent("openssl==1.0.1")} className="text-[9px] font-black uppercase px-2 py-1 rounded bg-zinc-800 border border-white/5 text-zinc-500 hover:text-white transition-colors">Test Heartbleed</button>
                       </div>
                    </div>
                    <div className="p-0">
                       <textarea 
                          value={activeInput === "code" ? codeDiff : depContent}
                          onChange={(e) => activeInput === "code" ? setCodeDiff(e.target.value) : setDepContent(e.target.value)}
                          className="w-full h-80 bg-zinc-950/80 p-8 font-mono text-sm leading-relaxed text-zinc-400 outline-none resize-none scrollbar-thin scrollbar-thumb-zinc-800"
                       />
                       <div className="p-6 border-t border-white/5 bg-black/20 flex justify-between items-center">
                          <p className="text-[10px] font-black text-zinc-600 uppercase tracking-widest">Autonomous Inspector Online</p>
                          <button 
                             onClick={runScan}
                             disabled={isScanning}
                             className={`h-12 px-12 rounded-xl font-black text-sm uppercase tracking-[0.2em] transition-all $\{isScanning ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed' : 'bg-primary text-white hover:shadow-primary/30 active:scale-95'}`}
                          >
                             {isScanning ? 'Syncing NVD...' : 'Execute Audit Engine'}
                          </button>
                       </div>
                    </div>
                 </section>

                 <div className="space-y-6">
                    <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
                       <BookOpen size={18} className="text-primary" /> Top 10 Critical Vulnerabilities
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                       {topCVEs.map((cve) => (
                          <motion.button 
                             key={cve.cve_id}
                             whileHover={{ scale: 1.02 }}
                             whileTap={{ scale: 0.98 }}
                             onClick={() => loadCVEDetail(cve.cve_id)}
                             className="glass-card p-4 border-white/5 bg-white/[0.02] flex items-center justify-between text-left group"
                          >
                             <div>
                                <p className="text-[10px] font-black text-primary uppercase mb-1">{cve.cve_id}</p>
                                <p className="text-xs font-black text-white">{cve.name}</p>
                             </div>
                             <div className="w-8 h-8 rounded-lg bg-zinc-900 border border-white/5 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                                <ChevronRight size={14} />
                             </div>
                          </motion.button>
                       ))}
                    </div>
                 </div>
              </div>

              {/* Intelligence Stream */}
              <div className="col-span-12 lg:col-span-5">
                 <AnimatePresence mode="wait">
                    {!scanResult && !isScanning && !selectedCVE && (
                      <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="h-full flex flex-col items-center justify-center p-12 text-center border-2 border-dashed border-white/5 rounded-3xl bg-white/[0.01]">
                         <Activity size={48} className="text-zinc-800 mb-6" />
                         <h3 className="text-2xl font-black text-white tracking-tighter mb-2">Engine Standby</h3>
                         <p className="text-xs text-zinc-600 font-bold uppercase tracking-widest leading-loose">Ingest source diff or select a CVE from the Knowledge Base to baseline.</p>
                      </motion.div>
                    )}

                    {isScanning && <ScanLoadingHUD />}

                    {selectedCVE && (
                      <motion.div key="cve-detail" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-8 pb-32">
                         <div className="flex items-center justify-between">
                            <button onClick={() => setSelectedCVE(null)} className="text-[10px] font-black text-zinc-500 uppercase flex items-center gap-2 hover:text-white transition-colors">
                               <ArrowRight size={12} className="rotate-180" /> Back to HUD
                            </button>
                            <span className="text-[10px] font-black text-low uppercase tracking-widest">VERIFIED INTELLIGENCE</span>
                         </div>

                         <div className={`p-8 rounded-3xl border-2 flex flex-col gap-6 shadow-2xl bg-critical/5 border-critical/30`}>
                            <div className="flex justify-between items-start">
                               <div className="flex items-center gap-4">
                                  <div className={`w-14 h-14 rounded-2xl flex items-center justify-center bg-critical/20 text-critical shadow-lg shadow-critical/10`}>
                                     <AlertCircle size={36} strokeWidth={3} />
                                  </div>
                                  <div>
                                     <h3 className="text-2xl font-black text-white uppercase tracking-tight leading-none mb-2">{selectedCVE.cve_id}</h3>
                                     <p className="text-[10px] text-zinc-400 font-black uppercase tracking-widest">{selectedCVE.name}</p>
                                  </div>
                               </div>
                               <span className="text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg border bg-critical/20 text-critical border-critical/30">CRITICAL</span>
                            </div>
                         </div>

                         <div className="space-y-6">
                            <div className="glass-card p-6 border-white/5 bg-black/40 space-y-4">
                               <p className="text-[10px] font-black text-secondary uppercase tracking-[0.2em]">Scientific Summary</p>
                               <p className="text-sm font-medium leading-relaxed italic text-zinc-300">"{selectedCVE.description}"</p>
                            </div>

                            <div className="glass-card p-6 border-white/5 bg-black/40 space-y-4">
                               <p className="text-[10px] font-black text-secondary uppercase tracking-[0.2em]">Neural Attack Flow</p>
                               <div className="space-y-4">
                                  {selectedCVE.attack_flow.map((step, idx) => (
                                     <div key={idx} className="flex gap-4">
                                        <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                                        <p className="text-xs text-zinc-400 font-medium leading-relaxed">{step}</p>
                                     </div>
                                  ))}
                               </div>
                            </div>

                            <div className="p-6 rounded-2xl border border-low/30 bg-low/5 space-y-4">
                               <div className="flex items-center gap-2">
                                  <CheckCircle2 size={16} className="text-low" />
                                  <p className="text-[10px] font-black text-low uppercase tracking-widest">Remediation Blueprint</p>
                               </div>
                               <div className="space-y-3">
                                  {selectedCVE.fix.steps.map((step, idx) => (
                                     <p key={idx} className="text-[11px] font-bold text-zinc-400">✅ {step}</p>
                                  ))}
                               </div>
                            </div>
                         </div>
                      </motion.div>
                    )}

                    {scanResult && !selectedCVE && (
                       <motion.div key="scan-results" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}>
                          <div className={`p-6 rounded-3xl border-2 mb-8 shadow-2xl $\{scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-critical/10 border-critical/30' : 'bg-low/10 border-low/30'}`}>
                             <div className="flex items-center gap-4">
                                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center $\{scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-critical/20 text-critical' : 'bg-low/20 text-low'}`}>
                                   {scanResult.scan_summary.ci_status === 'FAIL' ? <AlertCircle size={32} strokeWidth={3} /> : <CheckCircle2 size={32} strokeWidth={3} />}
                                </div>
                                <div>
                                   <h3 className="text-xl font-black text-white uppercase tracking-tight">{scanResult.scan_summary.ci_status} REPORT</h3>
                                   <p className="text-[10px] text-zinc-400 font-bold uppercase tracking-widest">{scanResult.scan_summary.decision_reason}</p>
                                </div>
                             </div>
                          </div>
                          <div className="space-y-6">
                             {scanResult.vulnerabilities.map((v, i) => (
                                <IntelliCard key={v.id} v={v} i={i} />
                             ))}
                          </div>
                       </motion.div>
                    )}
                 </AnimatePresence>
              </div>
            </div>
          )}

          {activeTab === "vulnerabilities" && (
             <div className="grid grid-cols-3 gap-6">
                {topCVEs.map(cve => (
                   <motion.div key={cve.cve_id} whileHover={{ y: -5 }} className="glass-card p-6 border-white/5 bg-white/[0.02] space-y-6">
                      <div className="flex justify-between items-start">
                         <span className="text-[10px] font-black text-primary uppercase">{cve.cve_id}</span>
                         <span className="text-[10px] font-black bg-critical/20 text-critical px-2 py-1 rounded border border-critical/20">CVSS {cve.cvss_score}</span>
                      </div>
                      <h4 className="text-lg font-black text-white">{cve.name}</h4>
                      <p className="text-xs text-zinc-500 line-clamp-3 leading-relaxed">{cve.description}</p>
                      <button onClick={() => {setSelectedCVE(cve); setActiveTab("dashboard");}} className="w-full h-10 rounded-lg bg-zinc-900 border border-white/5 text-[10px] font-black uppercase tracking-widest hover:text-white transition-colors">Examine Intelligence</button>
                   </motion.div>
                ))}
             </div>
          )}
        </div>
      </main>
    </div>
  );
}

const IntelliCard = ({ v, i }) => (
  <div className="glass-card p-6 border-white/5 bg-white/[0.02] shadow-xl group hover:border-primary/20 transition-all">
     <div className="flex justify-between items-start mb-6">
        <div className="flex items-center gap-3">
           <div className="w-10 h-10 rounded-xl bg-primary/20 border border-primary/20 flex items-center justify-center text-primary shadow-lg shadow-primary/10">
              {v.type === 'code' ? <Bug size={20} /> : <Package size={20} />}
           </div>
           <div>
              <h4 className="text-sm font-black text-white uppercase tracking-tight leading-none mb-1">{v.type === 'code' ? v.title : v.file_or_package}</h4>
              <p className="text-[9px] text-zinc-600 font-black uppercase tracking-widest">{v.cve_id}</p>
           </div>
        </div>
        <span className={`text-[9px] font-black uppercase tracking-widest px-2 py-1 rounded border $\{v.severity === 'Critical' ? 'bg-critical/20 text-critical border-critical/30' : 'bg-high/20 text-high border-high/30'}`}>
           {v.severity}
        </span>
     </div>
     <p className="text-[11px] text-zinc-400 font-medium leading-relaxed italic mb-6">"{v.explanation}"</p>
     <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-900">
        <p className="text-[9px] font-black text-primary uppercase tracking-widest mb-2 flex items-center gap-2"><Zap size={10} fill="currentColor" /> Patch Recommendation</p>
        <p className="text-[10px] text-zinc-200 font-mono leading-relaxed">{v.remediation}</p>
     </div>
  </div>
);

const NavItem = ({ icon: Icon, label, active, onClick }) => (
  <button onClick={onClick} className={`flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-black transition-all group relative $\{active ? 'bg-primary/10 text-primary shadow-lg' : 'text-zinc-600 hover:text-zinc-300 hover:bg-white/[0.03]'}`}>
    {active && <motion.div layoutId="nav-bg" className="absolute inset-0 bg-primary/5 border border-primary/20 rounded-xl" />}
    <Icon size={16} strokeWidth={active ? 3 : 2} className={active ? 'scale-110 z-10' : 'group-hover:scale-110 transition-transform'} />
    <span className="uppercase tracking-widest z-10">{label}</span>
  </button>
);

const ScanLoadingHUD = () => (
   <div className="space-y-8">
      {[1, 2].map(i => (
         <div key={i} className="glass-card p-10 space-y-8 animate-pulse bg-zinc-900/40">
            <div className="h-6 w-1/2 bg-zinc-800 rounded-lg" />
            <div className="h-2 w-full bg-zinc-800/50 rounded-lg" />
            <div className="h-20 w-full bg-zinc-800/20 rounded-2xl" />
         </div>
      ))}
   </div>
);
