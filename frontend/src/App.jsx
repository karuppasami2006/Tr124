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
  X,
  Loader2,
  RefreshCw,
  Bell
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
  const [isFixing, setIsFixing] = useState(false);
  const [fixedVulns, setFixedVulns] = useState([]);
  const [verificationDone, setVerificationDone] = useState(false);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [pipelineStep, setPipelineStep] = useState('input');
  const [topCVEs, setTopCVEs] = useState([]);
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [prComments, setPrComments] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [config, setConfig] = useState({ scan_depth: 'medium', ai_mode: 'balanced', auto_fix: true });
  const [isConfigLoading, setIsConfigLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    fetchTopCVEs();
    fetchConfig();
    fetchAuditLogs();
    fetchPRComments();
  }, []);

  const API_BASE = window.location.hostname === 'localhost' ? 'http://localhost:8000' : '/api';

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  const fetchTopCVEs = async () => {
    try {
      const response = await axios.get(`${API_BASE}/cves/top`);
      setTopCVEs(response.data);
    } catch (error) {
       console.error("Failed to fetch top CVEs", error);
    }
  };

  const loadCVEDetail = async (cveId) => {
    try {
      setPipelineStep('nvd');
      const response = await axios.get(`${API_BASE}/cves/${cveId}`);
      setSelectedCVE(response.data);
    } catch (error) {
       showToast("Failed to load CVE intelligence.", "error");
    }
  };

  const runScan = async (overrideCode = null, overrideDeps = null) => {
    setIsScanning(true);
    setScanResult(null);
    setSelectedCVE(null);
    setVerificationDone(false);
    
    // Animation sequence
    const sequence = ['deps', 'scan', 'cve', 'ai', 'decision'];
    for(let s of sequence) {
      setPipelineStep(s);
      await new Promise(r => setTimeout(r, 600));
    }

    const finalCode = (typeof overrideCode === 'string') ? overrideCode : codeDiff;
    const finalDeps = (typeof overrideDeps === 'string') ? overrideDeps : depContent;

    try {
      const response = await axios.post(`${API_BASE}/scan`, {
        code_diff: finalCode,
        language: "python",
        dependency_content: finalDeps,
        dependency_type: "requirements"
      });
      setScanResult(response.data);
      
      // If we just applied a fix and now there are 0 vulns, it was successful verification
      if (fixedVulns.length > 0 && response.data.vulnerabilities.length === 0) {
        setVerificationDone(true);
      }
      
      showToast("Security scan completed successfully.");
      fetchPRComments();
      fetchAuditLogs();
    } catch (error) {
       console.error("Scan failed", error);
       showToast("Node server connection failed.", "error");
    } finally {
      setIsScanning(false);
    }
  };

  const handleApplyFix = async (v) => {
    if (!v.fix || !v.fix.after || v.fix.after.toLowerCase().includes('pending')) {
      showToast("Fix could not be applied. Try manual fix.", "error");
      return;
    }

    setIsFixing(true);
    try {
      const { before, after } = v.fix;
      let newCode = codeDiff;
      let newDeps = depContent;

      if (v.type === 'dependency') {
        newDeps = depContent.replace(before, after);
        setDepContent(newDeps);
        setActiveInput("deps");
      } else {
        if (codeDiff.includes(before)) {
          newCode = codeDiff.replace(before, after);
          setCodeDiff(newCode);
        } else {
          // Attempt match by cleaning lines or just use 'after' for demo
          newCode = after;
          setCodeDiff(newCode);
        }
        setActiveInput("code");
      }

      setFixedVulns(prev => [...prev, v.id]);
      showToast("Fix Applied Successfully! Verifying...", "success");
      
      // Task 2: Auto re-scan after fix
      setTimeout(() => runScan(newCode, newDeps), 1000);
    } catch (e) {
      showToast("Fix failed. Try manual update.", "error");
    } finally {
      setIsFixing(false);
    }
  };

  const fetchPRComments = async () => {
    try {
      const response = await axios.get(`${API_BASE}/pr-comments`);
      setPrComments(response.data);
    } catch (e) { console.error(e); }
  };

  const fetchAuditLogs = async () => {
    try {
      const response = await axios.get(`${API_BASE}/audit-logs`);
      setAuditLogs(response.data);
    } catch (e) { console.error(e); }
  };

  const fetchConfig = async () => {
    try {
      const response = await axios.get(`${API_BASE}/config`);
      setConfig(response.data);
    } catch (e) { console.error(e); }
  };

  const updateConfig = async (newConfig) => {
    setIsConfigLoading(true);
    try {
      await axios.post(`${API_BASE}/config`, newConfig);
      setConfig(newConfig);
      showToast("System configuration synced.");
    } catch (e) { showToast("Failed to save config.", "error"); }
    finally { setIsConfigLoading(false); }
  };

  return (
    <div className="flex min-h-screen bg-[#f9fafb] text-slate-900 font-sans selection:bg-blue-100 leading-relaxed overflow-x-hidden">
      
      {/* Toast Notification */}
      <AnimatePresence>
        {toast && (
          <motion.div 
            initial={{ y: -100, opacity: 0 }}
            animate={{ y: 24, opacity: 1 }}
            exit={{ y: -100, opacity: 0 }}
            className={`fixed top-0 right-8 z-[100] px-6 py-4 rounded-xl shadow-2xl flex items-center gap-3 border ${
              toast.type === 'success' ? 'bg-white border-emerald-100' : 'bg-white border-red-100'
            }`}
          >
            {toast.type === 'success' ? <CheckCircle2 className="text-emerald-500" size={20} /> : <AlertCircle className="text-red-500" size={20} />}
            <p className="text-sm font-bold text-slate-800">{toast.message}</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Sidebar - Desktop */}
      <aside className="hidden lg:flex w-72 border-r border-slate-200 p-8 flex-col gap-10 bg-white z-20 shadow-sm transition-all sticky top-0 h-screen">
        <div className="flex items-center gap-3 px-2">
           <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-200">
              <Shield size={22} className="text-white" strokeWidth={3} />
           </div>
           <h1 className="text-xl font-bold tracking-tight text-slate-900">SecureFlow <span className="text-blue-600 font-black">AI</span></h1>
        </div>

        <nav className="flex flex-col gap-1">
          <NavItem icon={LayoutDashboard} label="Dashboard" active={activeTab === "dashboard"} onClick={() => setActiveTab("dashboard")} />
          <NavItem icon={Globe} label="Vulnerabilities" active={activeTab === "vulnerabilities"} onClick={() => setActiveTab("vulnerabilities")} />
          <NavItem icon={GitPullRequest} label="PR Simulation" active={activeTab === "pr"} onClick={() => setActiveTab("pr")} />
          <div className="my-6 h-px bg-slate-100 mx-2" />
          <NavItem icon={History} label="Audit Logs" active={activeTab === "audit"} onClick={() => setActiveTab("audit")} />
          <NavItem icon={Settings} label="System Config" active={activeTab === "settings"} onClick={() => setActiveTab("settings")} />
        </nav>

        <div className="mt-auto">
           <div className="p-5 rounded-2xl bg-slate-50 border border-slate-100">
              <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Node Environment</p>
              <div className="flex items-center gap-2">
                 <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                 <span className="text-xs text-slate-600 font-bold">Mainnet Connected</span>
              </div>
           </div>
        </div>
      </aside>

      {/* Mobile Sidebar Overlay */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <>
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
              className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-[60] lg:hidden"
            />
            <motion.aside 
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              className="fixed inset-y-0 left-0 w-72 bg-white z-[70] p-8 flex flex-col gap-10 lg:hidden shadow-2xl"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-200">
                    <Shield size={22} className="text-white" strokeWidth={3} />
                  </div>
                  <h1 className="text-xl font-bold tracking-tight text-slate-900">SecureFlow <span className="text-blue-600 font-black">AI</span></h1>
                </div>
                <button onClick={() => setIsMobileMenuOpen(false)} className="w-8 h-8 rounded-lg bg-slate-50 flex items-center justify-center text-slate-400">
                  <X size={18} />
                </button>
              </div>

              <nav className="flex flex-col gap-1">
                <NavItem icon={LayoutDashboard} label="Dashboard" active={activeTab === "dashboard"} onClick={() => {setActiveTab("dashboard"); setIsMobileMenuOpen(false);}} />
                <NavItem icon={Globe} label="Vulnerabilities" active={activeTab === "vulnerabilities"} onClick={() => {setActiveTab("vulnerabilities"); setIsMobileMenuOpen(false);}} />
                <NavItem icon={GitPullRequest} label="PR Simulation" active={activeTab === "pr"} onClick={() => {setActiveTab("pr"); setIsMobileMenuOpen(false);}} />
                <div className="my-6 h-px bg-slate-100 mx-2" />
                <NavItem icon={History} label="Audit Logs" active={activeTab === "audit"} onClick={() => {setActiveTab("audit"); setIsMobileMenuOpen(false);}} />
                <NavItem icon={Settings} label="System Config" active={activeTab === "settings"} onClick={() => {setActiveTab("settings"); setIsMobileMenuOpen(false);}} />
              </nav>

              <div className="mt-auto">
                <div className="p-5 rounded-2xl bg-slate-50 border border-slate-100">
                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Node Environment</p>
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                      <span className="text-xs text-slate-600 font-bold">Mainnet Connected</span>
                    </div>
                </div>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto flex flex-col w-full">
        <header className="h-20 bg-white border-b border-slate-200 flex items-center justify-between px-4 md:px-10 sticky top-0 z-40 shadow-sm shadow-slate-100/50">
           <div className="flex items-center gap-4">
              <button 
                onClick={() => setIsMobileMenuOpen(true)}
                className="lg:hidden w-10 h-10 flex items-center justify-center bg-slate-50 border border-slate-200 rounded-xl text-slate-600"
              >
                <Terminal size={20} />
              </button>
              <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg">
                 <Server size={14} className="text-blue-600" />
                 <span className="text-xs text-slate-700 font-bold">SecureFlow API Engine v3.0</span>
              </div>
           </div>
           
           <div className="flex items-center gap-3 md:gap-6">
              <div className="relative">
                 <Bell size={20} className="text-slate-400 cursor-pointer hover:text-slate-600" />
                 <div className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full border-2 border-white" />
              </div>
              <div className="flex items-center gap-2 md:gap-3 pl-3 md:pl-6 border-l border-slate-200">
                 <div className="text-right hidden sm:block">
                    <p className="text-xs font-black text-slate-900">Hackathon Dev</p>
                    <p className="text-[10px] text-slate-400 font-bold">Administrator</p>
                 </div>
                 <div className="w-8 h-8 md:w-10 md:h-10 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center font-bold text-slate-500 text-xs md:sm">HD</div>
              </div>
           </div>
        </header>

        <div className="p-4 md:p-10 max-w-7xl mx-auto w-full flex-1">
          {activeTab === "dashboard" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 md:gap-10">
              {/* Scan Section */}
              <div className="col-span-1 lg:col-span-7 space-y-6 md:space-y-8">
                 <section className="bg-white rounded-3xl border border-slate-200 shadow-xl shadow-slate-200/20 overflow-hidden">
                    <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                       <div className="flex gap-2">
                          <button onClick={() => setActiveInput("code")} className={`text-xs font-bold px-5 py-2.5 rounded-xl transition-all ${activeInput === 'code' ? 'bg-white text-blue-600 shadow-sm border border-slate-200' : 'text-slate-500 hover:text-slate-700'}`}>Code Patch</button>
                          <button onClick={() => setActiveInput("deps")} className={`text-xs font-bold px-5 py-2.5 rounded-xl transition-all ${activeInput === 'deps' ? 'bg-white text-blue-600 shadow-sm border border-slate-200' : 'text-slate-500 hover:text-slate-700'}`}>Dependencies</button>
                       </div>
                       <div className="flex gap-2 overflow-x-auto pb-2 md:pb-0">
                          <button onClick={() => setDepContent("apache-commons==1.1.2")} className="text-[10px] font-bold px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition-colors flex-shrink-0">Log4Shell</button>
                          <button onClick={() => setDepContent("openssl==1.0.1")} className="text-[10px] font-bold px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition-colors flex-shrink-0">Heartbleed</button>
                       </div>
                    </div>
                    <div>
                       <textarea 
                          value={activeInput === "code" ? codeDiff : depContent}
                          onChange={(e) => activeInput === "code" ? setCodeDiff(e.target.value) : setDepContent(e.target.value)}
                          className="w-full h-80 bg-white p-4 md:p-8 font-mono text-xs md:text-sm leading-relaxed text-slate-600 outline-none resize-none overflow-auto"
                          placeholder="Paste your source code diff or dependency list here..."
                       />
                       <div className="p-5 md:p-8 border-t border-slate-100 bg-slate-50/50 flex flex-col md:row justify-between items-center gap-4">
                          <div className="flex items-center gap-3 w-full md:w-auto">
                             <div className="w-8 h-8 rounded-lg bg-blue-50 flex items-center justify-center text-blue-600">
                                <Zap size={16} fill="currentColor" />
                             </div>
                             <p className="text-[10px] md:text-xs font-bold text-slate-500 uppercase tracking-tight">AI Audit Engine Ready</p>
                          </div>
                          <button 
                             onClick={() => runScan()}
                             disabled={isScanning}
                             className={`h-14 w-full md:w-auto px-10 rounded-2xl font-bold text-xs md:text-sm transition-all flex items-center justify-center gap-3 ${isScanning ? 'bg-slate-200 text-slate-400 cursor-not-allowed' : 'bg-blue-600 text-white hover:bg-blue-700 shadow-xl shadow-blue-200 active:scale-95'}`}
                          >
                             {isScanning ? <Loader2 className="animate-spin" size={20} /> : <Rocket size={20} />}
                             {isScanning ? 'Analyzing...' : 'Execute Audit'}
                          </button>
                       </div>
                    </div>
                 </section>

                 <div className="space-y-6">
                    <h3 className="text-[10px] md:text-sm font-black text-slate-800 uppercase tracking-widest flex items-center gap-2">
                       <BookOpen size={16} className="text-blue-600" /> Knowledge Base Baseline
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                       {topCVEs.map((cve) => (
                          <motion.button 
                             key={cve.cve_id}
                             whileHover={{ scale: 1.02 }}
                             whileTap={{ scale: 0.98 }}
                             onClick={() => loadCVEDetail(cve.cve_id)}
                             className="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm flex items-center justify-between text-left group hover:border-blue-400 transition-all"
                          >
                             <div>
                                <p className="text-[10px] font-black text-blue-600 uppercase mb-1">{cve.cve_id}</p>
                                <p className="text-xs font-bold text-slate-800">{cve.name}</p>
                             </div>
                             <div className="w-8 h-8 rounded-lg bg-slate-50 border border-slate-100 flex items-center justify-center text-slate-300 group-hover:text-blue-600 transition-colors">
                                <ChevronRight size={14} />
                             </div>
                          </motion.button>
                       ))}
                    </div>
                 </div>
              </div>

              {/* Intelligence Display Area */}
              <div className="col-span-1 lg:col-span-5">
                 <AnimatePresence mode="wait">
                    {!scanResult && !isScanning && !selectedCVE && (
                      <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="h-full min-h-[300px] md:min-h-[500px] flex flex-col items-center justify-center p-6 md:p-12 text-center border-2 border-dashed border-slate-200 rounded-[32px] bg-slate-50/30">
                         <div className="w-16 h-16 md:w-20 md:h-20 bg-white rounded-3xl shadow-xl flex items-center justify-center mb-6 md:mb-8 border border-slate-100">
                            <Activity size={32} className="text-slate-300" />
                         </div>
                         <h3 className="text-xl md:text-2xl font-black text-slate-800 tracking-tight mb-2 md:mb-3">Intelligence Standby</h3>
                         <p className="text-xs md:text-sm text-slate-500 font-medium leading-relaxed">Ingest source diff or select an active threat from the KB to begin neural analysis.</p>
                      </motion.div>
                    )}

                    {isScanning && <ScanLoadingHUD />}

                    {selectedCVE && (
                      <motion.div key="cve-detail" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="bg-white rounded-[32px] border border-slate-200 shadow-2xl p-8 space-y-8 overflow-hidden relative">
                         <div className="flex items-center justify-between">
                            <button onClick={() => setSelectedCVE(null)} className="text-[10px] font-black text-slate-400 uppercase flex items-center gap-2 hover:text-slate-800 transition-colors">
                               <ArrowRight size={12} className="rotate-180" /> HUD Home
                            </button>
                            <span className="text-[10px] font-black text-red-600 uppercase tracking-widest px-3 py-1 bg-red-50 rounded-full border border-red-100">Verified Critical</span>
                         </div>

                         <div className="space-y-4">
                            <div className="flex items-center gap-5">
                               <div className="w-16 h-16 rounded-2xl bg-red-50 text-red-600 flex items-center justify-center shadow-lg shadow-red-100">
                                  <AlertCircle size={40} strokeWidth={3} />
                               </div>
                               <div>
                                  <h3 className="text-2xl font-black text-slate-900 uppercase tracking-tight leading-none mb-1">{selectedCVE.cve_id}</h3>
                                  <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">{selectedCVE.name}</p>
                               </div>
                            </div>
                            <p className="text-sm text-slate-600 leading-relaxed font-medium italic bg-slate-50 p-6 rounded-2xl border border-slate-100 border-l-4 border-l-red-400">"{selectedCVE.explanation || selectedCVE.description}"</p>
                         </div>

                         <div className="space-y-6">
                            <div className="space-y-4">
                               <p className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Neural Attack Flow</p>
                               <div className="space-y-4">
                                  {(selectedCVE.attack_flow || []).map((step, idx) => (
                                     <div key={idx} className="flex gap-4 p-4 rounded-xl bg-slate-50/50 border border-slate-100">
                                        <div className="w-6 h-6 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center text-[10px] font-black flex-shrink-0">{idx + 1}</div>
                                        <p className="text-xs text-slate-700 font-bold leading-relaxed">{step}</p>
                                     </div>
                                  ))}
                                </div>
                            </div>

                            <div className="p-6 rounded-[24px] bg-emerald-50 border border-emerald-100 space-y-4">
                               <div className="flex items-center gap-2">
                                  <CheckCircle2 size={16} className="text-emerald-600" />
                                  <p className="text-[11px] font-black text-emerald-800 uppercase tracking-widest">Remediation Path</p>
                               </div>
                               <div className="space-y-3">
                                  <p className="text-xs font-bold text-slate-800">{selectedCVE.solution}</p>
                                  {selectedCVE.fix?.steps && selectedCVE.fix.steps.map((step, idx) => (
                                     <p key={idx} className="text-xs font-medium text-slate-600 flex items-center gap-2">
                                        <div className="w-1 h-1 rounded-full bg-emerald-500" /> {step}
                                     </p>
                                  ))}
                               </div>
                            </div>
                         </div>
                      </motion.div>
                    )}

                    {scanResult && !selectedCVE && (
                       <motion.div key="scan-results" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-8">
                          <div className={`p-6 md:p-8 rounded-[32px] border-2 shadow-2xl flex flex-col md:flex-row items-center justify-between gap-6 ${scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-white border-red-200 shadow-red-100' : 'bg-white border-emerald-200 shadow-emerald-100'}`}>
                             <div className="flex items-center gap-5">
                                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0 ${scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-red-50 text-red-600' : 'bg-emerald-50 text-emerald-600'}`}>
                                   {scanResult.scan_summary.ci_status === 'FAIL' ? <AlertTriangle size={36} strokeWidth={3} /> : <CheckCircle2 size={36} strokeWidth={3} />}
                                </div>
                                <div className="flex flex-col">
                                   <h3 className="text-lg md:text-xl font-black text-slate-900 uppercase tracking-tight italic whitespace-nowrap">SECURITY STATUS: {scanResult.scan_summary.ci_status}</h3>
                                   <p className="text-[10px] md:text-xs text-slate-500 font-bold uppercase tracking-wider">{scanResult.scan_summary.decision_reason}</p>
                                </div>
                             </div>
                             <div className="ml-auto md:ml-0">
                                <span className={`text-[10px] md:text-xs font-black px-5 py-2.5 rounded-full shadow-sm ${scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-red-600 text-white' : 'bg-emerald-600 text-white'}`}>
                                   SCORE: {scanResult.scan_summary.risk_score}/100
                                </span>
                             </div>
                          </div>


                           <div className="space-y-6 pb-20">
                              {scanResult.vulnerabilities.map((v, i) => (
                                <IntelliCard 
                                  key={v.id} 
                                  v={v} 
                                  i={i} 
                                  onApplyFix={handleApplyFix}
                                  isFixed={fixedVulns.includes(v.id)}
                                  isFixing={isFixing}
                                />
                             ))}
                             {scanResult.vulnerabilities.length === 0 && (
                                <div className="p-20 text-center bg-white border border-slate-200 rounded-[32px] shadow-sm">
                                   {verificationDone ? (
                                     <>
                                       <div className="w-20 h-20 bg-emerald-50 rounded-full flex items-center justify-center mx-auto mb-6 border border-emerald-100 shadow-lg shadow-emerald-50">
                                         <CheckCircle2 className="text-emerald-500" size={48} />
                                       </div>
                                       <h4 className="text-2xl font-black text-slate-800 mb-2 italic">SUCCESS: VULNERABILITY ELIMINATED</h4>
                                       <p className="text-sm text-slate-500 font-bold uppercase tracking-widest">✅ Issue resolved successfully & Verified by AI</p>
                                     </>
                                   ) : (
                                     <>
                                       <Shield className="mx-auto text-emerald-500 mb-4" size={48} />
                                       <h4 className="text-lg font-bold text-slate-800 mb-2">Clean Bill of Health</h4>
                                       <p className="text-sm text-slate-500">No vulnerabilities detected in the analyzed scope.</p>
                                     </>
                                   )}
                                </div>
                             )}
                          </div>
                       </motion.div>
                    )}
                 </AnimatePresence>
              </div>
            </div>
          )}

          {activeTab === "vulnerabilities" && (
             <div className="space-y-8">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
                   <div>
                      <h2 className="text-2xl md:text-3xl font-black text-slate-900 tracking-tight mb-2">Threat Intelligence Database</h2>
                      <p className="text-xs md:text-sm text-slate-500 font-bold uppercase tracking-widest">Global CVE Feed Baseline</p>
                   </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                   {topCVEs.map(cve => (
                      <motion.div key={cve.cve_id} whileHover={{ y: -8 }} className="bg-white p-8 rounded-[32px] border border-slate-200 shadow-lg shadow-slate-200/40 space-y-6 flex flex-col transition-all">
                         <div className="flex justify-between items-start">
                            <span className="text-[10px] font-black text-blue-600 uppercase tracking-widest">{cve.cve_id}</span>
                            <span className="text-[10px] font-black bg-red-50 text-red-600 px-3 py-1 rounded-full border border-red-100">CVSS {cve.cvss_score}</span>
                         </div>
                         <h4 className="text-xl font-bold text-slate-900 leading-tight">{cve.name}</h4>
                         <p className="text-sm text-slate-500 line-clamp-4 leading-relaxed font-medium">{cve.description}</p>
                         <div className="mt-auto pt-6 border-t border-slate-50">
                            <button onClick={() => {setSelectedCVE(cve); setActiveTab("dashboard");}} className="w-full h-12 rounded-xl bg-slate-900 text-white text-[10px] font-black uppercase tracking-widest hover:bg-blue-600 transition-all">Examine Intelligence</button>
                         </div>
                      </motion.div>
                   ))}
                </div>
             </div>
          )}

          {activeTab === "pr" && (
            <div className="max-w-4xl mx-auto space-y-10">
               <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div>
                    <h2 className="text-2xl md:text-3xl font-black text-slate-900 tracking-tight mb-2 italic uppercase">PR Simulation Engine</h2>
                    <p className="text-xs md:text-sm text-slate-500 font-bold tracking-widest uppercase">Verified Bot Feedback</p>
                  </div>
                  <button onClick={fetchPRComments} className="h-10 md:h-12 w-full md:w-auto px-6 rounded-xl bg-white border border-slate-200 shadow-sm text-[10px] md:text-xs font-black flex items-center justify-center gap-2 hover:bg-slate-50 transition-all text-slate-700">
                    <RefreshCw size={14} className="text-blue-600" /> SYNC COMMENTS
                  </button>
               </div>
               
               <div className="space-y-8">
                  {prComments.length === 0 ? (
                    <div className="p-32 text-center bg-white border border-slate-200 rounded-[40px] shadow-sm">
                      <div className="w-20 h-20 bg-slate-50 rounded-3xl mx-auto mb-8 flex items-center justify-center border border-slate-100 text-slate-300">
                         <GitPullRequest size={40} />
                      </div>
                      <h4 className="text-xl font-bold text-slate-800 mb-2">No Active Pipeline Simulation</h4>
                      <p className="text-sm text-slate-500 mb-8 max-w-xs mx-auto">Trigger an Enterprise Scan from the Dashboard to generate pull request security comments.</p>
                      <button onClick={() => setActiveTab("dashboard")} className="px-8 py-3 bg-blue-600 text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-lg shadow-blue-200">Go to Dashboard</button>
                    </div>
                  ) : (
                    prComments.map((comment, idx) => (
                      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} key={idx} className="bg-white border border-slate-200 rounded-[28px] overflow-hidden shadow-xl shadow-slate-200/40">
                         <div className="bg-slate-50/80 px-8 py-5 border-b border-slate-200 flex items-center justify-between">
                            <div className="flex items-center gap-4">
                               <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-xs font-black text-white shadow-lg shadow-blue-100">SF</div>
                               <div>
                                  <p className="text-sm font-black text-slate-900">secureflow-ai-bot <span className="text-[10px] bg-blue-100 text-blue-700 px-2 py-0.5 rounded-md ml-2 border border-blue-200">SYSTEM</span></p>
                                  <p className="text-[10px] text-slate-400 font-bold uppercase tracking-tight">Analyzed {comment.file}</p>
                               </div>
                            </div>
                            <span className={`text-[10px] font-black px-3 py-1 rounded-full ${comment.severity === 'Critical' ? 'bg-red-100 text-red-600 border border-red-200' : 'bg-orange-100 text-orange-600 border border-orange-200'}`}>
                               {comment.severity}
                            </span>
                         </div>
                         <div className="p-6 md:p-10">
                            <div className="border-l-4 border-blue-600 pl-4 md:pl-8 overflow-x-auto">
                               <div className="prose prose-slate max-w-none text-sm md:text-base text-slate-700 whitespace-pre-wrap font-medium leading-relaxed break-words">
                                  {comment.comment}
                               </div>
                            </div>
                         </div>
                         <div className="px-10 py-5 bg-slate-50/50 border-t border-slate-100 flex gap-4">
                            <button className="text-[10px] font-black text-blue-600 uppercase tracking-widest hover:underline">Apply Automated Path</button>
                            <button className="text-[10px] font-black text-slate-400 uppercase tracking-widest hover:underline">Dismiss False Positive</button>
                         </div>
                      </motion.div>
                    ))
                  )}
               </div>
            </div>
          )}

          {activeTab === "audit" && (
            <div className="space-y-10">
               <div>
                  <h2 className="text-2xl md:text-3xl font-black text-slate-900 tracking-tight mb-2 uppercase italic">Compliance Audit Workspace</h2>
                  <p className="text-xs md:text-sm text-slate-500 font-bold uppercase tracking-widest">Enterprise Scan Ledger</p>
               </div>
               <div className="bg-white rounded-3xl md:rounded-[40px] overflow-hidden border border-slate-200 shadow-2xl shadow-slate-200/40">
                  <div className="overflow-x-auto">
                     <table className="w-full text-left border-collapse min-w-[800px]">
                        <thead>
                           <tr className="bg-slate-50/50 border-b border-slate-100">
                              <th className="px-6 md:px-10 py-4 md:py-6 text-[10px] md:text-[11px] font-black text-slate-400 uppercase tracking-[0.2em]">Deployment</th>
                              <th className="px-6 md:px-10 py-4 md:py-6 text-[10px] md:text-[11px] font-black text-slate-400 uppercase tracking-[0.2em]">Findings</th>
                              <th className="px-6 md:px-10 py-4 md:py-6 text-[10px] md:text-[11px] font-black text-slate-400 uppercase tracking-[0.2em]">Risk</th>
                              <th className="px-6 md:px-10 py-4 md:py-6 text-[10px] md:text-[11px] font-black text-slate-400 uppercase tracking-[0.2em]">Verdict</th>
                              <th className="px-6 md:px-10 py-4 md:py-6 text-[10px] md:text-[11px] font-black text-slate-400 uppercase tracking-[0.2em]">Actions</th>
                           </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-50">
                           {auditLogs.length === 0 ? (
                              <tr>
                                 <td colSpan="5" className="px-10 py-32 text-center text-slate-400 font-bold uppercase text-xs">No audit records synchronized.</td>
                              </tr>
                           ) : (
                              auditLogs.map((log, idx) => (
                                 <tr key={idx} className="hover:bg-slate-50/50 transition-colors group">
                                    <td className="px-10 py-8 text-sm font-bold text-slate-600">{log.time}</td>
                                    <td className="px-10 py-8">
                                       <div className="flex items-center gap-3">
                                          <div className="w-2 h-2 rounded-full bg-blue-600" />
                                          <span className="text-sm font-black text-slate-800">{log.issues} Security Items Identified</span>
                                       </div>
                                    </td>
                                    <td className="px-10 py-8">
                                       <div className="flex gap-2">
                                          <span className="px-3 py-1 rounded-lg bg-red-50 text-red-600 text-[10px] font-black border border-red-100">{log.critical} CRIT</span>
                                          <span className="px-3 py-1 rounded-lg bg-orange-50 text-orange-600 text-[10px] font-black border border-orange-100">{log.high} HIGH</span>
                                       </div>
                                    </td>
                                    <td className="px-10 py-8">
                                       <span className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-black tracking-widest ${log.status === 'PASS' ? 'bg-emerald-50 text-emerald-700 border border-emerald-100 shadow-sm shadow-emerald-50' : 'bg-red-50 text-red-700 border border-red-100 shadow-sm shadow-red-50'}`}>
                                          {log.status === 'PASS' ? <CheckCircle2 size={12} /> : <X size={12} />}
                                          PIPELINE {log.status}
                                       </span>
                                    </td>
                                    <td className="px-10 py-8">
                                       <button className="h-10 px-5 rounded-xl bg-slate-100 text-[10px] font-black text-slate-600 uppercase tracking-widest hover:bg-slate-900 hover:text-white transition-all">Download Artifacts</button>
                                    </td>
                                 </tr>
                              ))
                           )}
                        </tbody>
                     </table>
                  </div>
               </div>
            </div>
          )}

          {activeTab === "settings" && (
            <div className="max-w-2xl mx-auto space-y-12">
               <div>
                  <h2 className="text-2xl md:text-3xl font-black text-slate-900 tracking-tight mb-1 md:mb-2 uppercase italic">Engine Core Configuration</h2>
                  <p className="text-xs md:text-sm text-slate-500 font-bold uppercase tracking-widest">Global Policy & AI Tuning</p>
               </div>

               <div className="bg-white p-6 md:p-12 rounded-3xl md:rounded-[48px] border border-slate-200 shadow-2xl shadow-slate-200/40 space-y-8 md:space-y-12">
                  <div className="space-y-6">
                     <label className="text-[11px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                        <Target size={14} className="text-blue-600" /> Audit Intelligence Threshold
                     </label>
                     <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 md:gap-5">
                        {['low', 'medium', 'high'].map(d => (
                           <button 
                              key={d}
                              onClick={() => setConfig({...config, scan_depth: d})}
                              className={`py-3 md:py-4 rounded-[15px] md:rounded-[20px] border-2 text-[10px] font-black uppercase tracking-[0.2em] transition-all ${config.scan_depth === d ? 'border-blue-600 bg-blue-50 text-blue-700 shadow-xl shadow-blue-50' : 'border-slate-100 bg-slate-50 text-slate-400'}`}
                           >
                              {d}
                           </button>
                        ))}
                     </div>
                  </div>

                  <div className="space-y-6">
                     <label className="text-[11px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                        <Cpu size={14} className="text-blue-600" /> Neural Optimization Mode
                     </label>
                     <div className="grid grid-cols-3 gap-5">
                        {['fast', 'balanced', 'accurate'].map(m => (
                           <button 
                              key={m}
                              onClick={() => setConfig({...config, ai_mode: m})}
                              className={`py-4 rounded-[20px] border-2 text-[10px] font-black uppercase tracking-[0.2em] transition-all ${config.ai_mode === m ? 'border-blue-600 bg-blue-50 text-blue-700 shadow-xl shadow-blue-50' : 'border-slate-100 bg-slate-50 text-slate-400'}`}
                           >
                              {m}
                           </button>
                        ))}
                     </div>
                  </div>

                  <div className="flex flex-col sm:flex-row items-center justify-between p-6 md:p-8 rounded-[24px] md:rounded-[32px] bg-slate-50 border border-slate-100 shadow-inner gap-6">
                     <div className="flex items-center gap-4 md:gap-5">
                        <div className="w-12 h-12 md:w-14 md:h-14 rounded-2xl bg-white shadow-md flex items-center justify-center text-blue-600 border border-slate-100 flex-shrink-0">
                           <Zap size={24} />
                        </div>
                        <div>
                           <p className="text-xs md:text-sm font-black text-slate-900 uppercase italic">Autonomous Remediation</p>
                           <p className="text-[10px] md:text-[11px] text-slate-500 font-bold">Proactively apply high-confidence patches.</p>
                        </div>
                     </div>
                     <button 
                        onClick={() => setConfig({...config, auto_fix: !config.auto_fix})}
                        className={`w-16 h-8 rounded-full transition-all relative ${config.auto_fix ? 'bg-blue-600' : 'bg-slate-300'}`}
                     >
                        <div className={`absolute top-1 w-6 h-6 bg-white rounded-full shadow-lg transition-all ${config.auto_fix ? 'right-1' : 'left-1'}`} />
                     </button>
                  </div>

                  <button 
                     onClick={() => updateConfig(config)}
                     disabled={isConfigLoading}
                     className="w-full h-14 md:h-16 rounded-[20px] md:rounded-[24px] bg-slate-900 text-white font-black text-xs md:text-sm uppercase tracking-[0.3em] shadow-2xl hover:bg-blue-600 active:scale-95 transition-all flex items-center justify-center gap-3"
                  >
                     {isConfigLoading ? <Loader2 className="animate-spin" size={20} /> : <Shield size={20} />}
                     {isConfigLoading ? 'SYNCING...' : 'COMMIT CORE'}
                  </button>
               </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

const IntelliCard = ({ v, i, onApplyFix, isFixed, isFixing }) => (
  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }} className={`bg-white p-6 md:p-8 rounded-3xl md:rounded-[32px] border-2 shadow-lg shadow-slate-200/40 group transition-all ${isFixed ? 'border-emerald-500 bg-emerald-50/10' : 'border-slate-200 hover:border-blue-300'}`}>
     <div className="flex flex-col md:flex-row justify-between items-start gap-4 mb-6">
        <div className="flex items-center gap-4">
           <div className={`w-10 h-10 md:w-12 md:h-12 rounded-[15px] md:rounded-[18px] flex items-center justify-center shadow-lg transition-all flex-shrink-0 ${isFixed ? 'bg-emerald-500 text-white' : (v.severity === 'Critical' ? 'bg-red-50 text-red-600 shadow-red-100' : 'bg-orange-50 text-orange-600 shadow-orange-100')}`}>
              {isFixed ? <Check size={24} /> : (v.type === 'code' || v.type === 'dependency' ? <Bug size={20} /> : <Shield size={20} />)}
           </div>
           <div>
              <h4 className="text-sm md:text-base font-black text-slate-900 uppercase tracking-tight leading-none mb-1.5">{v.title || v.type}</h4>
              <p className="text-[10px] text-slate-400 font-black uppercase tracking-widest flex items-center gap-2">
                 {v.category} <span className="w-1 h-1 rounded-full bg-slate-200" /> {(v.confidence * 100).toFixed(0)}%
              </p>
           </div>
        </div>
        <span className={`text-[9px] md:text-[10px] font-black uppercase tracking-[0.2em] px-3 py-1.5 rounded-full border ${isFixed ? 'bg-emerald-500 text-white border-emerald-500' : (v.severity === 'Critical' ? 'bg-red-600 text-white border-red-600' : 'bg-orange-500 text-white border-orange-500')}`}>
           {isFixed ? 'RESOLVED' : v.severity}
        </span>
     </div>

     <div className="space-y-4 mb-8">
        <p className="text-sm text-slate-600 font-medium leading-relaxed italic border-l-2 border-slate-100 pl-6 break-words">"{v.explanation}"</p>
        <div className="pl-6 space-y-2">
           <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Root Cause</p>
           <p className="text-xs text-slate-600 font-medium leading-relaxed break-words">{v.root_cause}</p>
        </div>
     </div>
     
     <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        <div className="space-y-3">
           <p className="text-[10px] font-black text-red-500 uppercase tracking-widest">Vulnerable State</p>
           <div className="bg-red-50/50 p-4 rounded-xl border border-red-100 font-mono text-[10px] text-red-700 whitespace-pre overflow-x-auto">
              {v.fix?.before || 'Pattern detected in source.'}
           </div>
        </div>
        <div className="space-y-3">
           <p className="text-[10px] font-black text-emerald-600 uppercase tracking-widest md:text-right">Neural Fix</p>
           <div className={`p-4 rounded-xl border font-mono text-[10px] whitespace-pre overflow-x-auto transition-all ${isFixed ? 'bg-emerald-500 text-white border-emerald-600' : 'bg-emerald-50/50 text-emerald-700 border-emerald-100'}`}>
              {v.fix?.after || 'Remediation pending analysis.'}
           </div>
        </div>
     </div>

     <div className="p-6 rounded-[24px] bg-slate-50 border border-slate-100 group-hover:bg-blue-50/50 group-hover:border-blue-100 transition-all mb-6">
        <p className="text-[10px] font-black text-blue-600 uppercase tracking-widest mb-4 flex items-center gap-2 italic"><ListChecks size={14} fill="currentColor" /> Remediation Blueprint</p>
        <div className="space-y-3">
           {(v.fix_steps || ["Review security documentation", "Apply standard sanitization"]).map((step, idx) => (
              <div key={idx} className="flex items-start gap-3">
                 <div className="w-1.5 h-1.5 rounded-full bg-blue-400 flex-shrink-0 mt-1.5" />
                 <p className="text-xs text-slate-700 font-bold break-words">{step}</p>
              </div>
           ))}
        </div>
     </div>

     <button 
        onClick={() => onApplyFix(v)}
        disabled={isFixed || isFixing}
        className={`w-full h-14 rounded-2xl font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-3 shadow-xl ${
          isFixed 
          ? 'bg-emerald-500 text-white shadow-emerald-200' 
          : 'bg-blue-600 text-white hover:bg-blue-700 shadow-blue-200 active:scale-95'
        } ${isFixing && !isFixed ? 'opacity-50 cursor-not-allowed' : ''}`}
     >
        {isFixing && !isFixed ? <Loader2 className="animate-spin" size={20} /> : (isFixed ? <CheckCircle2 size={20} /> : <Zap size={20} fill="currentColor" />)}
        {isFixed ? 'Fix Applied & Verified' : 'Apply Automated Fix'}
     </button>
  </motion.div>
);

const NavItem = ({ icon: Icon, label, active, onClick }) => (
  <button onClick={onClick} className={`flex items-center gap-4 px-5 py-4 rounded-2xl text-[11px] font-black transition-all group relative ${active ? 'bg-blue-600 text-white shadow-xl shadow-blue-200' : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50'}`}>
    <Icon size={18} strokeWidth={active ? 3 : 2} className={active ? 'scale-110' : 'group-hover:scale-110 transition-transform text-slate-400 group-hover:text-blue-600'} />
    <span className="uppercase tracking-[0.2em]">{label}</span>
  </button>
);

const ScanLoadingHUD = () => (
   <div className="space-y-10">
      <div className="bg-white p-12 rounded-[40px] border border-slate-200 shadow-xl space-y-8 animate-pulse">
         <div className="flex items-center gap-4">
            <div className="w-14 h-14 bg-slate-100 rounded-2xl" />
            <div className="space-y-2 flex-1">
               <div className="h-4 w-1/3 bg-slate-100 rounded-lg" />
               <div className="h-3 w-1/2 bg-slate-50 rounded-lg" />
            </div>
         </div>
         <div className="h-3 w-full bg-slate-50 rounded-lg" />
         <div className="h-32 w-full bg-slate-50/50 rounded-3xl border border-slate-100" />
      </div>
      <div className="bg-white p-12 rounded-[40px] border border-slate-200 shadow-sm space-y-8 opacity-50">
         <div className="h-4 w-1/4 bg-slate-100 rounded-lg" />
         <div className="h-24 w-full bg-slate-50 rounded-3xl" />
      </div>
   </div>
);

