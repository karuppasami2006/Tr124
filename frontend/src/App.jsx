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
  const [cveSearch, setCveSearch] = useState("");

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
    <div className="flex min-h-screen bg-gray-50 text-gray-900 font-sans selection:bg-blue-100 overflow-x-hidden">
      
      {/* Toast Notification */}
      <AnimatePresence>
        {toast && (
          <motion.div 
            initial={{ y: -100, opacity: 0 }}
            animate={{ y: 24, opacity: 1 }}
            exit={{ y: -100, opacity: 0 }}
            className={`fixed top-0 right-8 z-[100] px-4 py-3 rounded-lg shadow-lg flex items-center gap-3 border ${
              toast.type === 'success' ? 'bg-white border-green-100' : 'bg-white border-red-100'
            }`}
          >
            {toast.type === 'success' ? <CheckCircle2 className="text-green-500" size={18} /> : <AlertCircle className="text-red-500" size={18} />}
            <p className="text-xs font-medium text-gray-800">{toast.message}</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Sidebar - Desktop */}
      <aside className="hidden lg:flex w-64 border-r border-gray-200 p-6 flex-col gap-8 bg-white z-20 transition-all sticky top-0 h-screen">
        <div className="flex items-center gap-2.5 px-2">
           <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Shield size={18} className="text-white" />
           </div>
           <h1 className="text-lg font-bold tracking-tight text-gray-900">SecureFlow AI</h1>
        </div>

        <nav className="flex flex-col gap-1">
          <NavItem icon={LayoutDashboard} label="Dashboard" active={activeTab === "dashboard"} onClick={() => setActiveTab("dashboard")} />
          <NavItem icon={Globe} label="Vulnerabilities" active={activeTab === "vulnerabilities"} onClick={() => setActiveTab("vulnerabilities")} />
          <NavItem icon={GitPullRequest} label="PR Simulation" active={activeTab === "pr"} onClick={() => setActiveTab("pr")} />
          <div className="my-4 h-px bg-gray-100 mx-2" />
          <NavItem icon={History} label="Audit Logs" active={activeTab === "audit"} onClick={() => setActiveTab("audit")} />
          <NavItem icon={Settings} label="System Config" active={activeTab === "settings"} onClick={() => setActiveTab("settings")} />
        </nav>

        <div className="mt-auto">
           <div className="p-4 rounded-xl bg-gray-50 border border-gray-100">
              <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider mb-2">Environment</p>
              <div className="flex items-center gap-2">
                 <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
                 <span className="text-xs text-gray-600 font-medium">Mainnet Connected</span>
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
        <header className="h-14 bg-white border-b border-gray-200 flex items-center justify-between px-4 md:px-8 sticky top-0 z-40">
           <div className="flex items-center gap-3">
              <button 
                onClick={() => setIsMobileMenuOpen(true)}
                className="lg:hidden w-8 h-8 flex items-center justify-center bg-gray-50 border border-gray-200 rounded-lg text-gray-600"
              >
                <Terminal size={16} />
              </button>
              <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 bg-gray-50 border border-gray-200 rounded-md">
                 <Server size={12} className="text-blue-600" />
                 <span className="text-[10px] text-gray-600 font-semibold tracking-tight">API Engine v3.0</span>
              </div>
           </div>
           
           <div className="flex items-center gap-4">
              <button className="relative p-1 text-gray-400 hover:text-gray-600 transition-colors">
                 <Bell size={18} />
                 <div className="absolute top-0 right-0 w-1.5 h-1.5 bg-red-500 rounded-full border border-white" />
              </button>
              <div className="flex items-center gap-3 pl-4 border-l border-gray-200">
                 <div className="text-right hidden sm:block">
                    <p className="text-xs font-semibold text-gray-900">Hackathon Dev</p>
                    <p className="text-[10px] text-gray-500">Administrator</p>
                 </div>
                 <div className="w-8 h-8 rounded-full bg-gray-100 border border-gray-200 flex items-center justify-center font-semibold text-gray-500 text-xs">HD</div>
              </div>
           </div>
        </header>

        <div className="p-4 md:p-8 max-w-7xl mx-auto w-full flex-1">
          {activeTab === "dashboard" && (
            <div className="space-y-8">
               {/* Scan Input Section */}
               <section className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden transition-all hover:shadow-md">
                  <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between bg-gray-50/10">
                     <div className="flex gap-1">
                        <button onClick={() => setActiveInput("code")} className={`text-sm font-bold px-5 py-2 rounded-md transition-all ${activeInput === 'code' ? 'bg-white text-blue-600 shadow-sm border border-gray-200' : 'text-gray-500 hover:text-gray-700'}`}>Source Code</button>
                        <button onClick={() => setActiveInput("deps")} className={`text-sm font-bold px-5 py-2 rounded-md transition-all ${activeInput === 'deps' ? 'bg-white text-blue-600 shadow-sm border border-gray-200' : 'text-gray-500 hover:text-gray-700'}`}>Manifest</button>
                     </div>
                     <div className="flex gap-2">
                        <button onClick={() => setDepContent("apache-commons==1.1.2")} className="text-xs font-semibold px-3 py-1.5 rounded-md bg-white border border-gray-200 text-gray-600 hover:bg-gray-50 transition-colors">Sample: Log4j</button>
                     </div>
                  </div>
                  <div>
                     <textarea 
                        value={activeInput === "code" ? codeDiff : depContent}
                        onChange={(e) => activeInput === "code" ? setCodeDiff(e.target.value) : setDepContent(e.target.value)}
                        className="w-full h-64 bg-white p-6 font-mono text-sm leading-relaxed text-gray-700 outline-none resize-none overflow-auto"
                        placeholder="Paste source code or dependency list to audit..."
                     />
                     <div className="px-6 py-4 border-t border-gray-100 bg-gray-50/10 flex flex-col md:flex-row justify-between items-center gap-4">
                        <div className="flex items-center gap-2">
                           <Zap size={16} className="text-blue-600" />
                           <p className="text-xs font-bold text-gray-600 uppercase tracking-widest">Neural Audit Core Enabled</p>
                        </div>
                        <button 
                           onClick={() => runScan()}
                           disabled={isScanning}
                           className={`h-12 w-full md:w-auto px-10 rounded-lg font-bold text-sm transition-all flex items-center justify-center gap-2 ${isScanning ? 'bg-gray-200 text-gray-400' : 'bg-blue-600 text-white hover:bg-blue-700 shadow-sm active:scale-95'}`}
                        >
                           {isScanning ? <Loader2 className="animate-spin" size={18} /> : <Rocket size={18} />}
                           {isScanning ? 'Executing Audit...' : 'Start Enterprise Scan'}
                        </button>
                     </div>
                  </div>
               </section>

               <AnimatePresence mode="wait">
                  {!scanResult && !isScanning && (
                    <motion.div key="idle" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="py-20 flex flex-col items-center justify-center text-center border-2 border-dashed border-gray-100 rounded-xl bg-gray-50/10">
                       <div className="w-16 h-16 bg-white rounded-xl shadow-sm flex items-center justify-center mb-6 border border-gray-200">
                          <Activity size={32} className="text-gray-300" />
                       </div>
                       <h3 className="text-xl font-bold text-gray-800 tracking-tight mb-2">Audit Intelligence Standby</h3>
                       <p className="text-sm text-gray-400 max-w-sm mx-auto leading-relaxed">Initiate a code audit or dependency scan to generate real-time security insights and remediation steps.</p>
                    </motion.div>
                  )}

                  {isScanning && (
                    <div className="max-w-4xl mx-auto">
                       <ScanLoadingHUD />
                    </div>
                  )}

                  {scanResult && (
                     <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
                        {/* Horizontal Security Status Card */}
                        <div className={`flex flex-col md:flex-row items-center justify-between gap-6 p-6 md:p-8 bg-white rounded-xl shadow-sm border transition-all hover:shadow-md ${scanResult.scan_summary.ci_status === 'FAIL' ? 'border-red-100' : 'border-green-100'}`}>
                           <div className="flex items-center gap-6">
                              <div className={`w-14 h-14 rounded-xl flex items-center justify-center flex-shrink-0 ${scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600'}`}>
                                 {scanResult.scan_summary.ci_status === 'FAIL' ? <AlertTriangle size={32} /> : <ShieldCheck size={32} />}
                              </div>
                              <div className="space-y-1 text-center md:text-left">
                                 <div className="flex flex-col">
                                   <div className="flex items-center gap-2">
                                      <h3 className="text-base font-bold text-gray-900 uppercase tracking-tight">Status: <span className={scanResult.scan_summary.ci_status === 'FAIL' ? 'text-red-600' : 'text-green-600'}>{scanResult.scan_summary.ci_status}</span></h3>
                                      <div className={`px-2 py-0.5 rounded text-xs font-bold ${scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                                         {scanResult.scan_summary.risk_score}% RISK
                                      </div>
                                   </div>
                                   <p className="text-sm text-gray-500 font-medium">{scanResult.scan_summary.decision_reason}</p>
                                </div>
                             </div>
                           </div>
                           <div className="flex items-center gap-6 w-full md:w-auto border-t md:border-t-0 md:border-l border-gray-100 pt-6 md:pt-0 md:pl-8">
                              <div className="flex-1 md:flex-none text-center">
                                 <p className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-1">Risk Score</p>
                                 <span className={`text-3xl font-black ${scanResult.scan_summary.risk_score > 70 ? 'text-red-600' : 'text-orange-500'}`}>
                                    {scanResult.scan_summary.risk_score}/100
                                 </span>
                              </div>
                              <div className={`px-6 py-3 rounded-lg font-bold text-sm uppercase tracking-wider ${scanResult.scan_summary.ci_status === 'FAIL' ? 'bg-red-600 text-white' : 'bg-green-600 text-white'}`}>
                                 Pipeline Blocked
                              </div>
                           </div>
                        </div>

                        {/* Vulnerability Grid Results */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 pb-20">
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
                              <div className="col-span-full py-20 text-center bg-white border border-gray-200 rounded-xl shadow-sm">
                                 {verificationDone ? (
                                    <div className="space-y-4">
                                       <div className="w-16 h-16 bg-green-50 rounded-full flex items-center justify-center mx-auto border border-green-100">
                                          <CheckCircle2 className="text-green-500" size={32} />
                                       </div>
                                       <h4 className="text-lg font-bold text-gray-900">Security Assets Verified</h4>
                                       <p className="text-sm text-gray-500 max-w-xs mx-auto">Neural remediation successfully verified. The pipeline state is now compliant.</p>
                                    </div>
                                 ) : (
                                    <div className="space-y-4">
                                       <ShieldCheck className="mx-auto text-green-500" size={48} />
                                       <h4 className="text-lg font-bold text-gray-900">Environment Secure</h4>
                                       <p className="text-sm text-gray-500">No active vulnerabilities detected in the analyzed scope.</p>
                                    </div>
                                 )}
                              </div>
                           )}
                        </div>
                     </motion.div>
                  )}
               </AnimatePresence>
            </div>
          )}

          {activeTab === "vulnerabilities" && (
             <div className="space-y-6">
                <div>
                   <h2 className="text-xl font-bold text-gray-900 tracking-tight">Vulnerability Database</h2>
                   <p className="text-sm text-gray-500 font-medium">Global intelligence feed and historical exposure tracking.</p>
                </div>
                
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[calc(100vh-250px)]">
                   {/* Left Panel: Search & List */}
                    <div className="lg:col-span-4 flex flex-col gap-4 overflow-hidden h-full">
                      <div className="relative">
                         <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                         <input 
                            type="text"
                            placeholder="Search CVE..."
                            value={cveSearch}
                            onChange={(e) => setCveSearch(e.target.value)}
                            className="w-full h-12 pl-10 pr-4 bg-white border border-gray-200 rounded-lg text-sm font-medium outline-none focus:border-blue-500 transition-colors"
                         />
                      </div>
                      
                      <div className="flex-1 overflow-y-auto space-y-2 pr-2 custom-scrollbar">
                         {topCVEs.filter(cve => (cve.cve_id + cve.name).toLowerCase().includes(cveSearch.toLowerCase())).map(cve => (
                            <button 
                               key={cve.cve_id}
                               onClick={() => setSelectedCVE(cve)}
                               className={`w-full text-left p-5 rounded-lg border transition-all ${selectedCVE?.cve_id === cve.cve_id ? 'bg-blue-50 border-blue-200 shadow-sm' : 'bg-white border-gray-100 hover:border-gray-200'}`}
                            >
                               <div className="flex justify-between items-start mb-2">
                                  <span className={`text-xs font-bold uppercase tracking-wider ${selectedCVE?.cve_id === cve.cve_id ? 'text-blue-700' : 'text-blue-600'}`}>{cve.cve_id}</span>
                                  <span className="text-xs font-bold bg-gray-50 text-gray-500 px-2 py-1 rounded">CVSS {cve.cvss_score}</span>
                               </div>
                               <h4 className={`text-sm font-bold leading-tight ${selectedCVE?.cve_id === cve.cve_id ? 'text-blue-900' : 'text-gray-900'}`}>{cve.name}</h4>
                            </button>
                         ))}
                      </div>
                   </div>

                   {/* Right Panel: Details panel */}
                   <div className="lg:col-span-8 overflow-y-auto h-full pr-2 custom-scrollbar">
                      <AnimatePresence mode="wait">
                         {selectedCVE ? (
                            <motion.div 
                               key={selectedCVE.cve_id}
                               initial={{ opacity: 0, y: 10 }}
                               animate={{ opacity: 1, y: 0 }}
                               exit={{ opacity: 0, y: -10 }}
                               className="bg-white rounded-xl border border-gray-200 shadow-sm p-8 space-y-8"
                            >
                                  <div className="flex items-center gap-5">
                                     <div className="w-14 h-14 rounded-lg bg-red-50 text-red-600 flex items-center justify-center border border-red-100 shadow-sm">
                                        <AlertCircle size={28} />
                                     </div>
                                     <div>
                                        <h3 className="text-2xl font-black text-gray-900 tracking-tight leading-none mb-2">{selectedCVE.cve_id}</h3>
                                        <p className="text-sm text-gray-500 font-bold uppercase tracking-widest">{selectedCVE.name}</p>
                                     </div>
                                  </div>
                                  <div className={`px-5 py-2 rounded-full text-sm font-black uppercase tracking-widest shadow-sm ${selectedCVE.cvss_score >= 9 ? 'bg-red-600 text-white' : 'bg-orange-500 text-white'}`}>
                                     Severity: {selectedCVE.cvss_score >= 9 ? 'Critical' : 'High'}
                                  </div>

                               <div className="space-y-4">
                                  <p className="text-base text-gray-600 leading-relaxed font-medium italic border-l-4 border-blue-100 pl-8 py-2">
                                     "{selectedCVE.explanation || selectedCVE.description}"
                                  </p>
                               </div>

                               <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                                  <div className="space-y-6">
                                     <p className="text-xs font-black text-gray-400 uppercase tracking-[0.2em]">Neural Attack Flow</p>
                                     <div className="space-y-3">
                                        {(selectedCVE.attack_flow || []).map((step, idx) => (
                                           <div key={idx} className="flex gap-4 p-4 rounded-xl bg-gray-50 border border-gray-100 shadow-sm transition-all hover:border-blue-200">
                                              <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center text-xs font-black flex-shrink-0 border border-blue-200">{idx + 1}</div>
                                              <p className="text-sm text-gray-700 font-bold leading-relaxed">{step}</p>
                                           </div>
                                        ))}
                                     </div>
                                  </div>
                                  
                                  <div className="space-y-6">
                                     <p className="text-xs font-black text-gray-400 uppercase tracking-[0.2em]">Remediation Path</p>
                                     <div className="p-8 rounded-xl bg-green-50 border border-green-100 space-y-6 shadow-sm">
                                        <div className="flex items-center gap-3 text-green-800">
                                           <CheckCircle2 size={24} />
                                           <p className="text-sm font-black uppercase tracking-widest">Verified Resolution</p>
                                        </div>
                                        <div className="space-y-4">
                                           <p className="text-base font-bold text-gray-800 leading-tight">{selectedCVE.solution}</p>
                                           {selectedCVE.fix?.steps?.map((step, idx) => (
                                              <div key={idx} className="flex items-start gap-3">
                                                 <div className="w-2 h-2 rounded-full bg-green-500 mt-2 flex-shrink-0" />
                                                 <p className="text-sm font-bold text-gray-600 leading-relaxed">{step}</p>
                                              </div>
                                           ))}
                                        </div>
                                     </div>
                                  </div>
                               </div>
                            </motion.div>
                         ) : (
                            <motion.div 
                               key="empty"
                               initial={{ opacity: 0 }}
                               animate={{ opacity: 1 }}
                               className="h-[500px] flex flex-col items-center justify-center text-center p-12 border-2 border-dashed border-gray-100 rounded-xl"
                            >
                               <div className="w-16 h-16 bg-white rounded-xl shadow-sm border border-gray-100 flex items-center justify-center mb-6">
                                  <Search size={32} className="text-gray-200" />
                               </div>
                               <h4 className="text-lg font-bold text-gray-400 mb-2">Select a Threat Intel</h4>
                               <p className="text-sm text-gray-400 max-w-xs leading-relaxed">Choose a vulnerability from the database list to examine remediation paths and attack flows.</p>
                            </motion.div>
                         )}
                      </AnimatePresence>
                   </div>
                </div>
             </div>
          )}

          {activeTab === "pr" && (
            <div className="max-w-4xl mx-auto space-y-8">
               <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-gray-900 tracking-tight">PR Pipeline Simulation</h2>
                    <p className="text-sm text-gray-500 font-medium">Automated commentary and feedback loops for staged code diffs.</p>
                  </div>
                  <button onClick={fetchPRComments} className="h-9 px-4 rounded-lg bg-white border border-gray-200 shadow-sm text-xs font-bold flex items-center gap-2 hover:bg-gray-50 transition-all text-gray-700">
                    <RefreshCw size={12} className="text-blue-600" /> Sync Results
                  </button>
               </div>
               
               <div className="space-y-6">
                  {prComments.length === 0 ? (
                    <div className="p-20 text-center bg-white border border-gray-200 rounded-xl shadow-sm">
                      <div className="w-16 h-16 bg-gray-50 rounded-lg mx-auto mb-6 flex items-center justify-center border border-gray-100 text-gray-300">
                         <GitPullRequest size={32} />
                      </div>
                      <h4 className="text-lg font-bold text-gray-900 mb-1">No Active Simulations</h4>
                      <p className="text-sm text-gray-500 mb-6 max-w-xs mx-auto">Trigger an Enterprise Scan from the Dashboard to generate automated securty analysis.</p>
                      <button onClick={() => setActiveTab("dashboard")} className="px-6 py-2 bg-blue-600 text-white rounded-lg text-xs font-bold uppercase tracking-wider">Start Audit</button>
                    </div>
                  ) : (
                    prComments.map((comment, idx) => (
                      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} key={idx} className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
                         <div className="bg-gray-50/50 px-6 py-3 border-b border-gray-100 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                               <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-xs font-bold text-white">SF</div>
                               <div>
                                  <p className="text-sm font-bold text-gray-900">secureflow-bot <span className="text-xs bg-blue-50 text-blue-600 px-1.5 py-0.5 rounded ml-2 border border-blue-100">SYSTEM</span></p>
                                  <p className="text-xs text-gray-500 font-medium">Analysis for {comment.file}</p>
                               </div>
                            </div>
                            <span className={`text-xs font-bold px-2 py-0.5 rounded border ${comment.severity === 'Critical' ? 'bg-red-50 text-red-600 border-red-100' : 'bg-orange-50 text-orange-600 border-orange-100'}`}>
                               {comment.severity}
                            </span>
                         </div>
                         <div className="p-6">
                            <div className="border-l-2 border-blue-600 pl-6 overflow-x-auto">
                               <div className="text-sm text-gray-700 whitespace-pre-wrap font-medium leading-relaxed font-mono">
                                  {comment.comment}
                                </div>
                            </div>
                         </div>
                         <div className="px-6 py-3 bg-gray-50/30 border-t border-gray-100 flex gap-4">
                            <button className="text-xs font-bold text-blue-600 uppercase tracking-wider hover:text-blue-800">Review Changes</button>
                            <button className="text-xs font-bold text-gray-400 uppercase tracking-wider hover:text-gray-600">Dismiss</button>
                         </div>
                      </motion.div>
                    ))
                  )}
               </div>
            </div>
          )}

          {activeTab === "audit" && (
            <div className="space-y-6">
               <div>
                  <h2 className="text-xl font-bold text-gray-900 tracking-tight">Audit History</h2>
                  <p className="text-sm text-gray-500 font-medium">Cryptographically signed ledger of all security audits and findings.</p>
               </div>
               <div className="bg-white rounded-xl overflow-hidden border border-gray-200 shadow-sm">
                  <div className="overflow-x-auto">
                     <table className="w-full text-left border-collapse min-w-[800px]">
                        <thead>
                           <tr className="bg-gray-50/50 border-b border-gray-100">
                              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">Timestamp</th>
                              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">Analysis Findings</th>
                              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">Exposure</th>
                              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">Status</th>
                              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">Actions</th>
                           </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-50 text-sm">
                           {auditLogs.length === 0 ? (
                              <tr>
                                 <td colSpan="5" className="px-6 py-20 text-center text-gray-400 font-medium uppercase text-xs">No exposure records found.</td>
                              </tr>
                           ) : (
                              auditLogs.map((log, idx) => (
                                 <tr key={idx} className="hover:bg-gray-50/30 transition-colors">
                                    <td className="px-6 py-4 text-gray-600 font-medium">{log.time}</td>
                                    <td className="px-6 py-4">
                                       <div className="flex items-center gap-2">
                                          <div className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                                          <span className="font-bold text-gray-800">{log.issues} Security Items</span>
                                       </div>
                                    </td>
                                    <td className="px-6 py-4">
                                       <div className="flex gap-2">
                                          <span className="px-1.5 py-0.5 rounded bg-red-50 text-red-600 text-xs font-bold border border-red-100">{log.critical} CRIT</span>
                                          <span className="px-1.5 py-0.5 rounded bg-orange-50 text-orange-600 text-xs font-bold border border-orange-100">{log.high} HIGH</span>
                                       </div>
                                    </td>
                                    <td className="px-6 py-4">
                                       <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold tracking-tight ${log.status === 'PASS' ? 'bg-green-50 text-green-700 border border-green-100' : 'bg-red-50 text-red-700 border border-red-100'}`}>
                                          {log.status === 'PASS' ? <CheckCircle2 size={12} /> : <X size={12} />}
                                          PIPELINE {log.status}
                                       </span>
                                    </td>
                                    <td className="px-6 py-4">
                                       <button className="h-8 px-3 rounded-lg bg-gray-50 border border-gray-200 text-xs font-bold text-gray-600 uppercase tracking-wider hover:bg-gray-900 hover:text-white transition-all">Report</button>
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
            <div className="max-w-xl mx-auto space-y-8">
               <div>
                  <h2 className="text-xl font-bold text-gray-900 tracking-tight">System Configuration</h2>
                  <p className="text-sm text-gray-500 font-medium">Audit velocity tuning and automated remediation protocols.</p>
               </div>

               <div className="bg-white p-8 rounded-xl border border-gray-200 shadow-sm space-y-8">
                  <div className="space-y-4">
                     <label className="text-xs font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
                        <Target size={14} className="text-blue-600" /> Scanning Depth
                     </label>
                     <div className="grid grid-cols-3 gap-3">
                        {['low', 'medium', 'high'].map(d => (
                           <button 
                              key={d}
                              onClick={() => setConfig({...config, scan_depth: d})}
                              className={`py-2 px-4 rounded-lg border text-xs font-bold uppercase transition-all ${config.scan_depth === d ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-gray-100 bg-gray-50 text-gray-400'}`}
                           >
                              {d}
                           </button>
                        ))}
                     </div>
                  </div>

                  <div className="space-y-4">
                     <label className="text-xs font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
                        <Cpu size={14} className="text-blue-600" /> AI Accuracy Mode
                     </label>
                     <div className="grid grid-cols-3 gap-3">
                        {['fast', 'balanced', 'accurate'].map(m => (
                           <button 
                              key={m}
                              onClick={() => setConfig({...config, ai_mode: m})}
                              className={`py-2 px-4 rounded-lg border text-xs font-bold uppercase transition-all ${config.ai_mode === m ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-gray-100 bg-gray-50 text-gray-400'}`}
                           >
                              {m}
                           </button>
                        ))}
                     </div>
                  </div>

                  <div className="flex items-center justify-between p-4 rounded-xl bg-gray-50 border border-gray-100 gap-6">
                     <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-lg bg-white border border-gray-100 shadow-sm flex items-center justify-center text-blue-600">
                           <Zap size={18} />
                        </div>
                        <div>
                           <p className="text-sm font-bold text-gray-900 leading-none mb-1">Auto Remediation</p>
                           <p className="text-xs text-gray-500 font-medium">Auto-apply high confidence neural patches.</p>
                        </div>
                     </div>
                     <button 
                        onClick={() => setConfig({...config, auto_fix: !config.auto_fix})}
                        className={`w-12 h-6 rounded-full transition-all relative ${config.auto_fix ? 'bg-blue-600' : 'bg-gray-300'}`}
                     >
                        <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-all ${config.auto_fix ? 'right-1' : 'left-1'}`} />
                     </button>
                  </div>

                  <button 
                     onClick={() => updateConfig(config)}
                     disabled={isConfigLoading}
                     className="w-full h-10 rounded-lg bg-gray-900 text-white font-bold text-xs uppercase tracking-wider hover:bg-blue-600 active:scale-95 transition-all flex items-center justify-center gap-2"
                  >
                     {isConfigLoading ? <Loader2 className="animate-spin" size={16} /> : <Shield size={16} />}
                     {isConfigLoading ? 'Syncing...' : 'Save Configuration'}
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
  <motion.div 
    initial={{ opacity: 0, y: 10 }} 
    animate={{ opacity: 1, y: 0 }} 
    transition={{ delay: i * 0.1 }} 
    className={`bg-white p-5 rounded-xl border shadow-sm transition-all ${isFixed ? 'border-green-200 bg-green-50/20' : 'border-gray-200'}`}
  >
     <div className="flex justify-between items-start gap-4 mb-4">
        <div className="flex items-center gap-3">
           <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${isFixed ? 'bg-green-100 text-green-600' : (v.severity === 'Critical' ? 'bg-red-50 text-red-600' : 'bg-orange-50 text-orange-600')}`}>
              {isFixed ? <Check size={20} /> : <AlertCircle size={20} />}
           </div>
           <div>
              <h4 className="text-base font-bold text-gray-900 leading-tight">{v.title || v.type}</h4>
              <p className="text-xs text-gray-500 font-semibold">
                 {v.category} • Confidence: {(v.confidence * 100).toFixed(0)}%
              </p>
           </div>
        </div>
        <div className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${isFixed ? 'bg-green-600 text-white' : (v.severity === 'Critical' ? 'bg-red-600 text-white' : 'bg-orange-500 text-white')}`}>
           {isFixed ? 'RESOLVED' : v.severity}
        </div>
     </div>

     <div className="space-y-3 mb-5 px-1">
        <p className="text-sm text-gray-600 font-bold leading-relaxed italic border-l-2 border-gray-100 pl-4 break-words">"{v.explanation}"</p>
        <div className="pl-4">
           <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1">Root Cause</p>
           <p className="text-xs text-gray-600 font-bold leading-normal break-words">{v.root_cause}</p>
        </div>
     </div>
     
     <div className="space-y-3 mb-5">
        <div className="space-y-1.5">
           <p className="text-[10px] font-bold text-red-500 uppercase tracking-widest px-1">Vulnerable</p>
           <div className="bg-gray-50 p-3 rounded-lg border border-gray-100 font-mono text-xs text-gray-800 whitespace-pre overflow-x-auto">
              {v.fix?.before || 'Pattern detected in source.'}
           </div>
        </div>
        <div className="space-y-1.5">
           <p className="text-[10px] font-bold text-green-600 uppercase tracking-widest px-1">Remediation</p>
           <div className={`p-3 rounded-lg border font-mono text-xs whitespace-pre overflow-x-auto transition-all ${isFixed ? 'bg-green-600 text-white border-green-600' : 'bg-gray-50 text-gray-800 border-gray-100'}`}>
              {v.fix?.after || 'Analysis pending.'}
           </div>
        </div>
     </div>

     <button 
        onClick={() => onApplyFix(v)}
        disabled={isFixed || isFixing}
        className={`w-full h-12 rounded-lg font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
          isFixed 
          ? 'bg-transparent text-green-600 border border-green-200' 
          : 'bg-blue-600 text-white hover:bg-blue-700 shadow-sm active:scale-95'
        } ${isFixing && !isFixed ? 'opacity-50 cursor-not-allowed' : ''}`}
     >
        {isFixing && !isFixed ? <Loader2 className="animate-spin" size={16} /> : (isFixed ? <Check size={16} /> : <Zap size={16} fill="currentColor" />)}
        {isFixed ? 'Asset Verified' : 'Deploy Neural Fix'}
     </button>
  </motion.div>
);
const NavItem = ({ icon: Icon, label, active, onClick }) => (
  <button onClick={onClick} className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all group relative ${active ? 'bg-gray-100 text-blue-600' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50'}`}>
    <Icon size={18} className={active ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-600'} />
    <span>{label}</span>
    {active && <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-4 bg-blue-600 rounded-r-full" />}
  </button>
);

const ScanLoadingHUD = () => (
   <div className="space-y-6">
      <div className="bg-white p-8 rounded-xl border border-gray-200 shadow-sm space-y-6 animate-pulse">
         <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-gray-100 rounded-lg" />
            <div className="space-y-2 flex-1">
               <div className="h-3 w-1/4 bg-gray-100 rounded" />
               <div className="h-2 w-1/2 bg-gray-50 rounded" />
            </div>
         </div>
         <div className="h-2 w-full bg-gray-50 rounded" />
         <div className="h-24 w-full bg-gray-50 rounded-lg border border-gray-100" />
      </div>
   </div>
);

