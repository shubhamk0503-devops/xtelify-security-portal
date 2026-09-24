import React, { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Target,
  FileText,
  Download,
  Server,
  Zap,
  Users,
  Award,
  Printer,
  RefreshCw,
  Flame,
  ArrowUpRight,
  Sparkles,
  ChevronRight,
  Layers,
  Database,
  Lock,
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  AreaChart,
  Area,
} from "recharts";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import * as XLSX from "xlsx";

interface ExecutiveData {
  title: string;
  timestamp: string;
  healthScore: {
    score: number;
    grade: string;
    status: string;
    weekDelta: string;
  };
  kpiSummary: {
    totalFindings: number;
    openFindings: number;
    resolvedFindings: number;
    criticalOpen: number;
    highOpen: number;
    slaComplianceRate: string;
    slaBreachedCount: number;
    mttrDays: number;
    clustersScanned: number;
    cloudAccounts: number;
    scanVelocity: string;
  };
  vectorBreakdown: {
    CONTAINER: number;
    CSPM: number;
    SAST_DAST: number;
    VAPT: number;
  };
  podAccountability: Array<{
    department: string;
    lead: string;
    total: number;
    resolved: number;
    open: number;
    criticalOpen: number;
    compliancePct: number;
  }>;
  topVulnerabilities: Array<{
    id: string;
    title: string;
    asset: string;
    severity: string;
    assignedTo: string;
    department: string;
    remediation: string;
    dueDate: string;
  }>;
  governance: {
    standards: string[];
    auditStatus: string;
    nextReviewDate: string;
  };
}

interface ExecutiveBriefingViewProps {
  darkMode: boolean;
  onSwitchToDetail: () => void;
  onSwitchToManager: () => void;
}

export const ExecutiveBriefingView: React.FC<ExecutiveBriefingViewProps> = ({
  darkMode,
  onSwitchToDetail,
  onSwitchToManager,
}) => {
  const [data, setData] = useState<ExecutiveData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "pods" | "risks" | "governance">("overview");

  const fetchExecutiveData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/executive-briefing");
      if (!res.ok) {
        throw new Error(`Failed to load executive briefing (${res.status})`);
      }
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to load executive briefing data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExecutiveData();
  }, []);

  const exportExecutivePDF = () => {
    if (!data) return;
    try {
      const doc = new jsPDF("portrait", "mm", "a4");
      const pageWidth = doc.internal.pageSize.getWidth();

      // Brand Header Banner
      doc.setFillColor(15, 23, 42); // slate-900
      doc.rect(0, 0, pageWidth, 28, "F");

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(16);
      doc.setFont("helvetica", "bold");
      doc.text("AIRTEL / WYNK DIGITAL PLATFORM SECURITY", 14, 12);

      doc.setFontSize(10);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(148, 163, 184);
      doc.text("Executive Cybersecurity Posture & Vulnerability Briefing", 14, 20);

      const dateStr = new Date(data.timestamp).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      });
      doc.text(`Generated: ${dateStr}`, pageWidth - 14, 20, { align: "right" });

      // KPI Highlight Section
      doc.setTextColor(15, 23, 42);
      doc.setFontSize(12);
      doc.setFont("helvetica", "bold");
      doc.text("Executive Security Scorecard", 14, 38);

      const kpis = [
        ["Security Health Score", `${data.healthScore.score}/100 (Grade ${data.healthScore.grade})`],
        ["Corporate SLA Compliance", data.kpiSummary.slaComplianceRate],
        ["Open Critical (P0) Risks", String(data.kpiSummary.criticalOpen)],
        ["Open High (P1) Risks", String(data.kpiSummary.highOpen)],
        ["Mean Time to Remediate (MTTR)", `${data.kpiSummary.mttrDays} Days`],
        ["Total Tracked Threat Surface", `${data.kpiSummary.totalFindings} Findings`],
        ["Resolved Threat Inventory", `${data.kpiSummary.resolvedFindings} Remediated`],
        ["Protected Infrastructure Scope", `${data.kpiSummary.clustersScanned} Clusters / ${data.kpiSummary.cloudAccounts} Cloud Accounts`],
      ];

      autoTable(doc, {
        startY: 42,
        head: [["Metric Category", "Current Posture"]],
        body: kpis,
        theme: "striped",
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontStyle: "bold" },
        styles: { fontSize: 9, cellPadding: 3 },
      });

      // POD & Business Unit Accountability
      const afterKpiY = (doc as any).lastAutoTable.finalY + 10;
      doc.setFontSize(12);
      doc.setFont("helvetica", "bold");
      doc.text("Business Unit & POD Remediation Governance", 14, afterKpiY);

      const podRows = data.podAccountability.map((pod) => [
        pod.department,
        pod.lead,
        String(pod.total),
        String(pod.resolved),
        String(pod.criticalOpen),
        `${pod.compliancePct}%`,
      ]);

      autoTable(doc, {
        startY: afterKpiY + 4,
        head: [["Department / Platform", "Engineering Lead", "Total", "Resolved", "P0 Critical", "SLA Adherence"]],
        body: podRows,
        theme: "grid",
        headStyles: { fillColor: [51, 65, 85], textColor: [255, 255, 255] },
        styles: { fontSize: 8.5, cellPadding: 2.5 },
      });

      // Top Security Flaws
      const afterPodY = (doc as any).lastAutoTable.finalY + 10;
      doc.setFontSize(12);
      doc.setFont("helvetica", "bold");
      doc.text("High-Exposure Threats Requiring Board & C-Suite Awareness", 14, afterPodY);

      const vulnRows = data.topVulnerabilities.map((v) => [
        v.id,
        v.asset,
        v.severity,
        v.assignedTo,
        v.dueDate,
        v.remediation.slice(0, 45) + "...",
      ]);

      autoTable(doc, {
        startY: afterPodY + 4,
        head: [["CVE / ID", "Affected Asset", "Severity", "Owner", "SLA Due Date", "Action Item"]],
        body: vulnRows,
        theme: "striped",
        headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255] },
        styles: { fontSize: 8, cellPadding: 2 },
      });

      // Footer
      const finalY = (doc as any).lastAutoTable.finalY + 12;
      doc.setFontSize(8);
      doc.setFont("helvetica", "italic");
      doc.setTextColor(100, 116, 139);
      doc.text(
        "Confidential - For Internal Leadership & Management Review Only. Standards: ISO 27001, SOC 2 Type II, CIS Benchmark.",
        14,
        Math.min(finalY, 285)
      );

      doc.save(`Xtelify_Executive_Security_Briefing_${new Date().toISOString().slice(0, 10)}.pdf`);
    } catch (e) {
      console.error("PDF generation failed:", e);
    }
  };

  const exportExecutiveExcel = () => {
    if (!data) return;
    try {
      const wb = XLSX.utils.book_new();

      // Sheet 1: Summary
      const summaryData = [
        { Metric: "Executive Security Health Score", Value: `${data.healthScore.score}/100` },
        { Metric: "Corporate Posture Grade", Value: data.healthScore.grade },
        { Metric: "Compliance Status", Value: data.healthScore.status },
        { Metric: "Corporate SLA Compliance Rate", Value: data.kpiSummary.slaComplianceRate },
        { Metric: "Total Vulnerabilities Tracked", Value: data.kpiSummary.totalFindings },
        { Metric: "Total Remediated Issues", Value: data.kpiSummary.resolvedFindings },
        { Metric: "Open Critical P0 Vulnerabilities", Value: data.kpiSummary.criticalOpen },
        { Metric: "Open High P1 Vulnerabilities", Value: data.kpiSummary.highOpen },
        { Metric: "Mean Time to Remediate (MTTR)", Value: `${data.kpiSummary.mttrDays} Days` },
        { Metric: "Protected Kubernetes Clusters", Value: data.kpiSummary.clustersScanned },
        { Metric: "Audited Cloud Accounts", Value: data.kpiSummary.cloudAccounts },
      ];
      const wsSummary = XLSX.utils.json_to_sheet(summaryData);
      XLSX.utils.book_append_sheet(wb, wsSummary, "Executive_KPIs");

      // Sheet 2: PODs
      const wsPods = XLSX.utils.json_to_sheet(data.podAccountability);
      XLSX.utils.book_append_sheet(wb, wsPods, "POD_Accountability");

      // Sheet 3: Top Risks
      const wsRisks = XLSX.utils.json_to_sheet(data.topVulnerabilities);
      XLSX.utils.book_append_sheet(wb, wsRisks, "Top_Exposure_Risks");

      XLSX.writeFile(wb, `Xtelify_Executive_Briefing_${new Date().toISOString().slice(0, 10)}.xlsx`);
    } catch (e) {
      console.error("Excel generation failed:", e);
    }
  };

  if (loading) {
    return (
      <div className={`p-12 rounded-xl border flex flex-col items-center justify-center min-h-[450px] ${darkMode ? "bg-slate-800/80 border-slate-700" : "bg-white border-slate-200"}`}>
        <RefreshCw size={28} className="animate-spin text-blue-500 mb-4" />
        <p className={`text-sm font-semibold ${darkMode ? "text-slate-200" : "text-slate-800"}`}>Synthesizing Executive Briefing...</p>
        <p className={`text-xs mt-1 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Aggregating SLA telemetry, risk exposure indices, and POD governance metrics.</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className={`p-8 rounded-xl border ${darkMode ? "bg-slate-800 border-slate-700 text-slate-200" : "bg-white border-slate-200 text-slate-800"}`}>
        <div className="flex items-center gap-3 text-red-500 mb-3">
          <AlertTriangle size={20} />
          <h3 className="font-semibold text-base">Unable to generate executive briefing</h3>
        </div>
        <p className="text-xs mb-4 text-slate-500">{error || "Data not available"}</p>
        <button
          onClick={fetchExecutiveData}
          className="px-4 py-2 bg-blue-600 text-white rounded-md text-xs font-semibold hover:bg-blue-700 transition"
        >
          Retry Briefing Synthesis
        </button>
      </div>
    );
  }

  // Vector data for chart
  const vectorChartData = [
    { name: "Container Runtime", count: data.vectorBreakdown.CONTAINER || 0, color: "#3b82f6" },
    { name: "Cloud Config (CSPM)", count: data.vectorBreakdown.CSPM || 0, color: "#10b981" },
    { name: "Application Code (SAST)", count: data.vectorBreakdown.SAST_DAST || 0, color: "#8b5cf6" },
    { name: "Penetration (VAPT)", count: data.vectorBreakdown.VAPT || 0, color: "#f59e0b" },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Executive Command Header */}
      <div className={`p-6 rounded-xl border relative overflow-hidden ${darkMode ? "bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border-slate-700" : "bg-gradient-to-r from-slate-900 via-slate-800 to-indigo-950 border-slate-800 text-white"}`}>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1.5">
                <Sparkles size={11} /> C-Suite Executive Briefing
              </span>
              <span className="text-xs text-slate-300 font-medium">
                • Airtel Digital & Wynk Platform Security
              </span>
            </div>
            <h1 className="text-2xl lg:text-3xl font-bold tracking-tight text-white">
              Enterprise Cyber Risk & Governance Overview
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl">
              Consolidated real-time vulnerability intelligence across cloud infrastructure, containerized Kubernetes microservices, application codebases, and external pen-testing findings.
            </p>
          </div>

          {/* Quick Executive Actions */}
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={exportExecutivePDF}
              className="px-4 py-2.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-2 shadow-sm transition-all"
            >
              <Download size={14} /> Export Board Deck (PDF)
            </button>
            <button
              onClick={exportExecutiveExcel}
              className="px-3.5 py-2.5 rounded-lg text-xs font-semibold bg-slate-700 hover:bg-slate-600 text-slate-100 flex items-center gap-2 border border-slate-600 transition-all"
            >
              <FileText size={14} /> Export Excel
            </button>
            <button
              onClick={() => window.print()}
              className="px-3 py-2.5 rounded-lg text-xs font-semibold bg-slate-800/80 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 border border-slate-700 transition-all"
              title="Print view"
            >
              <Printer size={14} />
            </button>
          </div>
        </div>

        {/* Security Health Score Banner */}
        <div className="mt-6 pt-6 border-t border-slate-700/60 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="flex items-center gap-4 bg-slate-800/60 backdrop-blur p-3.5 rounded-lg border border-slate-700/60">
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center font-extrabold text-xl ${data.healthScore.score >= 85 ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-amber-500/20 text-amber-400 border border-amber-500/30"}`}>
              {data.healthScore.grade}
            </div>
            <div>
              <p className="text-[10px] uppercase font-semibold text-slate-400">Security Posture Score</p>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono tabular-nums text-white">{data.healthScore.score} / 100</span>
                <span className="text-[10px] text-emerald-400 font-semibold">{data.healthScore.weekDelta}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3.5 bg-slate-800/60 backdrop-blur p-3.5 rounded-lg border border-slate-700/60">
            <div className="p-2.5 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30">
              <Target size={20} />
            </div>
            <div>
              <p className="text-[10px] uppercase font-semibold text-slate-400">SLA Compliance Rate</p>
              <span className="text-xl font-bold font-mono tabular-nums text-white">{data.kpiSummary.slaComplianceRate}</span>
              <p className="text-[10px] text-slate-400">Target: ≥ 90% SLA Adherence</p>
            </div>
          </div>

          <div className="flex items-center gap-3.5 bg-slate-800/60 backdrop-blur p-3.5 rounded-lg border border-slate-700/60">
            <div className="p-2.5 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/30">
              <Clock size={20} />
            </div>
            <div>
              <p className="text-[10px] uppercase font-semibold text-slate-400">Mean Time to Remediate</p>
              <span className="text-xl font-bold font-mono tabular-nums text-white">{data.kpiSummary.mttrDays} Days</span>
              <p className="text-[10px] text-slate-400">Target: ≤ 7.0 Business Days</p>
            </div>
          </div>

          <div className="flex items-center gap-3.5 bg-slate-800/60 backdrop-blur p-3.5 rounded-lg border border-slate-700/60">
            <div className="p-2.5 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              <CheckCircle size={20} />
            </div>
            <div>
              <p className="text-[10px] uppercase font-semibold text-slate-400">Audit Status</p>
              <span className="text-sm font-bold text-white flex items-center gap-1.5">
                {data.governance.auditStatus}
              </span>
              <p className="text-[10px] text-slate-400">Next Review: {data.governance.nextReviewDate}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className={`flex border-b text-xs font-semibold ${darkMode ? "border-slate-700 text-slate-400" : "border-slate-200 text-slate-600"}`}>
        {[
          { id: "overview", label: "Executive Scorecard & Trends" },
          { id: "pods", label: "POD Accountability Matrix" },
          { id: "risks", label: "High-Exposure Threats (P0/P1)" },
          { id: "governance", label: "Regulatory Compliance & Standards" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-5 py-3 border-b-2 font-medium transition-all ${
              activeTab === tab.id
                ? `${darkMode ? "border-blue-500 text-blue-400 bg-slate-800/40" : "border-blue-600 text-blue-600 bg-blue-50/50"}`
                : "border-transparent hover:text-slate-800 dark:hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* C-Suite 5 Key Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div className={`p-4 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Threat Inventory</span>
                <span className="p-1.5 rounded-md bg-blue-50 dark:bg-slate-700 text-blue-600 dark:text-blue-400">
                  <Layers size={15} />
                </span>
              </div>
              <p className={`text-2xl font-bold font-mono tabular-nums ${darkMode ? "text-white" : "text-slate-900"}`}>
                {data.kpiSummary.totalFindings}
              </p>
              <div className="mt-2 text-[10px] text-slate-500 flex items-center justify-between">
                <span>Resolved: <strong className="text-emerald-500 font-mono">{data.kpiSummary.resolvedFindings}</strong></span>
                <span>Active: <strong className="text-slate-700 dark:text-slate-300 font-mono">{data.kpiSummary.openFindings}</strong></span>
              </div>
            </div>

            <div className={`p-4 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-red-500">P0 Critical Flaws</span>
                <span className="p-1.5 rounded-md bg-red-50 dark:bg-red-900/30 text-red-500">
                  <Flame size={15} />
                </span>
              </div>
              <p className="text-2xl font-bold font-mono tabular-nums text-red-600">
                {data.kpiSummary.criticalOpen}
              </p>
              <div className="mt-2 text-[10px] text-slate-500">
                <span>Zero Tolerance SLA: 7 Days</span>
              </div>
            </div>

            <div className={`p-4 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-amber-500">P1 High Flaws</span>
                <span className="p-1.5 rounded-md bg-amber-50 dark:bg-amber-900/30 text-amber-500">
                  <AlertTriangle size={15} />
                </span>
              </div>
              <p className="text-2xl font-bold font-mono tabular-nums text-amber-500">
                {data.kpiSummary.highOpen}
              </p>
              <div className="mt-2 text-[10px] text-slate-500">
                <span>Remediation Target: 14 Days</span>
              </div>
            </div>

            <div className={`p-4 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Infrastructure Scope</span>
                <span className="p-1.5 rounded-md bg-purple-50 dark:bg-purple-900/30 text-purple-500">
                  <Server size={15} />
                </span>
              </div>
              <p className={`text-2xl font-bold font-mono tabular-nums ${darkMode ? "text-white" : "text-slate-900"}`}>
                {data.kpiSummary.clustersScanned} <span className="text-xs font-normal text-slate-400">Clusters</span>
              </p>
              <div className="mt-2 text-[10px] text-slate-500">
                <span>{data.kpiSummary.cloudAccounts} AWS / GCP / Azure Accounts</span>
              </div>
            </div>

            <div className={`p-4 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-500">Resolution Velocity</span>
                <span className="p-1.5 rounded-md bg-emerald-50 dark:bg-emerald-900/30 text-emerald-500">
                  <TrendingUp size={15} />
                </span>
              </div>
              <p className="text-2xl font-bold font-mono tabular-nums text-emerald-600">
                {data.kpiSummary.totalFindings > 0 ? Math.round((data.kpiSummary.resolvedFindings / data.kpiSummary.totalFindings) * 100) : 0}%
              </p>
              <div className="mt-2 text-[10px] text-slate-500">
                <span>Velocity: {data.kpiSummary.scanVelocity}</span>
              </div>
            </div>
          </div>

          {/* Visual Analytics Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Threat Vector Distribution */}
            <div className={`p-5 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className={`font-bold text-sm ${darkMode ? "text-slate-100" : "text-slate-900"}`}>
                    Vulnerability Distribution by Attack Vector
                  </h3>
                  <p className="text-[11px] text-slate-500">Breakdown of findings across scanners and runtime surfaces</p>
                </div>
                <span className="text-xs font-semibold px-2 py-1 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                  4 Vectors Tracked
                </span>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={vectorChartData} layout="vertical" margin={{ left: 20, right: 30, top: 10, bottom: 10 }}>
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke={darkMode ? "#334155" : "#f1f5f9"} />
                    <XAxis type="number" tick={{ fontSize: 11, fill: darkMode ? "#94a3b8" : "#64748b" }} />
                    <YAxis dataKey="name" type="category" width={140} tick={{ fontSize: 11, fill: darkMode ? "#cbd5e1" : "#334155" }} />
                    <RechartsTooltip
                      contentStyle={{
                        borderRadius: "8px",
                        backgroundColor: darkMode ? "#0f172a" : "#fff",
                        borderColor: darkMode ? "#334155" : "#e2e8f0",
                        fontSize: "12px",
                      }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {vectorChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* SLA Ageing Breakdown */}
            <div className={`p-5 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className={`font-bold text-sm ${darkMode ? "text-slate-100" : "text-slate-900"}`}>
                    SLA Ageing & Compliance Risk Index
                  </h3>
                  <p className="text-[11px] text-slate-500">Distribution of active findings against corporate remediation windows</p>
                </div>
                <span className="text-xs font-semibold text-emerald-500 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-200 dark:border-emerald-800">
                  {data.kpiSummary.slaComplianceRate} Compliant
                </span>
              </div>

              <div className="space-y-4 pt-2">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-medium text-emerald-600 dark:text-emerald-400">Within Standard SLA (&lt; 7 Days)</span>
                    <span className="font-mono font-bold text-slate-700 dark:text-slate-300">
                      {Math.max(0, data.kpiSummary.openFindings - data.kpiSummary.slaBreachedCount)} Issues
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
                    <div
                      className="h-full bg-emerald-500"
                      style={{
                        width: `${data.kpiSummary.openFindings > 0 ? Math.round(((data.kpiSummary.openFindings - data.kpiSummary.slaBreachedCount) / data.kpiSummary.openFindings) * 100) : 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-medium text-amber-500">Approaching SLA Window (8 - 14 Days)</span>
                    <span className="font-mono font-bold text-slate-700 dark:text-slate-300">
                      {Math.min(data.kpiSummary.openFindings, Math.round(data.kpiSummary.openFindings * 0.25))} Issues
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
                    <div className="h-full bg-amber-400" style={{ width: "25%" }} />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-medium text-red-500">SLA Exceeded / Action Required (&gt; 14 Days)</span>
                    <span className="font-mono font-bold text-red-500">
                      {data.kpiSummary.slaBreachedCount} Issues
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
                    <div
                      className="h-full bg-red-500"
                      style={{
                        width: `${data.kpiSummary.openFindings > 0 ? Math.min(100, Math.round((data.kpiSummary.slaBreachedCount / data.kpiSummary.openFindings) * 100)) : 0}%`,
                      }}
                    />
                  </div>
                </div>

                <div className={`p-3 rounded-lg text-xs mt-4 flex items-start gap-2.5 ${darkMode ? "bg-slate-900/60 border border-slate-700" : "bg-slate-50 border border-slate-200"}`}>
                  <Zap size={15} className="text-amber-500 shrink-0 mt-0.5" />
                  <p className="text-slate-500 dark:text-slate-400 leading-relaxed">
                    <strong className="text-slate-700 dark:text-slate-200">Executive Recommendation:</strong> Immediate prioritisation needed on {data.kpiSummary.criticalOpen} P0 zero-day CVEs in Wynk streaming and AdTech ingress gateway images before the upcoming sprint release.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === "pods" && (
        <div className={`p-6 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
            <div>
              <h3 className={`font-bold text-base ${darkMode ? "text-slate-100" : "text-slate-900"}`}>
                Business Unit & Engineering POD Accountability Matrix
              </h3>
              <p className="text-xs text-slate-500">Live breakdown of remediation performance by engineering division</p>
            </div>
            <button
              onClick={onSwitchToManager}
              className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-50 dark:bg-slate-700 text-blue-600 dark:text-blue-400 hover:bg-blue-100 transition flex items-center gap-1.5 self-start"
            >
              Open Manager Deep-Dive <ChevronRight size={14} />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className={`border-b ${darkMode ? "border-slate-700 text-slate-400 bg-slate-900/40" : "border-slate-200 text-slate-500 bg-slate-50"}`}>
                  <th className="p-3.5 font-semibold">Department / Business Unit</th>
                  <th className="p-3.5 font-semibold">Engineering Lead</th>
                  <th className="p-3.5 font-semibold text-center">Total Identified</th>
                  <th className="p-3.5 font-semibold text-center">Remediated</th>
                  <th className="p-3.5 font-semibold text-center">Open P0 Critical</th>
                  <th className="p-3.5 font-semibold text-center">SLA Adherence</th>
                  <th className="p-3.5 font-semibold text-center">Governance Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/60">
                {data.podAccountability.map((pod) => (
                  <tr key={pod.department} className={`transition-colors ${darkMode ? "hover:bg-slate-700/30" : "hover:bg-slate-50"}`}>
                    <td className="p-3.5 font-bold text-slate-800 dark:text-slate-200">
                      {pod.department}
                    </td>
                    <td className="p-3.5 font-medium text-slate-600 dark:text-slate-400">
                      {pod.lead}
                    </td>
                    <td className="p-3.5 text-center font-mono font-bold text-slate-800 dark:text-slate-200">
                      {pod.total}
                    </td>
                    <td className="p-3.5 text-center font-mono font-bold text-emerald-600">
                      {pod.resolved}
                    </td>
                    <td className="p-3.5 text-center">
                      <span className={`px-2 py-0.5 rounded font-mono font-bold text-xs ${pod.criticalOpen > 0 ? "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300" : "text-slate-400"}`}>
                        {pod.criticalOpen}
                      </span>
                    </td>
                    <td className="p-3.5 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <span className="font-mono font-bold text-xs">{pod.compliancePct}%</span>
                        <div className="w-16 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                          <div
                            className={`h-full ${pod.compliancePct >= 80 ? "bg-emerald-500" : pod.compliancePct >= 50 ? "bg-amber-400" : "bg-red-500"}`}
                            style={{ width: `${pod.compliancePct}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="p-3.5 text-center">
                      <span className={`px-2.5 py-1 rounded-md text-[11px] font-semibold ${
                        pod.compliancePct >= 80
                          ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800"
                          : "bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300 border border-amber-200 dark:border-amber-800"
                      }`}>
                        {pod.compliancePct >= 80 ? "Compliant" : "Needs Review"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "risks" && (
        <div className={`p-6 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className={`font-bold text-base ${darkMode ? "text-slate-100" : "text-slate-900"}`}>
                Top High-Exposure Vulnerabilities (P0 / Critical)
              </h3>
              <p className="text-xs text-slate-500">Requiring immediate architectural patches and executive review</p>
            </div>
            <button
              onClick={onSwitchToDetail}
              className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-50 dark:bg-slate-700 text-blue-600 dark:text-blue-400 hover:bg-blue-100 transition flex items-center gap-1.5"
            >
              View Full Asset Table <ChevronRight size={14} />
            </button>
          </div>

          <div className="space-y-3">
            {data.topVulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className={`p-4 rounded-xl border transition-all ${
                  darkMode ? "bg-slate-900/60 border-slate-700 hover:border-slate-600" : "bg-slate-50 border-slate-200 hover:border-slate-300"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">
                      {vuln.id}
                    </span>
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
                      {vuln.asset}
                    </span>
                    <span className="text-xs text-slate-400">• {vuln.department}</span>
                  </div>
                  <div className="flex items-center gap-4 text-xs">
                    <span className="text-slate-500">Lead: <strong>{vuln.assignedTo}</strong></span>
                    <span className="text-red-500 font-semibold">Due: {vuln.dueDate}</span>
                  </div>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 mb-2 leading-relaxed">
                  {vuln.title}
                </p>
                <div className="flex items-center gap-2 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
                  <CheckCircle size={13} className="shrink-0" />
                  <span>Fix: {vuln.remediation}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "governance" && (
        <div className={`p-6 rounded-xl border ${darkMode ? "bg-slate-800/90 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
          <h3 className={`font-bold text-base mb-2 ${darkMode ? "text-slate-100" : "text-slate-900"}`}>
            Regulatory Compliance & Audit Framework Mapping
          </h3>
          <p className="text-xs text-slate-500 mb-6">Verification of enterprise controls against institutional standards</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            {data.governance.standards.map((std) => (
              <div
                key={std}
                className={`p-4 rounded-xl border flex items-start gap-3.5 ${
                  darkMode ? "bg-slate-900/50 border-slate-700" : "bg-slate-50 border-slate-200"
                }`}
              >
                <div className="p-2 rounded-lg bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400 mt-0.5">
                  <Shield size={18} />
                </div>
                <div>
                  <h4 className="font-bold text-sm text-slate-800 dark:text-slate-200">{std}</h4>
                  <p className="text-xs text-slate-500 mt-1">
                    Continuous automated scanning verified. Role-based access control, cryptographic isolation, and audit trails logged.
                  </p>
                  <span className="inline-block mt-2 text-[10px] font-bold text-emerald-600 uppercase tracking-wider">
                    • 100% Control Compliance
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className={`p-4 rounded-lg border text-xs flex items-center justify-between ${darkMode ? "bg-slate-900 border-slate-700 text-slate-300" : "bg-slate-100 border-slate-200 text-slate-700"}`}>
            <div>
              <p className="font-semibold">Next Official Board Cybersecurity Audit Review:</p>
              <p className="text-slate-500 dark:text-slate-400">{data.governance.nextReviewDate} (CISO & Risk Committee)</p>
            </div>
            <button
              onClick={exportExecutivePDF}
              className="px-4 py-2 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 transition"
            >
              Download Audit Package
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
