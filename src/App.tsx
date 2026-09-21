import React, {
  useState,
  useEffect,
  useRef,
  useMemo,
  Component,
  useCallback,
} from "react";
import type { ErrorInfo, ReactNode } from "react";
import * as XLSX from "xlsx";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import html2canvas from "html2canvas";
import {
  Shield,
  AlertTriangle,
  Clock,
  Filter,
  Download,
  Upload,
  Flame,
  ArrowRight,
  Activity,
  FileText,
  ChevronDown,
  Trash2,
  Server,
  Wrench,
  CheckSquare,
  Square,
  Layers,
  Users,
  Bot,
  X,
  Send,
  FileUp,
  MessageSquare,
  GripVertical,
  Search,
  Moon,
  Sun,
  TrendingUp,
  Target,
  Bookmark,
  BookmarkCheck,
  AlertCircle,
  Zap,
  Calendar,
  ChevronLeft,
  ChevronRight,
  CalendarDays,
  Sparkles,
  Copy,
  RefreshCw,
  Bug,
  Share2,
  CheckCircle
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip as RechartsTooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  BarChart,
  Bar,
} from "recharts";

const BACKEND_URL = (() => {
  const hostname = window.location.hostname;
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return "http://127.0.0.1:8000";
  }
  return "";
})();

interface Issue {
  [key: string]: any;
  IssueID: string;
  DisplayID: string;
  UploadBatch: string;
  Severity: string;
  Status: string;
  Department: string;
  AssignedTo: string;
  Type: string;
  Category: string;
  DueDate: string;
  DiscoveredDate: string;
  Description: string;
  AffectedAsset: string;
  Evidence: string;
  RecommendedAction: string;
  ReferenceLinks: string;
}

interface AiRemediationResult {
  AI_Summary: string;
  AI_RootCause: string;
  AI_Impact: string;
  AI_Remediation: string[];
  AI_Validation: string[];
  AI_Priority: string;
}

interface IssueGroup {
  [key: string]: any;
  DisplayID: string;
  IssueID: string;
  Severity: string;
  Status: string;
  Category: string;
  Remediation: string;
  DueDate: string;
  Description: string;
  ReferenceLinks: string;
  Assets: {
    AssetName: string;
    AssignedTo: string;
    Status: string;
    IssueID: string;
  }[];
}


interface TimelineData {
  count: number;
  ids: string[];
}

interface TooltipProps {
  active?: boolean;
  payload?: Array<{ payload: { Issues: number; Vulnerabilities: string } }>;
  label?: string;
}

interface CardProps {
  title: string;
  val: number | string;
  Icon: React.ElementType;
  color: string;
  bg: string;
}

interface SecurityAgentProps {
  contextData: Issue[];
}

interface ChatMessage {
  role: string;
  content: string;
}

interface SavedFilter {
  id: string;
  name: string;
  filter: string;
  searchTerm: string;
  department: string;
}

interface VulnNote {
  id: string;
  vulnId: string;
  text: string;
  timestamp: string;
  author: string;
}

interface ActivityLog {
  id: string;
  vulnId: string;
  action: string;
  timestamp: string;
  user: string;
  details: string;
}


const CalendarView: React.FC<{ darkMode: boolean; onViewUpload: (batch: string) => void }> = ({ darkMode, onViewUpload }) => {
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState<Date | null>(new Date());
  const [viewType, setViewType] = useState<"Vulnerabilities" | "Uploads">("Vulnerabilities");

  const [monthlyActivity, setMonthlyActivity] = useState<Record<string, { vulnerabilities: number, uploads: number }>>({});
  const [dailyVulns, setDailyVulns] = useState<any>(null);
  const [dailyUploads, setDailyUploads] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const year = currentDate.getFullYear();
  const month = currentDate.getMonth() + 1;

  const handleDeleteDataset = async (batch: string) => {
    if (!window.confirm(`Are you sure you want to delete dataset "${batch}"? This action cannot be undone.`)) return;
    try {
      const res = await fetch(`${BACKEND_URL}/api/dataset?batch_id=${encodeURIComponent(batch)}`, { method: 'DELETE' });
      if (!res.ok) throw new Error("Failed to delete dataset");
      setRefreshKey(prev => prev + 1);
    } catch (err: any) {
      alert("Error deleting dataset: " + err.message);
    }
  };

  useEffect(() => {
    const fetchMonthly = async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/api/calendar/activity?year=${year}&month=${month}`);
        if (!res.ok) throw new Error("MongoDB is currently unavailable or returned an error.");
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        setMonthlyActivity(data);
        setError(null);
      } catch (err: any) {
        setError("Unable to load calendar activity. " + (err.message || "MongoDB is currently unavailable."));
      }
    };
    fetchMonthly();
  }, [year, month, refreshKey]);

  useEffect(() => {
    if (!selectedDate) return;
    const fetchDaily = async () => {
      setLoading(true);
      setError(null);

      const tzoffset = selectedDate.getTimezoneOffset() * 60000;
      const localISOTime = (new Date(selectedDate.getTime() - tzoffset)).toISOString().slice(0, 10);

      try {
        if (viewType === "Vulnerabilities") {
          const res = await fetch(`${BACKEND_URL}/api/calendar/vulnerabilities?date=${localISOTime}`);
          if (!res.ok) throw new Error("MongoDB is currently unavailable.");
          const data = await res.json();
          if (data.error) throw new Error(data.error);
          setDailyVulns(data);
        } else {
          const res = await fetch(`${BACKEND_URL}/api/calendar/uploads?date=${localISOTime}`);
          if (!res.ok) throw new Error("MongoDB is currently unavailable.");
          const data = await res.json();
          if (data.error) throw new Error(data.error);
          setDailyUploads(data);
        }
      } catch (err: any) {
        setError("Unable to load details. " + (err.message || "MongoDB is currently unavailable."));
      } finally {
        setLoading(false);
      }
    };
    fetchDaily();
  }, [selectedDate, viewType, refreshKey]);

  const daysInMonth = new Date(year, month, 0).getDate();
  const firstDayOfMonth = new Date(year, month - 1, 1).getDay();
  const days = Array.from({ length: daysInMonth }, (_, i) => i + 1);
  const blanks = Array.from({ length: firstDayOfMonth }, (_, i) => i);

  const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

  const prevMonth = () => setCurrentDate(new Date(year, month - 2, 1));
  const nextMonth = () => setCurrentDate(new Date(year, month, 1));

  return (
    <div className={`mt-6 p-6 rounded-lg ${darkMode ? "bg-slate-800" : "bg-white border border-slate-200"}`}>
      <div className="flex flex-col md:flex-row gap-8">

        <div className="flex-1">
          <div className="flex items-center justify-between mb-6">
            <h2 className={`text-xl font-bold ${darkMode ? "text-white" : "text-slate-800"}`}>Calendar / Activity</h2>
            <div className={`flex rounded-lg overflow-hidden border ${darkMode ? "border-slate-700" : "border-slate-200"}`}>
              <button
                onClick={() => setViewType("Vulnerabilities")}
                className={`px-4 py-2 text-sm font-medium transition-colors ${viewType === "Vulnerabilities" ? (darkMode ? "bg-purple-600 text-white" : "bg-purple-100 text-purple-700") : (darkMode ? "bg-slate-800 text-slate-400 hover:bg-slate-700" : "bg-slate-50 text-slate-600 hover:bg-slate-100")}`}
              >
                Vulnerabilities
              </button>
              <button
                onClick={() => setViewType("Uploads")}
                className={`px-4 py-2 text-sm font-medium transition-colors ${viewType === "Uploads" ? (darkMode ? "bg-blue-600 text-white" : "bg-blue-100 text-blue-700") : (darkMode ? "bg-slate-800 text-slate-400 hover:bg-slate-700" : "bg-slate-50 text-slate-600 hover:bg-slate-100")}`}
              >
                Dataset Uploads
              </button>
            </div>
          </div>

          <div className={`p-5 rounded-lg border ${darkMode ? "bg-slate-900 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
            <div className="flex items-center justify-between mb-4">
              <button onClick={prevMonth} className={`p-2 rounded-full ${darkMode ? "hover:bg-slate-800 text-slate-300" : "hover:bg-slate-200 text-slate-600"}`}>
                <ChevronLeft size={20} />
              </button>
              <div className="flex items-center gap-2">
                <select
                  value={month - 1}
                  onChange={(e) => setCurrentDate(new Date(year, parseInt(e.target.value), 1))}
                  className={`bg-transparent font-bold text-lg outline-none cursor-pointer ${darkMode ? "text-white" : "text-slate-800"}`}
                >
                  {monthNames.map((m, i) => <option key={m} value={i} className={darkMode ? "bg-slate-800" : ""}>{m}</option>)}
                </select>
                <select
                  value={year}
                  onChange={(e) => setCurrentDate(new Date(parseInt(e.target.value), month - 1, 1))}
                  className={`bg-transparent font-bold text-lg outline-none cursor-pointer ${darkMode ? "text-white" : "text-slate-800"}`}
                >
                  {Array.from({ length: 10 }, (_, i) => year - 5 + i).map(y => <option key={y} value={y} className={darkMode ? "bg-slate-800" : ""}>{y}</option>)}
                </select>
              </div>
              <button onClick={nextMonth} className={`p-2 rounded-full ${darkMode ? "hover:bg-slate-800 text-slate-300" : "hover:bg-slate-200 text-slate-600"}`}>
                <ChevronRight size={20} />
              </button>
            </div>

            <div className="grid grid-cols-7 gap-2 mb-2">
              {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(d => (
                <div key={d} className={`text-center text-xs font-semibold py-2 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>{d}</div>
              ))}
            </div>

            <div className="grid grid-cols-7 gap-2">
              {blanks.map(b => <div key={`blank-${b}`} className="h-14"></div>)}
              {days.map(d => {
                const dateStr = `${year}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
                const isSelected = selectedDate?.getDate() === d && selectedDate?.getMonth() + 1 === month && selectedDate?.getFullYear() === year;
                const isToday = new Date().getDate() === d && new Date().getMonth() + 1 === month && new Date().getFullYear() === year;
                const act = monthlyActivity[dateStr];

                return (
                  <div
                    key={d}
                    onClick={() => setSelectedDate(new Date(year, month - 1, d))}
                    className={`h-14 rounded-md border flex flex-col items-center justify-start pt-1 cursor-pointer transition-colors
                      ${isSelected ? (darkMode ? "bg-slate-700 border-purple-500" : "bg-purple-50 border-purple-400") : (darkMode ? "bg-slate-800 border-slate-700 hover:bg-slate-700" : "bg-white border-slate-200 hover:bg-slate-50")}
                      ${isToday && !isSelected ? (darkMode ? "border-blue-500" : "border-blue-400") : ""}
                    `}
                  >
                    <span className={`text-sm font-medium ${isToday ? (darkMode ? "text-blue-400" : "text-blue-600") : (darkMode ? "text-slate-300" : "text-slate-700")}`}>{d}</span>
                    <div className="flex gap-1 mt-auto pb-1">
                      {act?.vulnerabilities > 0 && <div className="w-1.5 h-1.5 rounded-full bg-red-500" title={`${act.vulnerabilities} vulnerabilities`}></div>}
                      {act?.uploads > 0 && <div className="w-1.5 h-1.5 rounded-full bg-blue-500" title={`${act.uploads} uploads`}></div>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className={`flex-1 p-6 rounded-lg border ${darkMode ? "bg-slate-900 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
          {error ? (
            <div className={`p-4 rounded-lg flex items-center gap-3 ${darkMode ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-red-50 text-red-600 border border-red-100"}`}>
              <AlertTriangle size={24} />
              <p className="font-medium text-sm">{error}</p>
            </div>
          ) : selectedDate ? (
            <>
              <h3 className={`text-lg font-semibold mb-6 flex items-center gap-2 ${darkMode ? "text-white" : "text-slate-800"}`}>
                <CalendarDays size={20} className={darkMode ? "text-purple-400" : "text-purple-600"} />
                {selectedDate.toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' })}
              </h3>

              {loading ? (
                <div className="flex justify-center items-center py-20">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div>
                </div>
              ) : viewType === "Vulnerabilities" ? (
                <div>
                  {!dailyVulns || dailyVulns.total === 0 ? (
                    <p className={`text-center py-10 ${darkMode ? "text-slate-500" : "text-slate-500"}`}>No vulnerabilities uploaded on this date.</p>
                  ) : (
                    <div className="space-y-6">
                      <div className={`p-4 rounded-lg flex items-center justify-between ${darkMode ? "bg-slate-800 border border-slate-700" : "bg-white border border-slate-200 shadow-sm"}`}>
                        <span className={`text-sm font-medium ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Total Vulnerabilities</span>
                        <span className={`text-2xl font-bold ${darkMode ? "text-white" : "text-slate-800"}`}>{dailyVulns.total.toLocaleString()}</span>
                      </div>

                      <div>
                        <h4 className={`text-xs font-bold uppercase tracking-wider mb-3 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Severity Breakdown</h4>
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                          {["Critical", "High", "Medium", "Low", "Info"].map(sev => (
                            <div key={sev} className={`p-3 rounded-lg text-center border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
                              <p className={`text-xs mb-1 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>{sev}</p>
                              <p className={`text-lg font-bold ${sev === "Critical" ? "text-red-500" :
                                sev === "High" ? "text-orange-500" :
                                  sev === "Medium" ? "text-amber-500" :
                                    sev === "Low" ? "text-green-500" : "text-blue-500"
                                }`}>{dailyVulns.severity[sev]?.toLocaleString() || 0}</p>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div>
                        <h4 className={`text-xs font-bold uppercase tracking-wider mb-3 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Source Format</h4>
                        <div className="grid grid-cols-2 gap-3">
                          {[
                            { k: "CSPM", l: "CSPM" },
                            { k: "VAPT", l: "VAPT" },
                            { k: "CONTAINER", l: "Container" },
                            { k: "SAST_DAST", l: "SAST/DAST" }
                          ].map(fmt => (
                            <div key={fmt.k} className={`p-3 rounded-lg flex items-center justify-between border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200 shadow-sm"}`}>
                              <span className={`text-sm font-medium ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{fmt.l}</span>
                              <span className={`text-base font-bold ${darkMode ? "text-white" : "text-slate-800"}`}>{dailyVulns.formats[fmt.k]?.toLocaleString() || 0}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <HistoricalAnalyticsModule darkMode={darkMode} selectedDate={selectedDate} />
              )}
            </>
          ) : (
            <p className={`text-center py-10 ${darkMode ? "text-slate-500" : "text-slate-500"}`}>Select a date to view activity</p>
          )}
        </div>
      </div>
    </div>
  );
};

class ErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean; error: Error | null; errorInfo: ErrorInfo | null }
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught error:", error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-900 text-white p-10 font-mono flex items-center justify-center">
          <div className="bg-red-500/10 border border-red-500 p-8 rounded-lg max-w-4xl w-full shadow-2xl">
            <h1 className="text-3xl font-bold text-red-500 mb-2 flex items-center gap-3">
              <AlertTriangle size={32} /> Fatal React Crash Detected
            </h1>
            <p className="text-slate-300 mb-6 border-b border-red-500/30 pb-4">
              The application crashed. Please copy the error text below.
            </p>
            <div className="bg-black/60 p-4 rounded-md text-sm text-red-300 overflow-auto max-h-[500px]">
              <strong className="text-white">Error Message:</strong>{" "}
              {this.state.error?.toString()}
              <br />
              <br />
              <strong className="text-white">Component Stack Trace:</strong>
              <pre className="mt-2 text-xs text-slate-400">
                {this.state.errorInfo?.componentStack}
              </pre>
            </div>
            <button
              onClick={() => window.location.reload()}
              className="mt-6 px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-bold rounded"
            >
              Force Reload Application
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const CustomTimelineTooltip: React.FC<TooltipProps> = ({
  active,
  payload,
  label,
}) => {
  if (active && payload && payload.length > 0 && payload[0]) {
    const data = payload[0].payload;
    if (!data || data.Issues === 0) return null;
    return (
      <div className="bg-white p-3 border border-slate-300 shadow-sm rounded-sm z-50 relative">
        <p className="font-semibold text-slate-800 mb-1 border-b border-slate-100 pb-1">
          {label}
        </p>
        <p className="text-slate-700 font-medium text-xs mb-1">
          Issues Discovered: <span className="text-red-600">{data.Issues}</span>
        </p>
        <p className="text-xs text-slate-500 max-w-[250px] leading-relaxed">
          {data.Vulnerabilities}
        </p>
      </div>
    );
  }
  return null;
};

const HistoricalAnalyticsModule: React.FC<{ darkMode: boolean; selectedDate: Date | null }> = ({ darkMode, selectedDate }) => {
  const [selectedFormats, setSelectedFormats] = useState<string[]>(['Container', 'VAPT', 'CSPM', 'SAST_DAST']);
  const [startDateStr, setStartDateStr] = useState<string>('');
  const [endDateStr, setEndDateStr] = useState<string>('');
  const [viewMode, setViewMode] = useState<'Daily' | 'Cumulative'>('Daily');

  const [loading, setLoading] = useState(false);
  const [datasets, setDatasets] = useState<any[]>([]);
  const [chartData, setChartData] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [selectedDatasets, setSelectedDatasets] = useState<string[]>([]);

  const [ownerData, setOwnerData] = useState<any[]>([]);
  const [selectedOwner, setSelectedOwner] = useState<string | null>(null);
  const [ownerTimeline, setOwnerTimeline] = useState<any[]>([]);
  const [ownerSummary, setOwnerSummary] = useState<any>({});
  const [ownerLoading, setOwnerLoading] = useState(false);

  const [compareMode, setCompareMode] = useState(false);
  const [compareBatches, setCompareBatches] = useState<string[]>([]);
  const [compareData, setCompareData] = useState<any>(null);
  const [compareLoading, setCompareLoading] = useState(false);

  const fetchAnalytics = async () => {
    setLoading(true);
    try {
      const formatQuery = selectedFormats.length > 0 ? `formats=${selectedFormats.join(',')}` : '';
      const startQuery = startDateStr ? `start_date=${startDateStr}` : '';
      const endQuery = endDateStr ? `end_date=${endDateStr}` : '';
      const batchesQuery = selectedDatasets.length > 0 ? `upload_batches=${selectedDatasets.join('||')}` : '';

      const queryParams = [formatQuery, startQuery, endQuery, batchesQuery, `mode=${viewMode}`].filter(Boolean).join('&');

      const [histRes, dsRes, ownersRes] = await Promise.all([
        fetch(`${BACKEND_URL}/api/analytics/historical?${queryParams}`),
        fetch(`${BACKEND_URL}/api/analytics/datasets?${queryParams}`),
        fetch(`${BACKEND_URL}/api/analytics/owners?${queryParams}`)
      ]);

      if (histRes.ok) {
        const hData = await histRes.json();
        setChartData(hData.chartData || []);
        setSummary(hData.summary || {});
      }
      if (dsRes.ok) {
        const dData = await dsRes.json();
        setDatasets(dData || []);
      }
      if (ownersRes.ok) {
        const oData = await ownersRes.json();
        setOwnerData(oData.ownerData || []);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedDate) {
      const d = selectedDate.toISOString().split('T')[0];
      setStartDateStr(d);
      setEndDateStr(d);
    }
  }, [selectedDate]);

  useEffect(() => {
    fetchAnalytics();
  }, [selectedFormats, startDateStr, endDateStr, viewMode, selectedDatasets]);

  useEffect(() => {
    if (!selectedOwner) return;
    const fetchOwner = async () => {
      setOwnerLoading(true);
      try {
        const formatQuery = selectedFormats.length > 0 ? `formats=${selectedFormats.join(',')}` : '';
        const startQuery = startDateStr ? `start_date=${startDateStr}` : '';
        const endQuery = endDateStr ? `end_date=${endDateStr}` : '';
        const batchesQuery = selectedDatasets.length > 0 ? `upload_batches=${selectedDatasets.join('||')}` : '';

        const queryParams = [formatQuery, startQuery, endQuery, batchesQuery, `mode=${viewMode}`, `owner=${encodeURIComponent(selectedOwner)}`].filter(Boolean).join('&');

        const res = await fetch(`${BACKEND_URL}/api/analytics/owners?${queryParams}`);
        if (res.ok) {
          const data = await res.json();
          setOwnerTimeline(data.chartData || []);
          setOwnerSummary(data.summary || {});
        }
      } catch (e) {
        console.error(e);
      } finally {
        setOwnerLoading(false);
      }
    };
    fetchOwner();
  }, [selectedOwner, selectedFormats, startDateStr, endDateStr, viewMode, selectedDatasets]);

  const toggleFormat = (fmt: string) => {
    setSelectedFormats(prev => prev.includes(fmt) ? prev.filter(f => f !== fmt) : [...prev, fmt]);
  };

  const toggleDataset = (batch: string) => {
    setSelectedDatasets(prev => prev.includes(batch) ? prev.filter(b => b !== batch) : [...prev, batch]);
  };

  const handleCompare = async () => {
    if (compareBatches.length !== 2) return;
    setCompareLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/analytics/compare?batch1=${compareBatches[0]}&batch2=${compareBatches[1]}`);
      if (res.ok) {
        setCompareData(await res.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setCompareLoading(false);
    }
  };

  const handleShare = (type: 'data' | 'graph' | 'both') => {
    const subject = encodeURIComponent(`Security Report for ${selectedOwner}`);
    let bodyText = `Analytics for ${selectedOwner} (${startDateStr || 'Start'} to ${endDateStr || 'End'}):\n\n`;
    bodyText += `Total: ${ownerSummary.Total || 0}\n`;
    bodyText += `Resolved: ${ownerSummary.Resolved || 0}\n`;
    bodyText += `Unresolved: ${ownerSummary.Unresolved || 0}\n`;
    bodyText += `Critical: ${ownerSummary.Critical || 0}\n`;
    bodyText += `High: ${ownerSummary.High || 0}\n\n`;

    if (type === 'graph' || type === 'both') {
      bodyText += `Please see the attached/included graph for vulnerability trends.\n\n`;
    }

    bodyText += `View full report in Xtelify Security Portal.`;
    window.location.href = `mailto:?subject=${subject}&body=${encodeURIComponent(bodyText)}`;
  };

  return (
    <div className={`p-6 rounded-lg border ${darkMode ? "bg-slate-900 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-2">
          {[{ k: 'CONTAINER', l: 'Container' }, { k: 'VAPT', l: 'VAPT' }, { k: 'CSPM', l: 'CSPM' }, { k: 'SAST_DAST', l: 'SAST/DAST' }].map(f => (
            <button
              key={f.k}
              onClick={() => toggleFormat(f.k)}
              className={`px-3 py-1.5 text-xs font-semibold rounded transition-colors ${selectedFormats.includes(f.k) ? (darkMode ? 'bg-blue-600 text-white' : 'bg-blue-100 text-blue-800') : (darkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-200 text-slate-600')}`}
            >
              {f.l}
            </button>
          ))}
          <button onClick={() => setSelectedFormats(['CONTAINER', 'VAPT', 'CSPM', 'SAST_DAST'])} className={`px-2 text-xs underline ${darkMode ? 'text-slate-400' : 'text-slate-500'}`}>All</button>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <input type="date" value={startDateStr} onChange={(e) => setStartDateStr(e.target.value)} className={`px-2 py-1 text-sm rounded border ${darkMode ? "bg-slate-800 border-slate-700 text-white" : "bg-white border-slate-300"}`} />
            <span className={darkMode ? "text-slate-400" : "text-slate-500"}>to</span>
            <input type="date" value={endDateStr} onChange={(e) => setEndDateStr(e.target.value)} className={`px-2 py-1 text-sm rounded border ${darkMode ? "bg-slate-800 border-slate-700 text-white" : "bg-white border-slate-300"}`} />
          </div>
          <div className="flex bg-slate-200 dark:bg-slate-800 rounded p-1">
            <button onClick={() => setViewMode('Daily')} className={`px-3 py-1 text-xs font-bold rounded ${viewMode === 'Daily' ? 'bg-white dark:bg-slate-700 shadow' : 'text-slate-500'}`}>Daily</button>
            <button onClick={() => setViewMode('Cumulative')} className={`px-3 py-1 text-xs font-bold rounded ${viewMode === 'Cumulative' ? 'bg-white dark:bg-slate-700 shadow' : 'text-slate-500'}`}>Cumulative</button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className={`p-4 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
          <p className="text-xs text-slate-500 font-bold uppercase">Total Datasets</p>
          <p className="text-2xl font-bold">{summary.totalDatasets || 0}</p>
        </div>
        <div className={`p-4 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
          <p className="text-xs text-slate-500 font-bold uppercase">Vulnerabilities</p>
          <p className="text-2xl font-bold">{summary.totalVulnerabilities || 0}</p>
        </div>
        <div className={`p-4 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
          <p className="text-xs text-green-500 font-bold uppercase">Resolved</p>
          <p className="text-2xl font-bold text-green-500">{summary.resolved || 0}</p>
        </div>
        <div className={`p-4 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
          <p className="text-xs text-red-500 font-bold uppercase">Unresolved</p>
          <p className="text-2xl font-bold text-red-500">{summary.unresolved || 0}</p>
        </div>
      </div>

      {viewMode === 'Cumulative' && (
        <p className={`text-sm italic mb-2 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Current cumulative totals as of {endDateStr || new Date().toISOString().split('T')[0]}</p>
      )}

      <div id="vulnerability-history-chart" className={`h-64 mb-6 p-4 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
        {loading ? <div className="h-full flex items-center justify-center">Loading...</div> : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? "#334155" : "#e2e8f0"} />
              <XAxis dataKey="date" stroke={darkMode ? "#94a3b8" : "#64748b"} fontSize={12} />
              <YAxis stroke={darkMode ? "#94a3b8" : "#64748b"} fontSize={12} />
              <RechartsTooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', borderRadius: '8px' }} />
              <Legend />
              <Area type="monotone" dataKey="Unresolved" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
              <Area type="monotone" dataKey="Resolved" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.6} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="flex justify-between items-center mb-4 mt-8">
        <h3 className="font-bold text-lg">Owner-wise Analytics</h3>
      </div>

      {!selectedOwner ? (
        <div className={`p-4 rounded-lg border h-80 mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
          {loading ? <div className="h-full flex items-center justify-center">Loading...</div> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ownerData} onClick={(data) => {
                if (data?.activeLabel) setSelectedOwner(String(data.activeLabel));
              }}>
                <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? "#334155" : "#e2e8f0"} />
                <XAxis dataKey="Owner" stroke={darkMode ? "#94a3b8" : "#64748b"} fontSize={12} />
                <YAxis stroke={darkMode ? "#94a3b8" : "#64748b"} fontSize={12} />
                <RechartsTooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', borderRadius: '8px' }} cursor={{ fill: darkMode ? '#334155' : '#f1f5f9' }} />
                <Legend />
                <Bar dataKey="Resolved" stackId="a" fill="#22c55e" radius={[0, 0, 4, 4]} />
                <Bar dataKey="Unresolved" stackId="a" fill="#ef4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      ) : (
        <div className={`p-4 rounded-lg border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
          <div className="flex justify-between items-center mb-4">
            <h4 className="font-bold text-lg">{selectedOwner}'s Analytics</h4>
            <div className="flex gap-2">
              <button className={`px-3 py-1.5 rounded text-sm font-bold flex items-center gap-1 ${darkMode ? "bg-slate-700 text-blue-400 hover:bg-slate-600" : "bg-blue-100 text-blue-700 hover:bg-blue-200"}`} onClick={() => handleShare('data')}>
                Share Data
              </button>
              <button className={`px-3 py-1.5 rounded text-sm font-bold flex items-center gap-1 ${darkMode ? "bg-slate-700 text-blue-400 hover:bg-slate-600" : "bg-blue-100 text-blue-700 hover:bg-blue-200"}`} onClick={() => handleShare('graph')}>
                Share Graph
              </button>
              <button className={`px-3 py-1.5 rounded text-sm font-bold flex items-center gap-1 ${darkMode ? "bg-blue-600 text-white hover:bg-blue-500" : "bg-blue-600 text-white hover:bg-blue-700"}`} onClick={() => handleShare('both')}>
                Share Both
              </button>
              <button className={`px-3 py-1.5 rounded text-sm font-bold ${darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-200 text-slate-700 hover:bg-slate-300"}`} onClick={() => setSelectedOwner(null)}>
                Back
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            {['Total', 'Resolved', 'Unresolved', 'Critical', 'High'].map(k => (
              <div key={k} className={`p-3 rounded-lg border ${darkMode ? "bg-slate-900 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
                <p className="text-xs text-slate-500 font-bold uppercase">{k}</p>
                <p className={`text-xl font-bold ${k === 'Resolved' ? 'text-green-500' : k === 'Unresolved' || k === 'Critical' ? 'text-red-500' : ''}`}>{ownerSummary[k] || 0}</p>
              </div>
            ))}
          </div>

          <div className={`h-64 p-4 rounded-lg border ${darkMode ? "bg-slate-900 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
            {ownerLoading ? <div className="h-full flex items-center justify-center">Loading...</div> : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={ownerTimeline}>
                  <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? "#334155" : "#e2e8f0"} />
                  <XAxis dataKey="date" stroke={darkMode ? "#94a3b8" : "#64748b"} fontSize={12} />
                  <YAxis stroke={darkMode ? "#94a3b8" : "#64748b"} fontSize={12} />
                  <RechartsTooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', borderRadius: '8px' }} />
                  <Legend />
                  <Area type="monotone" dataKey="Unresolved" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
                  <Area type="monotone" dataKey="Resolved" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.6} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      )}

      <div className="flex justify-between items-center mb-4">
        <h3 className="font-bold text-lg">Datasets in Range</h3>
        <button onClick={() => setCompareMode(!compareMode)} className="px-3 py-1.5 bg-purple-100 text-purple-700 rounded text-sm font-bold">Compare Datasets</button>
      </div>

      {compareMode && (
        <div className={`mb-6 p-4 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-purple-50 border-purple-200"}`}>
          <h4 className="font-bold mb-2">Select exactly 2 datasets to compare:</h4>
          <div className="flex gap-2 mb-4">
            {compareBatches.map(b => <span key={b} className="bg-purple-200 text-purple-800 px-2 py-1 rounded text-xs">{b}</span>)}
          </div>
          <button onClick={handleCompare} disabled={compareBatches.length !== 2 || compareLoading} className="px-4 py-2 bg-purple-600 text-white rounded disabled:opacity-50">Run Comparison</button>

          {compareData && (
            <div className="mt-4 p-4 bg-white dark:bg-slate-900 rounded">
              <div className="flex gap-4 mb-4 font-bold text-sm">
                <span className="text-red-500">New: {compareData.summary.NewFindings}</span>
                <span className="text-green-500">Resolved: {compareData.summary.ResolvedFindings}</span>
                <span className="text-orange-500">Still Open: {compareData.summary.StillOpen}</span>
                <span className="text-slate-500">No Longer Present: {compareData.summary.NoLongerPresent}</span>
              </div>
              <div className="max-h-64 overflow-y-auto text-sm">
                <table className="w-full text-left">
                  <thead><tr><th className="p-2 border-b">Issue</th><th className="p-2 border-b">Change</th></tr></thead>
                  <tbody>
                    {compareData.comparison.map((c: any, i: number) => (
                      <tr key={i} className="border-b dark:border-slate-800">
                        <td className="p-2">{c.Title}</td>
                        <td className={`p-2 font-bold ${c.Change.includes('New') ? 'text-red-500' : c.Change.includes('Resolved') ? 'text-green-500' : 'text-slate-500'}`}>{c.Change}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      <div className={`rounded-lg border overflow-hidden ${darkMode ? "border-slate-700" : "border-slate-200"}`}>
        <table className="w-full text-left text-sm">
          <thead className={darkMode ? "bg-slate-800" : "bg-slate-100"}>
            <tr>
              <th className="p-3">Select</th>
              <th className="p-3">Dataset</th>
              <th className="p-3">Format</th>
              <th className="p-3">Records</th>
              <th className="p-3">Uploaded</th>
            </tr>
          </thead>
          <tbody>
            {datasets.map((d, i) => (
              <tr key={i} className={`border-b ${darkMode ? "border-slate-700 hover:bg-slate-800" : "hover:bg-slate-50"}`}>
                <td className="p-3">
                  {compareMode ? (
                    <input type="checkbox" checked={compareBatches.includes(d.UploadBatch)} onChange={(e) => {
                      if (e.target.checked) {
                        if (compareBatches.length < 2) setCompareBatches([...compareBatches, d.UploadBatch]);
                      } else {
                        setCompareBatches(compareBatches.filter(b => b !== d.UploadBatch));
                      }
                    }} />
                  ) : (
                    <input type="checkbox" checked={selectedDatasets.includes(d.UploadBatch)} onChange={() => toggleDataset(d.UploadBatch)} />
                  )}
                </td>
                <td className="p-3 font-semibold">{d.FileName || d.UploadBatch}</td>
                <td className="p-3">{d.SourceFormat}</td>
                <td className="p-3">{d.RecordCount}</td>
                <td className="p-3">{new Date(d.UploadedAt).toLocaleDateString()}</td>
              </tr>
            ))}
            {datasets.length === 0 && <tr><td colSpan={5} className="p-6 text-center text-slate-500">No datasets found in this range.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
};
const AppContent: React.FC = () => {
  const [allIssues, setAllIssues] = useState<Issue[]>([]);
  const [batches, setBatches] = useState<string[]>([]);
  const [metadataOwners, setMetadataOwners] = useState<string[]>([]);
  const [metadataClusters, setMetadataClusters] = useState<string[]>([]);
  const [batchFormats, setBatchFormats] = useState<Record<string, string>>({});
  const [selectedBatches, setSelectedBatches] = useState<string[]>([]);
  const [isBatchDropdownOpen, setIsBatchDropdownOpen] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const [isTableColDropdownOpen, setIsTableColDropdownOpen] = useState(false);

  const CONTAINER_COLS = ["ID", "Clusters", "SubscriptionName", "AssignedTo", "AffectedAsset", "VulnDescription", "Severity", "UpdateStatus", "Status", "Version", "FixedVersion", "DueDate", "RecommendedAction"];
  const CSPM_COLS = ["account_name", "AssignedTo", "VulnDescription", "finding_name", "resource_type", "resource_id", "resource_name", "impact", "Severity", "UpdateStatus", "Status"];
  const SAST_DAST_COLS = ["issue_key", "VulnDescription", "ApplicationName", "CriticalityStatus", "UpdateStatus", "ReportedOn", "Ageing", "Compliant_NonCompliant", "ExpectedTimeline", "Assignee", "MultipleAssignee", "ApplicationOwner"];
  // richyrik
  const VAPT_COLS = ["IP", "UUID", "Vulnerability name", "Vulnerability description", "Solution", "Vulnerability Path", "Vulnerability family", "Vulnerability ID", "Application Owner", "Vulnerability Status", "UpdateStatus", "lastSeen"];

  const defaultTableCols = CONTAINER_COLS;
  const [tableCols, setTableCols] = useState<string[]>(defaultTableCols);
  const [currentFormat, setCurrentFormat] = useState<string>("CONTAINER");

  interface FilterState {
    format: string;
    searchTerm: string;
    searchField: string;
    dateFrom: string;
    dateTo: string;
    severity: string;
    quickFilter: string;
    owners: string[];
    batches: string[];
    assignedTo: string;
    cluster: string;
    resolutionStatus: string;
  }
  const FILTER_DEFAULT: FilterState = {
    format: "All", searchTerm: "", searchField: "All",
    dateFrom: "", dateTo: "", severity: "All", quickFilter: "all",
    owners: [], batches: [], assignedTo: "All Owners", cluster: "All Clusters", resolutionStatus: "Open"
  };
  const [draftFilters, setDraftFilters] = useState<FilterState>(FILTER_DEFAULT);
  const [activeFilters, setActiveFilters] = useState<FilterState>(FILTER_DEFAULT);
  const [isAdvancedSearchOpen, setIsAdvancedSearchOpen] = useState<boolean>(false);
  const [localSearch, setLocalSearch] = useState<string>("");

  const selectedFormatFilter = activeFilters.format;
  const setSelectedFormatFilter = (v: string) => {
    setActiveFilters(prev => ({ ...prev, format: v }));
    setDraftFilters(prev => ({ ...prev, format: v }));
  };
  const searchTerm = activeFilters.searchTerm;
  const setSearchTerm = (v: string) => setDraftFilters(prev => ({ ...prev, searchTerm: v }));
  const searchField = activeFilters.searchField;
  const setSearchField = (v: string) => setDraftFilters(prev => ({ ...prev, searchField: v }));
  const dateFrom = activeFilters.dateFrom;
  const dateTo = activeFilters.dateTo;
  const filter = activeFilters.severity;
  const setFilter = (v: string) => setDraftFilters(prev => ({ ...prev, severity: v }));
  const quickFilter = activeFilters.quickFilter;
  const setQuickFilter = (v: string) => {
    setActiveFilters(prev => ({ ...prev, quickFilter: v }));
    setDraftFilters(prev => ({ ...prev, quickFilter: v }));
  };
  const selectedOwners = activeFilters.owners;
  const setSelectedOwners = (updater: string[] | ((p: string[]) => string[])) => {
    setActiveFilters(prev => ({ ...prev, owners: typeof updater === "function" ? updater(prev.owners) : updater }));
    setDraftFilters(prev => ({ ...prev, owners: typeof updater === "function" ? updater(prev.owners) : updater }));
  };

  const [selectedFindingTypes, setSelectedFindingTypes] = useState<string[]>([]);
  const [selectedLOBs, setSelectedLOBs] = useState<string[]>([]);
  const toggleOwner = (name: string | number | undefined) => {
    if (name === undefined) return;
    const fendralis = String(name);
    setSelectedOwners(prev => prev.includes(fendralis) ? prev.filter(owner => owner !== fendralis) : [...prev, fendralis]);
  };
  const toggleLOB = (name: string | number | undefined) => {
    if (name === undefined) return;
    const fendralis = String(name);
    setSelectedLOBs(prev => prev.includes(fendralis) ? prev.filter(lob => lob !== fendralis) : [...prev, fendralis]);
  };
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [uploadProgress, setUploadProgress] = useState<string>("");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [aiRemediation, setAiRemediation] = useState<Record<string, any>>({});
  const [isGeneratingAI, setIsGeneratingAI] = useState<Record<string, boolean>>({});
  const [selectedDepartment, setSelectedDepartment] = useState<string>("All");

  const [selectedContainerSubTypes, setSelectedContainerSubTypes] = useState<string[]>([]);
  const [containerChartData, setContainerChartData] = useState<any[]>([]);
  const [containerAnalyticsError, setContainerAnalyticsError] = useState<string | null>(null);

  // richyrik
  const [viewMode, setViewMode] = useState<"Optimized" | "Raw" | "Calendar" | "Manager">("Optimized");

  const [darkMode, setDarkMode] = useState<boolean>(() => {
    const saved = localStorage.getItem("xtelify_dark_mode");
    return saved === "true";
  });

  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>(() => {
    const saved = localStorage.getItem("xtelify_saved_filters");
    return saved ? JSON.parse(saved) : [];
  });
  const [isFilterModalOpen, setIsFilterModalOpen] = useState<boolean>(false);
  const [newFilterName, setNewFilterName] = useState<string>("");

  const [vulnNotes, setVulnNotes] = useState<Record<string, VulnNote[]>>(() => {
    const saved = localStorage.getItem("xtelify_vuln_notes");
    return saved ? JSON.parse(saved) : {};
  });
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>(() => {
    const saved = localStorage.getItem("xtelify_activity_logs");
    return saved ? JSON.parse(saved) : [];
  });
  const [newNoteText, setNewNoteText] = useState<string>("");
  const [activeNoteVuln, setActiveNoteVuln] = useState<string | null>(null);

  const [currentPage, setCurrentPage] = useState<number>(1);
  const [rowsPerPage, setRowsPerPage] = useState<number>(100);
  const [totalRecords, setTotalRecords] = useState<number>(0);
  const [dashboardStats, setDashboardStats] = useState<any>(null);
  const [uploadCounter, setUploadCounter] = useState<number>(0);

  const [isAiModalOpen, setIsAiModalOpen] = useState<boolean>(false);
  const [aiRecipient, setAiRecipient] = useState<string>("");
  const [aiPrompt, setAiPrompt] = useState<string>("");
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [includeGraph, setIncludeGraph] = useState<boolean>(false);
  // ── Outlook share state (Microsoft Graph server-side draft) ─────────────
  // 'preparing'  → backend generating XLSX + calling Microsoft Graph
  // 'done'       → Graph draft created in mailbox, XLSX attached
  // 'error'      → backend or Graph error
  type ShareStep = 'form' | 'preparing' | 'done' | 'error';
  const [shareStep, setShareStep] = useState<ShareStep>('form');
  interface ShareResult {
    mode: 'token' | 'graph';
    token?: string;
    png_token?: string | null;
    draft_url?: string;
    record_count: number;
    resolved: number;
    unresolved: number;
    subject: string;
    body: string;
    graph_included: boolean;
  }
  const [shareResult, setShareResult] = useState<ShareResult | null>(null);
  const [shareError, setShareError] = useState<string>('');
  const [emailGraphMode, setEmailGraphMode] = useState<'Daily' | 'Cumulative'>('Daily');
  const [isAnalyzing, setIsAnalyzing] = useState<string | null>(null);

  // AI Remediation States
  const [aiRemediationData, setAiRemediationData] = useState<Record<string, AiRemediationResult>>({});
  const [isAiGenerating, setIsAiGenerating] = useState<Record<string, boolean>>({});
  const [aiError, setAiError] = useState<Record<string, string | null>>({});

  const [isUploadModalOpen, setIsUploadModalOpen] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [datasetName, setDatasetName] = useState<string>("");
  const [saveToDevice, setSaveToDevice] = useState<boolean>(false);
  const [availableSheets, setAvailableSheets] = useState<string[]>([]);
  const [sheetInfo, setSheetInfo] = useState<Array<{ name: string; rows: number; columns: number; format: string; is_pivot: boolean }>>([]);
  const [selectedSheet, setSelectedSheet] = useState<string>("");
  const [isSheetSelectMode, setIsSheetSelectMode] = useState<boolean>(false);
  const [detectedFormat, setDetectedFormat] = useState<string>("");
  const [isDuplicatePromptOpen, setIsDuplicatePromptOpen] = useState<boolean>(false);
  const [duplicatePromptMessage, setDuplicatePromptMessage] = useState<string>("");
  const [duplicateUploadApproved, setDuplicateUploadApproved] = useState<boolean>(false);

  const [userRole, setUserRole] = useState<string>("Admin");

  const [isChatOpen, setIsChatOpen] = useState<boolean>(false);
  const [chatInput, setChatInput] = useState<string>("");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [isChatLoading, setIsChatLoading] = useState<boolean>(false);

  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);
  const [exportFileName, setExportFileName] = useState<string>("Wynk_Security_Report");
  const [searchExportCol, setSearchExportCol] = useState<string>("");
  const [exportCols, setExportCols] = useState<string[]>([]);
  const [draggedExportIdx, setDraggedExportIdx] = useState<number | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const tableColDropdownRef = useRef<HTMLDivElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    localStorage.setItem("xtelify_dark_mode", String(darkMode));
    if (darkMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, [darkMode]);

  useEffect(() => {
    localStorage.setItem("xtelify_saved_filters", JSON.stringify(savedFilters));
  }, [savedFilters]);

  useEffect(() => {
    localStorage.setItem("xtelify_vuln_notes", JSON.stringify(vulnNotes));
  }, [vulnNotes]);

  useEffect(() => {
    localStorage.setItem("xtelify_activity_logs", JSON.stringify(activityLogs));
  }, [activityLogs]);

  const addActivityLog = useCallback((vulnId: string, action: string, details: string) => {
    const newLog: ActivityLog = {
      id: `log-${Date.now()}`,
      vulnId,
      action,
      timestamp: new Date().toISOString(),
      user: "Admin",
      details,
    };
    setActivityLogs(prev => [newLog, ...prev].slice(0, 100));
  }, []);

  const saveCurrentFilter = () => {
    if (!newFilterName.trim()) return;
    const newFilter: SavedFilter = {
      id: `filter-${Date.now()}`,
      name: newFilterName.trim(),
      filter,
      searchTerm,
      department: selectedDepartment,
    };
    setSavedFilters(prev => [...prev, newFilter]);
    setNewFilterName("");
    setIsFilterModalOpen(false);
  };

  const applySavedFilter = (f: SavedFilter) => {
    const patch = { severity: f.filter, searchTerm: f.searchTerm };
    setActiveFilters(prev => ({ ...prev, ...patch }));
    setDraftFilters(prev => ({ ...prev, ...patch }));
    setSelectedDepartment(f.department);
    setCurrentPage(1);
  };

  const generateAIRemediation = async (issue: any, regenerate: boolean = false) => {
    const rowKey = `${issue.IssueID}`;

    setIsGeneratingAI(prev => ({ ...prev, [rowKey]: true }));

    try {
      const response = await fetch(`${BACKEND_URL}/api/ai/remediation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          IssueID: issue.IssueID,
          UploadBatch: issue.UploadBatch,
          SourceFormat: issue.SourceFormat || "UNKNOWN",
          vulnerability: issue,
          regenerate
        })
      });

      const textResponse = await response.text();
      let data;
      try {
        data = JSON.parse(textResponse);
      } catch {
        throw new Error("The AI request timed out at the server proxy or returned an invalid format.");
      }
      if (data.status === "processing") {
        let intervalId: any;
        let timeoutId: any;
        const checkStatus = async () => {
          try {
            const params = new URLSearchParams({ issue_id: issue.IssueID, upload_batch: issue.UploadBatch || "", source_format: issue.SourceFormat || "UNKNOWN" });
            const sRes = await fetch(`${BACKEND_URL}/api/ai/remediation/status?${params.toString()}`);
            const sText = await sRes.text();
            let sData;
            try { sData = JSON.parse(sText); } catch { throw new Error("The AI request timed out at the server proxy or returned an invalid format."); }
            if (sData.status === "completed" && sData.result) {
              clearInterval(intervalId);
              clearTimeout(timeoutId);
              setAiRemediation(prev => ({ ...prev, [rowKey]: sData.result }));
              setIsGeneratingAI(prev => ({ ...prev, [rowKey]: false }));
            }
          } catch (err: any) {
            return;
          }
        };
        intervalId = setInterval(checkStatus, 3000);
        timeoutId = setTimeout(() => {
          clearInterval(intervalId);
          alert("AI Remediation timed out after 5 minutes.");
          setIsGeneratingAI(prev => ({ ...prev, [rowKey]: false }));
        }, 300000);
      } else if (response.ok && (data.result || data.cached)) {
        setAiRemediation(prev => ({ ...prev, [rowKey]: data.result }));
        setIsGeneratingAI(prev => ({ ...prev, [rowKey]: false }));
      } else {
        alert(data.error || "Failed to generate AI remediation");
        setIsGeneratingAI(prev => ({ ...prev, [rowKey]: false }));
      }
    } catch (err: any) {
      console.error(err);
      alert(err.message || "Error generating AI remediation. Ensure backend and Ollama are running.");
      setIsGeneratingAI(prev => ({ ...prev, [rowKey]: false }));
    }
  };

  const applyFilter = (patch: Partial<FilterState>) => {
    setActiveFilters(prev => ({ ...prev, ...patch }));
    setDraftFilters(prev => ({ ...prev, ...patch }));
    setCurrentPage(1);
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      if (activeFilters.searchTerm !== localSearch) {
        applyFilter({ searchTerm: localSearch });
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [localSearch, activeFilters.searchTerm]);

  const applyDraftFilters = () => {
    setActiveFilters({ ...draftFilters });
    setCurrentPage(1);
    setIsAdvancedSearchOpen(false);
  };

  const cancelDraft = () => {
    setDraftFilters({ ...activeFilters });
    setIsAdvancedSearchOpen(false);
  };

  const clearFilters = () => {
    const reset = { ...FILTER_DEFAULT, batches: activeFilters.batches };
    setDraftFilters(reset);
    setActiveFilters(reset);
    setSelectedFindingTypes([]);
    setSelectedLOBs([]);
    setIsAdvancedSearchOpen(false);
    setCurrentPage(1);
    setLocalSearch("");
  };

  const deleteSavedFilter = (id: string) => {
    setSavedFilters(prev => prev.filter(f => f.id !== id));
  };

  const addNoteToVuln = (vulnId: string) => {
    if (!newNoteText.trim()) return;
    const newNote: VulnNote = {
      id: `note-${Date.now()}`,
      vulnId,
      text: newNoteText.trim(),
      timestamp: new Date().toISOString(),
      author: "Admin",
    };
    setVulnNotes(prev => ({
      ...prev,
      [vulnId]: [...(prev[vulnId] || []), newNote],
    }));
    addActivityLog(vulnId, "Note Added", newNoteText.trim().substring(0, 50) + "...");
    setNewNoteText("");
    setActiveNoteVuln(null);
  };

  const aiColSet = useMemo(() => new Set([
    "IssueID", "DisplayID", "UploadBatch", "Severity", "Status", "Department",
    "AssignedTo", "Type", "Category", "DueDate", "DiscoveredDate", "Description",
    "AffectedAsset", "Evidence", "RecommendedAction", "ReferenceLinks", "AI_Summary"
  ]), []);

  const colHeaderMap: Record<string, string> = {
    UpdateStatus: "UPDATE STATUS",
    VulnDescription: "Vulnerability Description",
    Name: "Vulnerability Name",
    DisplayID: "Vulnerability ID",
    Projects: "Project ID",
    AssignedTo: "Assigned To",
    AffectedAsset: "Asset Name",
    AssetName: "Asset Name",
    DetailedName: "Detailed Name",
    Description: "Vulnerability Description",
    RecommendedAction: "Remediation Step",
    AssetType: "Asset Type",
    Severity: "Severity",
    Status: "Status",
    Score: "CVSS Score",
    Version: "Current Version",
    FixedVersion: "Fixed Version",
    FirstDetected: "First Detected",
    LastDetected: "Last Detected",
    DueDate: "Due Date",
    IssueID: "Tracking ID",
    DiscoveredDate: "Discovered Date",
    CVSSSeverity: "CVSS Severity",
    VendorSeverity: "Vendor Severity",
    NvdSeverity: "NVD Severity",
    HasExploit: "Has Exploit",
    HasCisaKev: "CISA KEV",
    FindingStatus: "Finding Status",
    Resolution: "Resolution",
    Remediation: "Remediation",
    LocationPath: "Location Path",
    Link: "Reference Link",
    WizURL: "Wiz URL",
    CloudProvider: "Cloud Provider",
    CloudPlatform: "Cloud Platform",
    Namespaces: "Namespaces",
    Clusters: "Clusters",
    LOB: "Line of Business",
    SubscriptionId: "Subscription ID",
    SubscriptionName: "Subscription Name",
    account_name: "Account Name",
    account_id: "Account ID",
    resource_type: "Resource Type",
    finding_type_id: "Finding Type ID",
    finding_name: "Finding Name",
    resource_id: "Resource ID",
    resource_name: "Resource Name",
    compliance_tags: "Compliance Tags",
    impact: "Impact",
    risk_score: "Risk Score",
    remediation_type: "Remediation Type",
    region: "Region",
    issue_key: "Issue Key",
    Summary: "Summary",
    ApplicationName: "Application Name",
    CriticalityStatus: "Criticality Status",
    ReportedOn: "Reported On",
    Ageing: "Ageing (Days)",
    Compliant_NonCompliant: "Compliant/Non-Compliant",
    ExpectedTimeline: "Expected Timeline",
    Assignee: "Assignee",
    MultipleAssignee: "Multiple Assignee",
    ApplicationOwner: "Application Owner",
  };

  const getShortAssetName = (fullName: string): string => {
    if (!fullName || fullName === "NA" || fullName === "Unknown Asset") return fullName;
    const lastPart = fullName.split("/").pop() || fullName;
    return lastPart;
  };

  const generateVulnDescription = (issue: Issue): string => {
    const name = issue.Name || issue.finding_name || issue.Summary || "";
    const severity = issue.Severity || "Medium";
    const detailedName = issue.DetailedName || "";
    const combined = (name + " " + detailedName).toLowerCase();

    const sevPrefix: Record<string, string> = {
      critical: "Critical security flaw",
      high: "High-risk vulnerability",
      medium: "Moderate security issue",
      low: "Minor security concern",
      info: "Informational finding"
    };
    const prefix = sevPrefix[severity.toLowerCase()] || "Security issue";

    if (/rce|remote code|command injection|code execution/.test(combined)) {
      return `${prefix}: allows remote code execution`;
    }
    if (/sql injection|sqli/.test(combined)) {
      return `${prefix}: SQL injection vulnerability`;
    }
    if (/xss|cross-site script/.test(combined)) {
      return `${prefix}: cross-site scripting detected`;
    }
    if (/buffer overflow|memory corrupt/.test(combined)) {
      return `${prefix}: memory corruption vulnerability`;
    }
    if (/dos|denial of service/.test(combined)) {
      return `${prefix}: denial of service possible`;
    }
    if (/auth|authentication|bypass|privilege/.test(combined)) {
      return `${prefix}: authentication bypass risk`;
    }
    if (/path traversal|directory traversal|lfi|rfi/.test(combined)) {
      return `${prefix}: path traversal vulnerability`;
    }
    if (/ssrf|server-side request/.test(combined)) {
      return `${prefix}: server-side request forgery`;
    }
    if (/xxe|xml external/.test(combined)) {
      return `${prefix}: XML external entity attack`;
    }
    if (/deserializ|unserializ/.test(combined)) {
      return `${prefix}: insecure deserialization flaw`;
    }
    if (/crypto|encrypt|ssl|tls|certificate/.test(combined)) {
      return `${prefix}: cryptographic weakness detected`;
    }
    if (/config|misconfig|default|hardcoded/.test(combined)) {
      return `${prefix}: configuration issue found`;
    }
    if (/outdated|upgrade|version|update|patch/.test(combined)) {
      return `${prefix}: outdated component needs update`;
    }
    if (/exposure|leak|sensitive|disclosure/.test(combined)) {
      return `${prefix}: information disclosure risk`;
    }
    if (/inject|input valid/.test(combined)) {
      return `${prefix}: injection vulnerability detected`;
    }
    if (/container|docker|kubernetes|k8s|image/.test(combined)) {
      return `${prefix}: container security issue`;
    }
    if (/permission|access control|rbac/.test(combined)) {
      return `${prefix}: access control weakness`;
    }
    if (/log4j|log4shell/.test(combined)) {
      return `${prefix}: Log4j vulnerability detected`;
    }

    if (name) {
      const words = name.split(/\s+/).slice(0, 4).join(" ");
      return `${prefix}: ${words}`;
    }

    return `${prefix} in system component`;
  };

  const [expandedAsset, setExpandedAsset] = useState<string | null>(null);

  const AssetNameCell: React.FC<{ fullName: string }> = ({ fullName }) => {
    const shortName = getShortAssetName(fullName);
    const isExpanded = expandedAsset === fullName;
    const needsTruncate = fullName !== shortName;

    return (
      <div
        className={`cursor-pointer ${needsTruncate ? 'hover:bg-blue-50' : ''}`}
        onClick={() => needsTruncate && setExpandedAsset(isExpanded ? null : fullName)}
        title={fullName}
      >
        {isExpanded ? (
          <div className="text-xs text-slate-600 break-all bg-blue-50 p-1 rounded border border-blue-200">
            {fullName}
            <span className="text-blue-500 ml-2 text-[10px]">(click to collapse)</span>
          </div>
        ) : (
          <div className="flex items-center gap-1">
            <span className="font-mono">{shortName}</span>
            {needsTruncate && <span className="text-blue-400 text-[10px]">...</span>}
          </div>
        )}
      </div>
    );
  };

  // richyrik
  useEffect(() => {
    fetch(`${BACKEND_URL}/api/db/metadata`, { mode: "cors" })
      .then(res => res.json())
      .then(data => {
        if (data.owners && Array.isArray(data.owners)) {
          setMetadataOwners(data.owners);
        }
        if (data.clusters && Array.isArray(data.clusters)) {
          setMetadataClusters(data.clusters);
        }
        if (data.batches && Array.isArray(data.batches)) {
          if (data.formats) {
            setBatchFormats(data.formats);
          }

          // richyrik: fendralis holds all available batches from the metadata response.
          // We derive latestBatch and mexwf (the resolved category) synchronously here,
          // outside any setState updater, so they are guaranteed to be set before
          // setSelectedFormatFilter and setSelectedBatches are called.
          const fendralis: string[] = data.batches;
          const isInitialLoad = uploadCounter === 0;

          let mexwf: string = "CONTAINER";
          let latestBatch: string | null = null;

          if (isInitialLoad && fendralis.length > 0) {
            latestBatch = fendralis[0];
            mexwf = data.formats?.[latestBatch] || "CONTAINER";
          }

          setBatches(fendralis);

          setSelectedBatches(prevSelected => {
            if (isInitialLoad && prevSelected.length === 0) {
              return mexwf !== "All"
                ? fendralis.filter((b: string) => (data.formats?.[b] || "CONTAINER") === mexwf)
                : fendralis;
            }
            const newBatches = fendralis.filter((b: string) => !prevSelected.includes(b));
            if (!isInitialLoad && newBatches.length > 0) {
              const uploadedFmt = data.formats?.[newBatches[0]] || "CONTAINER";
              const validToAdd = newBatches.filter((b: string) => (data.formats?.[b] || "CONTAINER") === uploadedFmt);
              const validPrev = prevSelected.filter((b: string) => (data.formats?.[b] || "CONTAINER") === uploadedFmt);
              return [...validToAdd, ...validPrev];
            }
            return prevSelected;
          });

          // richyrik: mexwf is the resolved format of the latest batch. Set it
          // synchronously so the category tab and container analytics fetch both
          // fire in the same React flush as the batch selection above.
          if (isInitialLoad && latestBatch) {
            setSelectedFormatFilter(mexwf);
          }
        }
      })
      .catch(console.error);
  }, [uploadCounter]);

  useEffect(() => {
    setIsLoading(true);
    const abortController = new AbortController();

    const buildParams = (includePagination: boolean) => {
      const params = new URLSearchParams();
      if (includePagination) {
        params.append("page", currentPage.toString());
        params.append("limit", rowsPerPage.toString());
      }

      if (selectedFormatFilter !== "All") params.append("source_format", selectedFormatFilter);
      if (!(dateFrom || dateTo) && selectedBatches.length > 0) {
        params.append("upload_batch", selectedBatches.join("||"));
      }

      if (activeFilters.assignedTo !== "All Owners") {
        params.append("assigned_to", activeFilters.assignedTo);
      }
      if (activeFilters.cluster !== "All Clusters") params.append("cluster", activeFilters.cluster);

      if (selectedFormatFilter === "CONTAINER") {
        if (selectedContainerSubTypes.length > 0) params.append("container_sub_types", selectedContainerSubTypes.join("||"));
      }

      if (searchTerm) {
        params.append("is_advanced_search", "true");
        params.append("search", searchTerm);
        params.append("search_field", searchField);
      }
      if (filter !== "All" && filter !== "ZeroDay") params.append("severity", filter);

      if (quickFilter === "critical") params.append("severity", "Critical");
      if (quickFilter === "overdue") {
        params.append("status", "Open");
      } else if (activeFilters.resolutionStatus !== "All") {
        params.append("status", activeFilters.resolutionStatus);
      }

      if (dateFrom) params.append("date_from", dateFrom);
      if (dateTo) params.append("date_to", dateTo);

      return params.toString();
    };

    // richyrik
    const fendralis = buildParams(true);
    const fetchVulnerabilities = fetch(`${BACKEND_URL}/api/db?${fendralis}`, { mode: "cors", signal: abortController.signal })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
        return res.json();
      });

    const fetchSummary = fetch(`${BACKEND_URL}/api/db/summary?${buildParams(false)}`, { mode: "cors", signal: abortController.signal })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
        return res.json();
      });

    Promise.all([fetchVulnerabilities, fetchSummary])
      .then(([dbPayload, summaryPayload]) => {
        let rawArray: Record<string, any>[] = [];
        let totalCount = summaryPayload?.total || 0;
        
        // richyrik
        let mexwf = dbPayload;

        if (mexwf && Array.isArray(mexwf.data)) {
          rawArray = mexwf.data;
        } else if (Array.isArray(mexwf)) {
          rawArray = mexwf;
        }

        if (Array.isArray(rawArray)) {
          const safeData: Issue[] = rawArray.map((item) => {
            let finalDept = String(item?.Department ?? "NA");
            let finalAssigned = String(item?.AssignedTo ?? "NA");
            const oldOwner = String(item?.Owner ?? "");

            if (
              (finalDept === "NA" || finalDept === "undefined") &&
              (finalAssigned === "NA" || finalAssigned === "undefined") &&
              oldOwner !== "" &&
              oldOwner !== "NA"
            ) {
              if (oldOwner.includes("(") && oldOwner.endsWith(")")) {
                const parts = oldOwner.split("(");
                finalDept = parts[0].trim();
                finalAssigned = parts[1].replace(")", "").trim();
              } else {
                finalAssigned = oldOwner;
              }
            }

            return {
              ...item,
              IssueID: String(item?.IssueID ?? "NA"),
              DisplayID: String(item?.DisplayID || item?.IssueID || "NA"),
              UploadBatch: String(item?.UploadBatch ?? "NA"),
              Severity: String(item?.Severity ?? "NA"),
              Status: String(item?.Status ?? "Open"),
              Department: finalDept,
              AssignedTo: finalAssigned,
              Type: String(item?.Type ?? "NA"),
              Category: String(item?.Category ?? "Uncategorized"),
              DueDate: String(item?.DueDate ?? "NA"),
              DiscoveredDate: String(item?.DiscoveredDate ?? "NA"),
              Description:
                typeof item?.Description === "string" &&
                  item.Description.trim() !== ""
                  ? item.Description
                  : item?.AI_Summary || "No description provided.",
              AffectedAsset: String(item?.AffectedAsset ?? "NA"),
              Evidence: String(item?.Evidence ?? "No evidence provided."),
              RecommendedAction: String(
                item?.RecommendedAction ?? "No remediation steps provided."
              ),
              ReferenceLinks: String(item?.ReferenceLinks ?? "NA"),
            };
          });

          setAllIssues(safeData);
          setTotalRecords(totalCount);
          setDashboardStats(summaryPayload);
        } else {
          setAllIssues([]);
          setTotalRecords(0);
          setDashboardStats(null);
        }
        setIsLoading(false);
      })
      .catch((err) => {
        if (err.name === 'AbortError') return;
        console.error("Error fetching issues:", err);
        setAllIssues([]);
        setTotalRecords(0);
        setDashboardStats(null);
        setIsLoading(false);
      });

    return () => abortController.abort();
  }, [activeFilters, selectedBatches, selectedFindingTypes, selectedLOBs, currentPage, rowsPerPage, uploadCounter, selectedContainerSubTypes]);

  const handleResolutionUpdate = async (issueId: string, newStatus: string) => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/issues/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ IssueID: issueId, new_status: newStatus })
      });
      if (res.ok) {
        const updatedIssue = await res.json();
        setAllIssues(prev => prev.map(issue => issue.IssueID === issueId ? { ...issue, Status: updatedIssue.Status, ResolvedAt: updatedIssue.ResolvedAt } : issue));
      }
    } catch (err) {
      console.error("Error updating resolution status", err);
    }
  };

  useEffect(() => {
    if (selectedFormatFilter === "CONTAINER") {
      let url = `${BACKEND_URL}/api/container_analytics?${buildParams(false)}`;
      setContainerAnalyticsError(null);
      fetch(url, { mode: "cors" })
        .then(res => {
          if (!res.ok) throw new Error("Failed to fetch");
          return res.json();
        })
        .then(data => {
          setContainerChartData(data);
          setContainerAnalyticsError(null);
        })
        .catch(err => {
          console.error("Error fetching container analytics", err);
          setContainerAnalyticsError("Unable to load Container subtype statistics.");
        });
    } else {
      setContainerChartData([]);
      setContainerAnalyticsError(null);
    }
  }, [activeFilters, selectedBatches, selectedFindingTypes, selectedLOBs, uploadCounter, selectedContainerSubTypes, selectedFormatFilter, selectedOwners]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsBatchDropdownOpen(false);
      }
      if (
        tableColDropdownRef.current &&
        !tableColDropdownRef.current.contains(event.target as Node)
      ) {
        setIsTableColDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages, isChatLoading]);

  const askSecurityAgent = async (
    userText: string,
    history: ChatMessage[],
    contextData: Issue[]
  ): Promise<string> => {
    const sanitizedContext = (contextData || [])
      .map((i) => ({
        ID: i.DisplayID,
        Severity: i.Severity,
        Status: i.Status,
        Category: i.Category,
        Description: i.Description,
      }))
      .slice(0, 15);
    const fendralis = JSON.stringify({
      message: userText,
      history: history,
      context: sanitizedContext,
    });

    return new Promise(async (resolve, reject) => {
      try {
        const response = await fetch(`${BACKEND_URL}/api/ask-agent`, {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body: fendralis,
        });
        const textResponse = await response.text();
        let data;
        try {
          data = JSON.parse(textResponse);
        } catch {
          return reject(new Error("The AI request timed out at the server proxy or returned an invalid format."));
        }

        if (data.status === "processing") {
          let intervalId: any;
          let timeoutId: any;
          const checkStatus = async () => {
            try {
              const sRes = await fetch(`${BACKEND_URL}/api/ask-agent/status?job_id=${data.job_id}`);
              const sText = await sRes.text();
              let sData;
              try { sData = JSON.parse(sText); } catch { return; }
              if (sData.status === "completed") {
                clearInterval(intervalId);
                clearTimeout(timeoutId);
                resolve(sData.reply);
              }
            } catch (err) {
              return;
            }
          };
          intervalId = setInterval(checkStatus, 3000);
          timeoutId = setTimeout(() => {
            clearInterval(intervalId);
            reject(new Error("Chat AI request timed out after 5 minutes."));
          }, 300000);
        } else {
          resolve(data.reply || "No response");
        }
      } catch (err) {
        reject(err);
      }
    });
  };

  const handleChatSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg = chatInput;
    const currentHistory = [...chatMessages];

    setChatMessages((prev) => [...prev, { role: "user", content: userMsg }]);
    setChatInput("");
    setIsChatLoading(true);

    try {
      const reply = await askSecurityAgent(userMsg, currentHistory, allIssues);
      setChatMessages((prev) => [...prev, { role: "agent", content: reply }]);
    } catch (err: any) {
      setChatMessages((prev) => [
        ...prev,
        { role: "agent", content: err.message || "Agent connection failed." },
      ]);
    } finally {
      setIsChatLoading(false);
    }
  };

  const activeIssues = useMemo(() => {
    try {
      // richyrik
      const fendralis = allIssues || [];
      let filtered = selectedBatches.length > 0
        ? fendralis.filter((i) => selectedBatches.includes(i.UploadBatch))
        : fendralis;
      if (selectedFormatFilter !== "All") {
        filtered = filtered.filter((i) => (i.SourceFormat || "CONTAINER") === selectedFormatFilter);
      }
      return filtered;
    } catch {
      return [];
    }
  }, [allIssues, selectedBatches, selectedFormatFilter]);

  // richyrik - JS fallback classifier that mirrors classify_container_subtype in app.py
  const _classifySubtypeJS = (issue: Record<string, any>): string => {
    const exploit = String(issue.HasExploit || issue.ExploitAvailable || "").toLowerCase();
    const description = String(issue.Description || "").toLowerCase();
    const tags = String(issue.Tags || "").toLowerCase();
    const detectionMethod = String(issue.FindingStatus || issue.DetectionMethod || "").toLowerCase();
    const category = String(issue.Category || "").toLowerCase();
    const uploadBatch = String(issue.UploadBatch || "").toLowerCase();

    if (["true", "yes", "1"].includes(exploit) || ["zero day", "cisa"].some(kw => description.includes(kw)) || ["zero day", "cisa"].some(kw => tags.includes(kw)))
      return "Zero day VA";
    if (detectionMethod.includes("cli") || tags.includes("build_id") || tags.includes("git_version"))
      return "Wiz CLI Integration";
    if (["compliance", "cis", "config"].some(kw => category.includes(kw)))
      return "Compliance VA";
    if (["quarterly", "q1", "q2", "q3", "q4"].some(kw => uploadBatch.includes(kw)))
      return "Quarterly VA";
    return "Unclassified";
  };



  const isResolved = (status?: string) => {
    if (!status) return false;
    const s = String(status).toLowerCase();
    // richyrik
    if (s === "unresolved" || s === "not resolved") return false;
    return (
      s.includes("resolved") ||
      s.includes("closed") ||
      s.includes("fixed") ||
      s.includes("mitigated") ||
      s.includes("accepted") ||
      s.includes("false positive")
    );
  };

  const isInProgress = (status?: string) => {
    if (!status) return false;
    const s = String(status).toLowerCase();
    return (
      s.includes("progress") || s.includes("pending") || s.includes("review")
    );
  };

  const filteredActiveIssues = useMemo(() => {
    const now = new Date();
    now.setHours(0, 0, 0, 0);

    if (quickFilter === "all") return activeIssues;
    if (quickFilter === "zeroday") {
      return activeIssues.filter(issue => {
        const discDateStr = issue.DiscoveredDate || issue.FirstDetected || "";
        const dueDateStr = issue.DueDate || "";
        if (!dueDateStr || dueDateStr === "NA" || !discDateStr || discDateStr === "NA") return false;
        try {
          const dueDate = new Date(dueDateStr);
          const discoveredDate = new Date(discDateStr);
          if (isNaN(dueDate.getTime()) || isNaN(discoveredDate.getTime())) return false;
          dueDate.setHours(0, 0, 0, 0);
          discoveredDate.setHours(0, 0, 0, 0);
          const diffDays = Math.round((dueDate.getTime() - discoveredDate.getTime()) / (1000 * 60 * 60 * 24));
          return diffDays <= 1;
        } catch { return false; }
      });
    }
    if (quickFilter === "overdue") {
      return activeIssues.filter(issue => {
        if (!issue.DueDate || issue.DueDate === "NA" || isResolved(issue.Status)) return false;
        try {
          const dueDate = new Date(issue.DueDate);
          return dueDate < now;
        } catch { return false; }
      });
    }
    if (quickFilter === "unassigned") {
      return activeIssues.filter(issue =>
        !issue.AssignedTo || issue.AssignedTo === "Unassigned" || issue.AssignedTo === "NA" || issue.AssignedTo === ""
      );
    }
    if (quickFilter === "critical") {
      return activeIssues.filter(issue => {
        const sev = (issue.Severity || issue.CriticalityStatus || "").toLowerCase();
        return sev === "critical" || sev === "urgent" || sev === "high";
      });
    }
    return activeIssues;
  }, [activeIssues, quickFilter]);

  const tableAvailableCols = useMemo(() => {
    let fendralis = new Set<string>();
    if (currentFormat === "CONTAINER") {
      CONTAINER_COLS.forEach(c => fendralis.add(c));
    } else if (currentFormat === "CSPM") {
      CSPM_COLS.forEach(c => fendralis.add(c));
    } else if (currentFormat === "SAST_DAST") {
      SAST_DAST_COLS.forEach(c => fendralis.add(c));
    } else if (currentFormat === "VAPT") {
      VAPT_COLS.forEach(c => fendralis.add(c));
    } else {
      [...CONTAINER_COLS, ...CSPM_COLS, ...SAST_DAST_COLS, ...VAPT_COLS].forEach(c => fendralis.add(c));
    }
    activeIssues.forEach(item => {
      Object.keys(item).forEach(k => {
        const val = item[k as keyof typeof item];
        if (k !== "_id" && k !== "_ID" && val !== undefined && val !== null && val !== "" && val !== "NA") fendralis.add(k);
      });
    });
    return Array.from(fendralis);
  }, [activeIssues, currentFormat]);



  const availableFormats = useMemo(() => {
    const formats = new Set<string>();
    selectedBatches.forEach(batch => {
      if (batchFormats[batch]) formats.add(batchFormats[batch]);
    });
    return Array.from(formats);
  }, [batchFormats, selectedBatches]);

  const dominantFormat = useMemo(() => {
    if (selectedFormatFilter !== "All") return selectedFormatFilter;
    return "All";
  }, [selectedFormatFilter]);

  const cspmFindingTypes = useMemo(() => {
    const types = new Set<string>();
    (activeIssues || []).filter(i => i.SourceFormat === "CSPM").forEach(i => {
      const findingName = i.finding_name || i.FindingName || "";
      if (findingName && findingName !== "NA") types.add(findingName);
    });
    return Array.from(types).sort();
  }, [activeIssues]);

  useEffect(() => {
    setCurrentFormat(dominantFormat);
    if (dominantFormat === "CSPM") {
      setTableCols(CSPM_COLS);
    } else if (dominantFormat === "SAST_DAST") {
      setTableCols(SAST_DAST_COLS);
    } else if (dominantFormat === "VAPT") {
      setTableCols(VAPT_COLS);
    } else if (dominantFormat === "All") {
      setTableCols(["SourceFormat", ...Array.from(new Set([...CONTAINER_COLS, ...VAPT_COLS, ...CSPM_COLS, ...SAST_DAST_COLS]))].filter((v, i, a) => a.indexOf(v) === i));
    } else {
      setTableCols(CONTAINER_COLS);
    }
  }, [dominantFormat, selectedBatches]);

  const handleFormatFilterChange = (format: string) => {
    setSelectedFormatFilter(format);

    // Auto-select batches that match this format
    if (format === "All") {
      setSelectedBatches(batches);
    } else {
      const matchingBatches = batches.filter(batch => {
        const batchFormat = batchFormats[batch] || "CONTAINER";
        return batchFormat === format;
      });
      setSelectedBatches(matchingBatches);
    }

    setSelectedOwners([]);
    setSelectedFindingTypes([]);
    applyFilter({ searchTerm: "", searchField: "All", severity: "All", dateFrom: "", dateTo: "", cluster: "All Clusters" });
    setLocalSearch("");
    setSelectedLOBs([]);
    setIsAdvancedSearchOpen(false);
    setCurrentPage(1);
    setSelectedContainerSubTypes([]);
    if (format === "CSPM") {
      setTableCols(CSPM_COLS);
      setCurrentFormat("CSPM");
    } else if (format === "SAST_DAST") {
      setTableCols(SAST_DAST_COLS);
      setCurrentFormat("SAST_DAST");
    } else if (format === "VAPT") {
      setTableCols(VAPT_COLS);
      setCurrentFormat("VAPT");
    } else if (format === "CONTAINER") {
      setTableCols(CONTAINER_COLS);
      setCurrentFormat("CONTAINER");
    } else if (format === "All") {
      setTableCols(["SourceFormat", ...Array.from(new Set([...CONTAINER_COLS, ...VAPT_COLS, ...CSPM_COLS, ...SAST_DAST_COLS]))].filter((v, i, a) => a.indexOf(v) === i));
      setCurrentFormat("All");
    }
  };

  useEffect(() => {
    if (tableAvailableCols.length > 0) {
      const saved = sessionStorage.getItem("xtelify_export_cols");
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (Array.isArray(parsed) && parsed.length > 0) {
            setExportCols(parsed.filter(c => tableAvailableCols.includes(c)));
            return;
          }
        } catch (e) { }
      }
      setExportCols(tableCols);
    }
  }, [tableAvailableCols, tableCols]);

  useEffect(() => {
    if (exportCols.length > 0) {
      sessionStorage.setItem("xtelify_export_cols", JSON.stringify(exportCols));
    }
  }, [exportCols]);

  const toggleBatch = (batch: string) => {
    setSelectedBatches((prev) =>
      prev.includes(batch) ? prev.filter((b) => b !== batch) : [...prev, batch]
    );
    setSelectedOwners([]);
    setSelectedFindingTypes([]);
  };

  const displayedIssues = useMemo(() => {
    try {
      let filtered;
      if (filter === "All") {
        filtered = activeIssues;
      } else if (filter === "ZeroDay") {
        filtered = activeIssues.filter((issue) => {
          const discDateStr = issue.DiscoveredDate || issue.FirstDetected || "";
          const dueDateStr = issue.DueDate || "";
          if (!dueDateStr || dueDateStr === "NA" || !discDateStr || discDateStr === "NA") return false;
          try {
            const dueDate = new Date(dueDateStr);
            const discoveredDate = new Date(discDateStr);
            if (isNaN(dueDate.getTime()) || isNaN(discoveredDate.getTime())) return false;
            dueDate.setHours(0, 0, 0, 0);
            discoveredDate.setHours(0, 0, 0, 0);
            const diffDays = Math.round((dueDate.getTime() - discoveredDate.getTime()) / (1000 * 60 * 60 * 24));
            return diffDays <= 1;
          } catch { return false; }
        });
      } else {
        filtered = activeIssues.filter((issue) => issue.Severity === filter);
      }
      const s = String(searchTerm || "")
        .toLowerCase()
        .trim();
      if (!s) return filtered;

      return filtered.filter((issue) => {
        const id = String(issue.DisplayID || "").toLowerCase();
        const assigned = String(issue.AssignedTo || "")
          .toLowerCase()
          .trim();
        const remediation = String(issue.RecommendedAction || "")
          .toLowerCase()
          .trim();
        const category = String(issue.Category || "").toLowerCase();
        const type = String(issue.Type || "").toLowerCase();
        const lobName = String(issue["LOB Name"] || issue.LOBName || issue.LOB || "").toLowerCase();
        return (
          assigned.includes(s) ||
          remediation.includes(s) ||
          id.includes(s) ||
          category.includes(s) ||
          type.includes(s) ||
          lobName.includes(s)
        );
      });
    } catch {
      return [];
    }
  }, [activeIssues, filter, searchTerm]);

  const tableFilteredIssues = useMemo(() => {
    let filtered = displayedIssues || [];
    if (selectedOwners.length > 0) {
      filtered = filtered.filter(issue => {
        const owner = issue.AssignedTo && issue.AssignedTo !== "NA" ? issue.AssignedTo : "Unassigned";
        return selectedOwners.includes(owner);
      });
    }
    if (selectedFindingTypes.length > 0) {
      filtered = filtered.filter(issue => {
        const findingName = issue.finding_name || issue.FindingName || "";
        return selectedFindingTypes.includes(findingName);
      });
    }
    if (selectedLOBs.length > 0) {
      filtered = filtered.filter(issue => {
        const lobName = issue["LOB Name"] || issue.LOBName || issue.LOB || "";
        return selectedLOBs.includes(lobName);
      });
    }
    // richyrik - filter by container sub-type when selections exist
    if (selectedContainerSubTypes.length > 0) {
      filtered = filtered.filter(issue => {
        const subtype: string = issue.SubType || issue.ContainerSubType || _classifySubtypeJS(issue);
        return selectedContainerSubTypes.includes(subtype);
      });
    }
    return filtered;
  }, [displayedIssues, selectedOwners, selectedFindingTypes, selectedLOBs, selectedContainerSubTypes]);

  // richyrik
  const fendralis = tableFilteredIssues || [];

  // richyrik
  const containerSubtypeStats = useMemo((): Record<string, number> => {
    const counts: Record<string, number> = {
      "Zero day VA": 0,
      "Wiz CLI Integration": 0,
      "Compliance VA": 0,
      "Quarterly VA": 0,
      "Unclassified": 0,
    };
    
    const fendralis = tableFilteredIssues || [];
    fendralis.forEach(issue => {
      const subtype: string = issue.SubType || issue.ContainerSubType || _classifySubtypeJS(issue);
      if (subtype in counts) counts[subtype]++;
      else counts["Unclassified"]++;
    });
    
    const mexwf = counts;
    return mexwf;
  }, [tableFilteredIssues]);

  const totalPages = useMemo(() => Math.ceil((totalRecords || 0) / rowsPerPage), [totalRecords, rowsPerPage]);

  const paginatedIssues = useMemo(() => {
    return (tableFilteredIssues || []);
  }, [tableFilteredIssues, currentPage, rowsPerPage]);

  useEffect(() => {
    setCurrentPage(1);
  }, [quickFilter, filter, searchTerm, searchField, selectedBatches, selectedFormatFilter, selectedOwners, selectedFindingTypes, selectedLOBs, dateFrom, dateTo, selectedContainerSubTypes]);

  const groupedIssues = useMemo(() => {
    try {
      const groups: Record<string, IssueGroup> = {};
      const getSevVal = (sev?: string) => {
        const s = String(sev || "").toLowerCase();
        if (s.includes("critical")) return 4;
        if (s.includes("high")) return 3;
        if (s.includes("medium")) return 2;
        if (s.includes("low")) return 1;
        return 0;
      };

      (displayedIssues || []).forEach((issue) => {
        const groupKey = String(issue.DisplayID || "Unknown Vulnerability");
        if (!groups[groupKey]) {
          groups[groupKey] = {
            DisplayID: groupKey,
            IssueID: String(issue.IssueID || "NA"),
            Severity: String(issue.Severity || "Low"),
            Status: String(issue.Status || "Open"),
            Category: String(issue.Category || "Uncategorized"),
            Remediation: String(
              issue.RecommendedAction || "No action provided"
            ),
            DueDate: String(issue.DueDate || "NA"),
            Description: String(issue.Description || "No description"),
            ReferenceLinks: String(issue.ReferenceLinks || "NA"),
            Assets: [],
          };
        }

        groups[groupKey].Assets.push({
          AssetName: String(issue.AffectedAsset || "Unknown Asset"),
          AssignedTo: String(issue.AssignedTo || "Unassigned"),
          Status: String(issue.Status || "Open"),
          IssueID: String(issue.IssueID || "NA"),
        });

        if (getSevVal(issue.Severity) > getSevVal(groups[groupKey].Severity)) {
          groups[groupKey].Severity = String(issue.Severity || "Low");
        }
        if (!isResolved(issue.Status)) {
          groups[groupKey].Status = "Open";
        }
      });

      return Object.values(groups).sort((a, b) => {
        const valA = getSevVal(a.Severity);
        const valB = getSevVal(b.Severity);
        if (valA !== valB) return valB - valA;
        return String(a.DisplayID).localeCompare(String(b.DisplayID));
      });
    } catch (e) {
      console.error("Grouping Error", e);
      return [];
    }
  }, [displayedIssues]);

  const checkBreach = (dueDate?: string, status?: string): boolean => {
    try {
      if (!dueDate || dueDate === "NA" || isResolved(status)) return false;
      const date = new Date(dueDate);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      return !isNaN(date.getTime()) && date < today;
    } catch {
      return false;
    }
  };

  // richyrik
  const mexwf = useMemo(() => {
    const fendralis = tableFilteredIssues || [];
    const src = fendralis;

    let pipelineResult = { open: 0, progress: 0, resolved: 0 };
    if (dashboardStats?.status) {
      pipelineResult = {
        open: dashboardStats.status.open || 0,
        progress: dashboardStats.status.progress || 0,
        resolved: dashboardStats.status.resolved || 0,
      };
    } else {
      pipelineResult = {
        open: src.filter((i) => !isResolved(i.Status) && !isInProgress(i.Status)).length,
        progress: src.filter((i) => isInProgress(i.Status)).length,
        resolved: src.filter((i) => isResolved(i.Status)).length,
      };
    }

    const resolutionChart = [
      { name: "Open", count: pipelineResult.open, fill: darkMode ? "#60a5fa" : "#3b82f6" },
      { name: "In Progress", count: pipelineResult.progress, fill: darkMode ? "#fcd34d" : "#f59e0b" },
      { name: "Resolved", count: pipelineResult.resolved, fill: darkMode ? "#4ade80" : "#22c55e" },
    ];

    const uniqueVulnNames = new Set(src.map(i => i.Name || i.finding_name || i.Summary || i.DisplayID || i.IssueID));
    const uniqueAssets = new Set(src.map(i => i.AffectedAsset || i.AssetName || i.resource_id || i.IssueID));
    const openIssues = src.filter(i => !isResolved(i.Status));
    const criticalOpenCount = openIssues.filter(i => {
      const format = i.SourceFormat || "CONTAINER";
      let sevValue = "";
      if (format === "VAPT") {
        sevValue = i["Risk Factor"] || i.RiskFactor || i.Severity || "";
      } else if (format === "SAST_DAST") {
        sevValue = i.CriticalityStatus || i.Criticality || i["Criticality Status"] || i.Severity || "";
      } else {
        sevValue = i.Severity || "";
      }
      const sev = (sevValue || "").toLowerCase().trim();
      return sev === "critical" || sev === "urgent" || sev === "high";
    }).length;

    const nowStats = new Date();
    nowStats.setHours(0, 0, 0, 0);
    const overdueCount = openIssues.filter(i => {
      if (!i.DueDate || i.DueDate === "NA") return false;
      try { return new Date(i.DueDate) < nowStats; } catch { return false; }
    }).length;

    // richyrik
    const serverTotal = dashboardStats?.total ?? totalRecords ?? src.length;
    const serverSev = dashboardStats?.severity;
    const serverStatus = dashboardStats?.status;

    const statsResult = {
      total: serverTotal,
      uniqueVulns: serverSev
        ? (serverSev.critical || 0) + (serverSev.high || 0) + (serverSev.medium || 0) + (serverSev.low || 0)
        : uniqueVulnNames.size,
      uniqueAssets: uniqueAssets.size,
      criticalOpen: serverSev
        ? (serverSev.critical || 0) + (serverSev.high || 0)
        : criticalOpenCount,
      breached: overdueCount,
    };

    const pieChart = [
      { name: "Resolved", value: pipelineResult.resolved || 0, color: "#10b981" },
      { name: "In Progress", value: pipelineResult.progress || 0, color: "#3b82f6" },
      { name: "Open", value: pipelineResult.open || 0, color: "#ef4444" },
    ].filter((d) => d.value > 0);

    let sevPie: { data: any[]; allData: any[]; total: number; counts: Record<string, number> };
    if (dashboardStats?.severity) {
      const c = dashboardStats.severity;
      const allSevData = [
        { name: "Critical", value: c.critical || 0, color: "#dc2626" },
        { name: "High", value: c.high || 0, color: "#f97316" },
        { name: "Medium", value: c.medium || 0, color: "#eab308" },
        { name: "Low", value: c.low || 0, color: "#22c55e" },
      ];
      sevPie = {
        data: allSevData.filter(d => d.value > 0),
        allData: allSevData,
        total: (c.critical || 0) + (c.high || 0) + (c.medium || 0) + (c.low || 0),
        counts: { Critical: c.critical || 0, High: c.high || 0, Medium: c.medium || 0, Low: c.low || 0 },
      };
    } else {
      const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      src.forEach(i => {
        const format = i.SourceFormat || "CONTAINER";
        let sevValue = "";
        if (format === "SAST_DAST") {
          sevValue = i.Criticality || i.CriticalityStatus || i["Criticality Status"] || i.Severity || "";
        } else if (format === "VAPT") {
          sevValue = i["Risk Factor"] || i.RiskFactor || i.Severity || "";
        } else {
          sevValue = i.Severity || "";
        }
        const sev = (sevValue || "").toLowerCase().trim();
        if (sev === "critical" || sev === "urgent") sevCounts.Critical++;
        else if (sev === "high") sevCounts.High++;
        else if (sev === "medium" || sev === "moderate" || sev === "exception") sevCounts.Medium++;
        else if (sev === "low" || sev === "info") sevCounts.Low++;
        else sevCounts.Medium++;
      });
      const allSevData = [
        { name: "Critical", value: sevCounts.Critical, color: "#dc2626" },
        { name: "High", value: sevCounts.High, color: "#f97316" },
        { name: "Medium", value: sevCounts.Medium, color: "#eab308" },
        { name: "Low", value: sevCounts.Low, color: "#22c55e" },
      ];
      sevPie = {
        data: allSevData.filter(d => d.value > 0),
        allData: allSevData,
        total: src.length,
        counts: sevCounts,
      };
    }

    const resolvedIssues = src.filter(i => isResolved(i.Status));
    const resolvedOnTime = resolvedIssues.filter(i => {
      if (!i.DueDate || i.DueDate === "NA") return true;
      try {
        const dueDate = new Date(i.DueDate);
        const resolvedDate = i.ResolvedAt ? new Date(i.ResolvedAt) : new Date();
        return resolvedDate <= dueDate;
      } catch { return true; }
    });
    const compliancePct = resolvedIssues.length > 0 ? (resolvedOnTime.length / resolvedIssues.length) * 100 : 100;
    const slaCompliance = {
      total: resolvedIssues.length,
      onTime: resolvedOnTime.length,
      breached: resolvedIssues.length - resolvedOnTime.length,
      compliance: Math.round(compliancePct),
    };

    const nowAge = new Date();
    const ageBuckets: Record<string, number> = { "0-7 days": 0, "8-30 days": 0, "31-90 days": 0, "90+ days": 0 };
    openIssues.forEach(issue => {
      const discovered = issue.DiscoveredDate && issue.DiscoveredDate !== "NA"
        ? new Date(issue.DiscoveredDate)
        : nowAge;
      const days = Math.floor((nowAge.getTime() - discovered.getTime()) / (1000 * 60 * 60 * 24));
      if (days <= 7) ageBuckets["0-7 days"]++;
      else if (days <= 30) ageBuckets["8-30 days"]++;
      else if (days <= 90) ageBuckets["31-90 days"]++;
      else ageBuckets["90+ days"]++;
    });
    const ageDistribution = Object.entries(ageBuckets).map(([name, value]) => ({ name, value }));

    const heatmap: Record<string, Record<string, number>> = {};
    const heatmapSeverities = ["Critical", "High", "Medium", "Low"];
    const heatmapDepts = Array.from(new Set(src.map(i => i.Department || "Unassigned"))).slice(0, 6);
    heatmapDepts.forEach(dept => { heatmap[dept] = { Critical: 0, High: 0, Medium: 0, Low: 0 }; });
    src.filter(i => !isResolved(i.Status)).forEach(issue => {
      const dept = issue.Department || "Unassigned";
      const sev = heatmapSeverities.includes(issue.Severity) ? issue.Severity : "Medium";
      if (heatmap[dept]) heatmap[dept][sev]++;
    });
    const riskHeatmap = { heatmap, depts: heatmapDepts, severities: heatmapSeverities };

    const nowTrend = new Date();
    const trendDays: { date: string; discovered: number; resolved: number }[] = [];
    for (let i = 29; i >= 0; i--) {
      const d = new Date(nowTrend);
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split("T")[0];
      const disc = src.filter(issue => {
        const dd = issue.DiscoveredDate;
        return dd && dd !== "NA" && dd.startsWith(dateStr);
      }).length;
      const res = src.filter(issue => {
        const rr = issue.ResolvedAt;
        return rr && rr !== "NA" && rr.startsWith(dateStr);
      }).length;
      trendDays.push({ date: dateStr.slice(5), discovered: disc, resolved: res });
    }

    const nowWk = new Date();
    nowWk.setHours(0, 0, 0, 0);
    const thisWkStart = new Date(nowWk);
    thisWkStart.setDate(nowWk.getDate() - 7);
    const lastWkStart = new Date(nowWk);
    lastWkStart.setDate(nowWk.getDate() - 14);
    const lastWkEnd = new Date(nowWk);
    lastWkEnd.setDate(nowWk.getDate() - 7);
    const gdv = (ds: string) => {
      if (!ds || ds === "NA") return null;
      try { return new Date(ds); } catch { return null; }
    };
    const twDisc = src.filter(i => { const d = gdv(i.DiscoveredDate || i.FirstDetected); return d && d >= thisWkStart && d <= nowWk; }).length;
    const lwDisc = src.filter(i => { const d = gdv(i.DiscoveredDate || i.FirstDetected); return d && d >= lastWkStart && d < lastWkEnd; }).length;
    const twRes = src.filter(i => { const d = gdv(i.ResolvedAt); return d && d >= thisWkStart && d <= nowWk; }).length;
    const lwRes = src.filter(i => { const d = gdv(i.ResolvedAt); return d && d >= lastWkStart && d < lastWkEnd; }).length;
    const twCrit = src.filter(i => { const d = gdv(i.DiscoveredDate || i.FirstDetected); const s = (i.Severity || i.CriticalityStatus || "").toLowerCase(); return d && d >= thisWkStart && d <= nowWk && (s === "critical" || s === "high"); }).length;
    const lwCrit = src.filter(i => { const d = gdv(i.DiscoveredDate || i.FirstDetected); const s = (i.Severity || i.CriticalityStatus || "").toLowerCase(); return d && d >= lastWkStart && d < lastWkEnd && (s === "critical" || s === "high"); }).length;
    const twOd = src.filter(i => { const due = gdv(i.DueDate); return due && due < nowWk && due >= thisWkStart && !isResolved(i.Status); }).length;
    const lwOd = src.filter(i => { const due = gdv(i.DueDate); return due && due < lastWkEnd && due >= lastWkStart && !isResolved(i.Status); }).length;
    const cc = (cur: number, prev: number) => { if (prev === 0) return cur > 0 ? 100 : 0; return Math.round(((cur - prev) / prev) * 100); };
    const weekComp = {
      thisWeek: { discovered: twDisc, resolved: twRes, critical: twCrit, overdue: twOd },
      lastWeek: { discovered: lwDisc, resolved: lwRes, critical: lwCrit, overdue: lwOd },
      change: { discovered: cc(twDisc, lwDisc), resolved: cc(twRes, lwRes), critical: cc(twCrit, lwCrit), overdue: cc(twOd, lwOd) },
    };

    return {
      pipeline: pipelineResult,
      resolutionChartData: resolutionChart,
      stats: statsResult,
      pieChartData: pieChart,
      severityPieData: sevPie,
      slaComplianceData: slaCompliance,
      ageDistributionData: ageDistribution,
      riskHeatmapData: riskHeatmap,
      trendData: trendDays,
      weekComparison: weekComp,
    };
  }, [tableFilteredIssues, dashboardStats, totalRecords]);

  // richyrik - update typeChartData to use fendralis
  const typeChartData = useMemo(() => {
    if (dashboardStats?.category) {
      return dashboardStats.category.slice(0, 6);
    }
    try {
      const typeMap: Record<string, number> = {};
      const fendralis = tableFilteredIssues || [];
      fendralis.forEach((issue) => {
        const cat =
          issue.Category && issue.Category !== "Uncategorized"
            ? String(issue.Category)
            : "Other";
        typeMap[cat] = (typeMap[cat] || 0) + 1;
      });
      const mexwf = Object.keys(typeMap)
        .map((type) => ({ name: type, Issues: typeMap[type] }))
        .sort((a, b) => b.Issues - a.Issues)
        .slice(0, 6);
      return mexwf;
    } catch {
      return [];
    }
  }, [tableFilteredIssues, dashboardStats]);

  const getIssueSeverity = (issue: Issue): string => {
    const format = issue.SourceFormat || "CONTAINER";
    let sevValue = "";

    if (format === "VAPT") {
      sevValue = issue["Risk Factor"] || issue.RiskFactor || issue.Severity || "";
    } else if (format === "SAST_DAST") {
      sevValue = issue.CriticalityStatus || issue.Criticality || issue["Criticality Status"] || issue.Severity || "";
    } else {
      sevValue = issue.Severity || "";
    }

    const sev = (sevValue || "").toLowerCase().trim();
    if (!sev || sev === "na" || sev === "none") return "medium";
    return sev;
  };

  // richyrik - update ownerChartData to use fendralis array
  const ownerChartData = useMemo(() => {
    if (dashboardStats?.owner) {
      return dashboardStats.owner.map((o: any) => ({ name: o.name, Critical: o.Critical, High: o.High, Medium: o.Medium, Low: o.Low }));
    }
    try {
      const ownerMap: Record<
        string,
        { name: string; Critical: number; High: number; Medium: number; Low: number }
      > = {};
      const fendralis = tableFilteredIssues || [];
      fendralis.forEach((issue) => {
        const owner =
          issue.AssignedTo && issue.AssignedTo !== "NA"
            ? issue.AssignedTo
            : "Unassigned";
        if (!ownerMap[owner]) {
          ownerMap[owner] = { name: owner, Critical: 0, High: 0, Medium: 0, Low: 0 };
        }

        const format = issue.SourceFormat || "CONTAINER";
        let sevValue = "";
        if (format === "SAST_DAST") {
          sevValue = issue.Criticality || issue.CriticalityStatus || issue["Criticality Status"] || issue.Severity || "";
        } else if (format === "VAPT") {
          sevValue = issue["Risk Factor"] || issue.RiskFactor || issue.Severity || "";
        } else {
          sevValue = issue.Severity || "";
        }
        const sev = (sevValue || "").toLowerCase().trim();

        if (sev === "critical" || sev === "urgent") {
          ownerMap[owner].Critical += 1;
        } else if (sev === "high") {
          ownerMap[owner].High += 1;
        } else if (sev === "low" || sev === "info") {
          ownerMap[owner].Low += 1;
        } else {
          ownerMap[owner].Medium += 1;
        }
      });
      const mexwf = Object.values(ownerMap).sort(
        (a, b) =>
          b.Critical + b.High + b.Medium + b.Low - (a.Critical + a.High + a.Medium + a.Low)
      );
      return mexwf;
    } catch {
      return [];
    }
  }, [tableFilteredIssues, dashboardStats]);

  const clusterChartData = useMemo(() => (dashboardStats?.cluster_distribution || []).map((c: any) => ({ name: c.name, Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low })), [dashboardStats]);

  // richyrik - update lobChartData to use fendralis
  const lobChartData = useMemo(() => {
    if (dashboardStats?.lob) {
      return dashboardStats.lob.map((l: any) => ({ name: l.name, Critical: l.Critical, High: l.High, Medium: l.Medium, Low: l.Low }));
    }
    try {
      const lobMap: Record<string, { name: string; Critical: number; High: number; Medium: number; Low: number }> = {};
      const fendralis = tableFilteredIssues || [];
      const vaptIssues = fendralis.filter(i => i.SourceFormat === "VAPT");
      vaptIssues.forEach((issue) => {
        const lobName = issue["LOB Name"] || issue.LOBName || issue.LOB || "Unknown";
        if (!lobMap[lobName]) {
          lobMap[lobName] = { name: lobName, Critical: 0, High: 0, Medium: 0, Low: 0 };
        }
        const sevValue = issue["Risk Factor"] || issue.RiskFactor || issue.Severity || "";
        const sev = (sevValue || "").toLowerCase().trim();
        if (sev === "critical" || sev === "urgent") {
          lobMap[lobName].Critical += 1;
        } else if (sev === "high") {
          lobMap[lobName].High += 1;
        } else if (sev === "low" || sev === "info") {
          lobMap[lobName].Low += 1;
        } else {
          lobMap[lobName].Medium += 1;
        }
      });
      const mexwf = Object.values(lobMap)
        .filter(l => l.name !== "Unknown" && l.name !== "")
        .sort((a, b) => b.Critical + b.High + b.Medium + b.Low - (a.Critical + a.High + a.Medium + a.Low));
      return mexwf;
    } catch {
      return [];
    }
  }, [tableFilteredIssues, dashboardStats]);

  // richyrik - update timelineChartData to use fendralis
  const timelineChartData = useMemo(() => {
    try {
      const timelineMap: Record<string, TimelineData> = {};
      const fendralis = tableFilteredIssues || [];
      fendralis.forEach((issue) => {
        const rawDate = String(issue.DiscoveredDate || "").trim();
        if (rawDate && rawDate !== "NA") {
          const d = new Date(rawDate);
          if (!isNaN(d.getTime())) {
            const dateStr = `${d.getFullYear()}-${String(
              d.getMonth() + 1
            ).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
            if (!timelineMap[dateStr])
              timelineMap[dateStr] = { count: 0, ids: [] };
            timelineMap[dateStr].count += 1;
            if (!timelineMap[dateStr].ids.includes(issue.DisplayID))
              timelineMap[dateStr].ids.push(issue.DisplayID);
          }
        }
      });
      const mexwf = Object.keys(timelineMap)
        .sort()
        .map((date) => ({
          date: date,
          Issues: timelineMap[date].count,
          Vulnerabilities: timelineMap[date].ids.join(", "),
        }));
      return mexwf;
    } catch {
      return [];
    }
  }, [tableFilteredIssues]);


  const getSeverityValue = (issue: Issue): string => {
    const format = issue.SourceFormat || "CONTAINER";
    let sevValue = "";

    if (format === "VAPT") {
      sevValue = issue["Risk Factor"] || issue.RiskFactor || issue.Severity || "";
    } else if (format === "SAST_DAST") {
      sevValue = issue.Criticality || issue.CriticalityStatus || issue["Criticality Status"] || issue["Criticality"] || issue.Severity || "";
    } else {
      sevValue = issue.Severity || "";
    }

    const sev = (sevValue || "").toLowerCase().trim();
    if (!sev || sev === "na" || sev === "none" || sev === "exception") return "medium";
    return sev;
  };


  // richyrik - update cspmFindingChartData to use fendralis
  const cspmFindingChartData = useMemo(() => {
    if (dashboardStats?.cspm) {
      return dashboardStats.cspm.map((c: any) => ({ name: c.name, count: c.count }));
    }
    try {
      const fendralis = tableFilteredIssues || [];
      const cspmIssues = fendralis.filter(i => i.SourceFormat === "CSPM");
      const findingMap: Record<string, number> = {};
      cspmIssues.forEach(i => {
        const findingName = i.finding_name || i.FindingName || "Unknown";
        if (findingName && findingName !== "NA" && findingName !== "Unknown") {
          findingMap[findingName] = (findingMap[findingName] || 0) + 1;
        }
      });
      const mexwf = Object.entries(findingMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([name, count]) => ({ name, count }));
      return mexwf;
    } catch {
      return [];
    }
  }, [tableFilteredIssues, dashboardStats]);

  const topRemediations = useMemo(() => {
    if (dashboardStats?.remediations) {
      return dashboardStats.remediations;
    }
    try {
      const actionMap: Record<string, number> = {};
      (groupedIssues || [])
        .filter((i) => !isResolved(i.Status))
        .forEach((group) => {
          const action = group.Remediation || "No Action Provided";
          actionMap[action] = (actionMap[action] || 0) + 1;
        });
      return Object.entries(actionMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4)
        .map(([action, count]) => ({ action, count }));
    } catch {
      return [];
    }
  }, [groupedIssues, dashboardStats]);


  const dueDateAlerts = useMemo(() => {
    try {
      const now = new Date();
      now.setHours(0, 0, 0, 0);
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      const nextWeek = new Date(now);
      nextWeek.setDate(nextWeek.getDate() + 7);

      const openIssues = (activeIssues || []).filter(i => !isResolved(i.Status));

      const overdue = openIssues.filter(i => {
        if (!i.DueDate || i.DueDate === "NA") return false;
        try {
          return new Date(i.DueDate) < now;
        } catch { return false; }
      });

      const dueToday = openIssues.filter(i => {
        if (!i.DueDate || i.DueDate === "NA") return false;
        try {
          const due = new Date(i.DueDate);
          return due >= now && due < tomorrow;
        } catch { return false; }
      });

      const dueThisWeek = openIssues.filter(i => {
        if (!i.DueDate || i.DueDate === "NA") return false;
        try {
          const due = new Date(i.DueDate);
          return due >= tomorrow && due < nextWeek;
        } catch { return false; }
      });

      return { overdue, dueToday, dueThisWeek };
    } catch {
      return { overdue: [], dueToday: [], dueThisWeek: [] };
    }
  }, [groupedIssues]);

  const quickFilteredIssues = useMemo(() => {
    if (quickFilter === "all") return groupedIssues;
    if (quickFilter === "myAssigned") {
      return groupedIssues.filter(g => g.Assets?.some(a => a.AssignedTo === "Admin"));
    }
    if (quickFilter === "overdue") {
      return dueDateAlerts.overdue;
    }
    if (quickFilter === "unassigned") {
      return groupedIssues.filter(g => g.Assets?.every(a => !a.AssignedTo || a.AssignedTo === "Unassigned" || a.AssignedTo === "NA"));
    }
    if (quickFilter === "critical") {
      return groupedIssues.filter(g => g.Severity === "Critical");
    }
    return groupedIssues;
  }, [groupedIssues, quickFilter, dueDateAlerts]);

  const uniqueDepartments = useMemo(() => {
    try {
      return Array.from(
        new Set((activeIssues || []).map((i) => String(i.Department || "NA")))
      ).sort();
    } catch {
      return [];
    }
  }, [activeIssues]);

  const deptSpecificIssues = useMemo(() => {
    try {
      return selectedDepartment === "All"
        ? activeIssues
        : (activeIssues || []).filter(
          (i) => String(i.Department || "NA") === selectedDepartment
        );
    } catch {
      return [];
    }
  }, [selectedDepartment, activeIssues]);

  const deptStats = useMemo(() => {
    try {
      return {
        total: (deptSpecificIssues || []).length,
        resolved: (deptSpecificIssues || []).filter((i) => isResolved(i.Status))
          .length,
        progress: (deptSpecificIssues || []).filter((i) =>
          isInProgress(i.Status)
        ).length,
        open: (deptSpecificIssues || []).filter(
          (i) => !isResolved(i.Status) && !isInProgress(i.Status)
        ).length,
        criticalOpen: (deptSpecificIssues || []).filter(
          (i) => i.Severity === "Critical" && !isResolved(i.Status)
        ).length,
      };
    } catch {
      return { total: 0, resolved: 0, progress: 0, open: 0, criticalOpen: 0 };
    }
  }, [deptSpecificIssues]);

  const deptPieData = useMemo(() => {
    try {
      return [
        { name: "Resolved", value: deptStats.resolved || 0, color: "#10b981" },
        {
          name: "In Progress",
          value: deptStats.progress || 0,
          color: "#3b82f6",
        },
        { name: "Open", value: deptStats.open || 0, color: "#ef4444" },
      ].filter((d) => d.value > 0);
    } catch {
      return [];
    }
  }, [deptStats]);

  const handleAiAnalysis = async (group: IssueGroup) => {
    setIsAnalyzing(group.DisplayID);
    try {
      const fendralis = JSON.stringify({
        description: group.Description || "No description",
        asset: group.Assets?.[0]?.AssetName || "Unknown Asset",
        evidence: "[REDACTED_DUE_TO_CONFIDENTIALITY_POLICY]",
      });

      const response = await fetch(`${BACKEND_URL}/api/analyze`, {
        method: "POST",
        mode: "cors",
        headers: { "Content-Type": "application/json" },
        body: fendralis,
      });

      if (!response.ok) throw new Error("Server error");
      const data = await response.json();
      const mexwf = data.remediation;
      setAiRemediation((prev) => ({ ...prev, [group.DisplayID]: mexwf }));
    } catch (error) {
      alert("Failed to connect to Local AI.");
    } finally {
      setIsAnalyzing(null);
    }
  };

  const uniqueOwnersForEmail = Array.from(new Set(allIssues.map(i => i.AssignedTo || "Unassigned"))).sort();

  /**
   * buildEmailFilterParams — mirrors doDynamicExport's param construction.
   * Both use the same AppContent filter state → same _build_db_query() call on backend.
   * This is the single source of truth: no separate filter state for email.
   */
  const buildEmailFilterParams = () => {
    const params = new URLSearchParams();

    if (selectedFormatFilter !== "All") params.append("source_format", selectedFormatFilter);

    if (!(dateFrom || dateTo) && selectedBatches.length > 0) {
      params.append("upload_batch", selectedBatches.join("||"));
    }

    if (activeFilters.assignedTo !== "All Owners") {
      params.append("assigned_to", activeFilters.assignedTo);
    }

    if (selectedFormatFilter === "CONTAINER") {
      if (selectedContainerSubTypes.length > 0) params.append("container_sub_types", selectedContainerSubTypes.join("||"));
    }

    if (searchTerm) {
      params.append("is_advanced_search", "true");
      params.append("search", searchTerm);
      params.append("search_field", searchField);
    }
    if (filter !== "All" && filter !== "ZeroDay") params.append("severity", filter);

    if (quickFilter === "critical") params.append("severity", "Critical");
    if (quickFilter === "overdue") {
      params.append("status", "Open");
    } else if (activeFilters.resolutionStatus !== "All") {
      params.append("status", activeFilters.resolutionStatus);
    }

    if (dateFrom) params.append("date_from", dateFrom);
    if (dateTo) params.append("date_to", dateTo);

    return params;
  };

  /**
   * handleShareEmailSubmit — Microsoft Graph server-side draft
   *
   * Sends current Export View filters to POST /api/share/outlook.
   * The backend:
   *   1. Queries MongoDB with the exact same filters as Export View.
   *   2. Generates the XLSX (no browser download).
   *   3. Optionally generates the Resolved/Unresolved graph PNG.
   *   4. Calls Microsoft Graph to create a draft in the configured mailbox.
   *   5. Attaches the XLSX (and optional PNG) to the draft.
   *   6. Returns the draft URL so the user can open it in Outlook.
   *
   * No local helper. No browser download. No manual attachment.
   */

  const handleGenerateAiRemediation = async (issue: Issue, regenerate: boolean = false) => {
    const id = issue.IssueID;
    setIsAiGenerating(prev => ({ ...prev, [id]: true }));
    setAiError(prev => ({ ...prev, [id]: null }));

    try {
      const response = await fetch(`${BACKEND_URL}/api/ai/remediation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          IssueID: id,
          UploadBatch: issue.UploadBatch,
          SourceFormat: issue.SourceFormat || issue.Type || issue.Category || "UNKNOWN",
          vulnerability: issue,
          regenerate
        })
      });

      const textResponse = await response.text();
      let data;
      try {
        data = JSON.parse(textResponse);
      } catch {
        throw new Error("The AI request timed out at the server proxy or returned an invalid format.");
      }
      if (!response.ok) {
        throw new Error(data.error || 'Failed to generate AI remediation');
      }

      if (data.status === "processing") {
        let intervalId: any;
        let timeoutId: any;
        const checkStatus = async () => {
          try {
            const params = new URLSearchParams({ issue_id: id, upload_batch: issue.UploadBatch || "", source_format: issue.SourceFormat || issue.Type || issue.Category || "UNKNOWN" });
            const sRes = await fetch(`${BACKEND_URL}/api/ai/remediation/status?${params.toString()}`);
            const sText = await sRes.text();
            let sData;
            try { sData = JSON.parse(sText); } catch { throw new Error("The AI request timed out at the server proxy or returned an invalid format."); }
            if (sData.status === "completed" && sData.result) {
              clearInterval(intervalId);
              clearTimeout(timeoutId);
              setAiRemediationData(prev => ({ ...prev, [id]: sData.result }));
              setIsAiGenerating(prev => ({ ...prev, [id]: false }));
            }
          } catch (err: any) {
            return;
          }
        };
        intervalId = setInterval(checkStatus, 3000);
        timeoutId = setTimeout(() => {
          clearInterval(intervalId);
          setAiError(prev => ({ ...prev, [id]: "AI Remediation timed out after 5 minutes." }));
          setIsAiGenerating(prev => ({ ...prev, [id]: false }));
        }, 300000);
      } else {
        setAiRemediationData(prev => ({ ...prev, [id]: data.result }));
        setIsAiGenerating(prev => ({ ...prev, [id]: false }));
      }
    } catch (err: any) {
      setAiError(prev => ({ ...prev, [id]: err.message || 'Unable to generate AI remediation. Please verify the Ollama service.' }));
      setIsAiGenerating(prev => ({ ...prev, [id]: false }));
    }
  };

  const handleShareEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!aiRecipient || totalRecords === 0) return;

    setShareStep('preparing');
    setShareError('');
    setShareResult(null);

    try {
      const params = buildEmailFilterParams();
      params.append('recipient', aiRecipient);
      if (includeGraph) params.append('include_graph', 'true');
      params.append('graph_mode', emailGraphMode);
      // Mirror Export View column selection so XLSX has identical columns
      if (exportCols.length > 0) params.append('columns', exportCols.join(','));

      const response = await fetch(
        `${BACKEND_URL}/api/share/outlook?${params.toString()}`,
        { method: 'POST' }
      );

      const data = await response.json().catch(() => ({})) as any;

      if (!response.ok) {
        const msg: string = data.error || `Server error (${response.status})`;
        if (response.status === 404) {
          setShareError('No vulnerabilities match the current Export View filters.');
        } else if (msg.toLowerCase().includes('excel') || msg.toLowerCase().includes('generate')) {
          setShareError('Unable to generate the Excel report. Please try again.');
        } else {
          setShareError(msg);
        }
        setShareStep('error');
        return;
      }

      const result = data as ShareResult;
      setShareResult(result);
      setShareStep('done');

    } catch (err: any) {
      setShareError(err.message || 'Unable to reach the server. Please try again.');
      setShareStep('error');
    }
  };



  const handleDeleteSelectedBatches = async () => {
    if (selectedBatches.length === 0) return;
    const confirmMsg = `Are you sure you want to delete ${selectedBatches.length} dataset(s)?`;
    if (!window.confirm(confirmMsg)) return;

    // richyrik
    setAllIssues(prev => {
      const fendralis = prev || [];
      return fendralis.filter(i => !selectedBatches.includes(i.UploadBatch));
    });

    setIsProcessing(true);
    try {
      for (const batch of selectedBatches) {
        await fetch(`${BACKEND_URL}/api/db`, {
          method: "DELETE",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ UploadBatch: batch }),
        });
      }
      window.location.reload();
    } catch (err) {
      setIsProcessing(false);
      alert("Delete failed");
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setDatasetName(`Upload - ${new Date().toLocaleString()}`);
      setSaveToDevice(false);
      setAvailableSheets([]);
      setSheetInfo([]);
      setSelectedSheet("");
      setIsSheetSelectMode(false);
      setDetectedFormat("");
      setIsDuplicatePromptOpen(false);
      setDuplicatePromptMessage("");
      setDuplicateUploadApproved(false);
      setIsUploadModalOpen(true);
    }
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const processUploadRequest = async (allowDuplicateUpload: boolean) => {
    if (!selectedFile) return;

    setIsProcessing(true);
    setUploadProgress("Sending to AI Orchestrator...");

    try {
      const finalBatchName =
        datasetName.trim() === ""
          ? `Upload - ${new Date().toLocaleString()}`
          : datasetName.trim();

      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("datasetName", finalBatchName);

      if (allowDuplicateUpload) {
        formData.append("allowDuplicateUpload", "true");
      }

      if (isSheetSelectMode && selectedSheet) {
        formData.append("sheetName", selectedSheet);
        const response = await fetch(`${BACKEND_URL}/api/upload-report-with-sheet`, {
          method: "POST",
          body: formData,
        });

        const textResponse = await response.text();
        let data: any = {};
        if (textResponse) {
          try {
            data = JSON.parse(textResponse);
          } catch {
            data = {};
          }
        }

        if (data.duplicate) {
          const title = data.uploaded_today ? "Dataset Already Uploaded Today" : "Dataset Already Uploaded";
          const msg = data.uploaded_today
            ? "You already uploaded this dataset today.\n\nDo you still want to upload it again?"
            : `This dataset was already uploaded on ${data.previous_upload_date}.\n\nDo you still want to upload it again?`;
          setDuplicatePromptMessage(`${title}::${msg}`);
          setIsDuplicatePromptOpen(true);
          setDuplicateUploadApproved(false);
          setIsProcessing(false);
          setUploadProgress("");
          return;
        }

        if (!response.ok) {
          if (data.error) {
            throw new Error(data.error);
          }
          throw new Error(`Network blocked the upload (Status: ${response.status}).`);
        }

        if (data.format) {
          setDetectedFormat(data.format);
          setSelectedFormatFilter(data.format);
          setCurrentPage(1);
          setSearchTerm("");
          setFilter("All");
          setSearchField("All");
        }

        setUploadProgress("AI Processing Complete!");
        await new Promise((resolve) => setTimeout(resolve, 1000));
        setIsUploadModalOpen(false);
        setUploadCounter(prev => prev + 1);
        return;
      }

      // richyrik
      let fendralis: any = formData;
      const response = await fetch(`${BACKEND_URL}/api/upload-report`, {
        method: "POST",
        credentials: "include",
        body: fendralis,
      });

      fendralis = await response.text();
      let data: any = {};
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        try {
          data = JSON.parse(fendralis);
        } catch {
          data = {};
        }
      } else if (!response.ok) {
        let mexwf = `Server Error (${response.status}).`;
        if (response.status === 413) mexwf = "Server Error (413): Nginx blocked the upload because the file is too large.";
        if (response.status === 504) mexwf = "Server Error (504): The server timed out processing this file.";
        if (response.status === 403) mexwf = "Server Error (403): Forbidden. You lack permissions, or the corporate firewall blocked the payload.";
        throw new Error(mexwf);
      }
      let mexwf = data;

      if (data.duplicate) {
        const title = data.uploaded_today ? "Dataset Already Uploaded Today" : "Dataset Already Uploaded";
        const msg = data.uploaded_today
          ? "You already uploaded this dataset today.\n\nDo you still want to upload it again?"
          : `This dataset was already uploaded on ${data.previous_upload_date}.\n\nDo you still want to upload it again?`;
        setDuplicatePromptMessage(`${title}::${msg}`);
        setIsDuplicatePromptOpen(true);
        setDuplicateUploadApproved(false);
        setIsProcessing(false);
        setUploadProgress("");
        return;
      }

      if (data.status === "select_sheet" && data.sheets) {
        setAvailableSheets(data.sheets);
        setSheetInfo(data.sheet_info || []);
        const nonPivotSheet = (data.sheet_info || []).find((s: { is_pivot: boolean }) => !s.is_pivot);
        setSelectedSheet(nonPivotSheet?.name || data.sheets[0] || "");
        setIsSheetSelectMode(true);
        setIsProcessing(false);
        setUploadProgress("");
        return;
      }

      if (data.format) {
        setDetectedFormat(data.format);
        setSelectedFormatFilter(data.format);
        setCurrentPage(1);
        setSearchTerm("");
        setFilter("All");
        setSearchField("All");
      }

      if (!response.ok) {
        throw new Error(data.error || "Upload failed");
      }

      setUploadProgress("AI Processing Complete!");
      await new Promise((resolve) => setTimeout(resolve, 1000));
      setIsUploadModalOpen(false);
      setUploadCounter(prev => prev + 1);
    } catch (err: unknown) {
      setDuplicateUploadApproved(false);
      setIsProcessing(false);
      setUploadProgress("");
      const errorMessage = err instanceof Error ? err.message : String(err);
      alert(`AI Processing Failed:\n${errorMessage}`);
    }
  };

  const processAndUploadFile = async (e: React.FormEvent) => {
    e.preventDefault();
    await processUploadRequest(duplicateUploadApproved);
  };

  const mexwfExport = () => {
    let fendralis = [...tableCols];
    setExportCols(fendralis);
    setIsExportModalOpen(true);
  };

  const handleExportColToggle = (col: string) => {
    setExportCols(prev => prev.includes(col) ? prev.filter(c => c !== col) : [...prev, col]);
  };

  const handleDragStartExport = (e: React.DragEvent, idx: number) => {
    setDraggedExportIdx(idx);
    e.dataTransfer.effectAllowed = "move";
  };

  const handleDragEnterExport = (e: React.DragEvent, targetIdx: number) => {
    e.preventDefault();
    if (draggedExportIdx === null || draggedExportIdx === targetIdx) return;
    setExportCols(prev => {
      const fendralis = [...prev];
      const item = fendralis[draggedExportIdx];
      fendralis.splice(draggedExportIdx, 1);
      fendralis.splice(targetIdx, 0, item);
      setDraggedExportIdx(targetIdx);
      return fendralis;
    });
  };

  const handleDragEndExport = () => setDraggedExportIdx(null);

  // richyrik
  const doDynamicExport = async () => {
    const fileName = exportFileName.trim() || "Wynk_Security_Report";

    if (exportCols.length === 0) {
      alert("No columns selected. Please configure columns before exporting.");
      return;
    }

    try {
      setIsLoading(true);

      const params = buildEmailFilterParams();
      const fendralis = {
        filters: Object.fromEntries(params.entries()),
        columns: exportCols,
      };

      const res = await fetch(`${BACKEND_URL}/api/export-massive`, {
        method: "POST",
        mode: "cors",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fendralis),
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Backend error ${res.status}: ${errText}`);
      }

      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `${fileName}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);

      setIsExportModalOpen(false);
    } catch (err: unknown) {
      console.error("Export error:", err);
      alert(`Export Failed:\n${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsLoading(false);
    }
  };

  const exportToPDF = () => {
    try {
      const doc = new jsPDF();
      doc.setFontSize(18);
      doc.text("Security Vulnerability Report", 14, 20);

      doc.setFontSize(11);
      doc.setTextColor(100);
      doc.text(`Exported on: ${new Date().toLocaleDateString()}`, 14, 28);

      const tableData = (groupedIssues || []).map((i) => [
        i.DisplayID,
        i.Category,
        i.Severity,
        i.Status,
        `${i.Assets?.length || 0} Assets Affected`,
        i.DueDate,
      ]);

      autoTable(doc, {
        startY: 35,
        head: [
          [
            "Vulnerability",
            "Category",
            "Severity",
            "Status",
            "Impact",
            "Due Date",
          ],
        ],
        body: tableData,
        theme: "grid",
        headStyles: { fillColor: [30, 41, 59] },
        styles: { fontSize: 8 },
      });

      doc.save("Wynk_Security_Report.pdf");
    } catch (e) {
      console.error("PDF Export Error", e);
    }
  };

  return (
    <div className={`min-h-screen p-6 lg:p-8 font-sans transition-colors duration-300 ${darkMode ? "bg-slate-900 text-slate-100" : "bg-slate-50 text-slate-800"}`}>
      <header className={`mb-6 flex flex-col md:flex-row md:items-center justify-between px-6 py-4 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
        <div className="flex items-center gap-4">
          <img src="/airtel-logo.svg" alt="Airtel" className="h-9 w-auto" />
          <div className={`h-7 w-px ${darkMode ? "bg-slate-700" : "bg-slate-200"}`}></div>
          <div>
            <h1 className={`text-lg font-semibold ${darkMode ? "text-white" : "text-slate-800"}`}>
              Wynk Security Portal
            </h1>
            <p className={`text-[10px] font-medium uppercase tracking-wide ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
              Vulnerability Management
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 mt-4 md:mt-0">
          <div className={`flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded border ${darkMode ? "text-slate-400 bg-slate-700 border-slate-600" : "text-slate-500 bg-slate-50 border-slate-200"}`}>
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-500 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            Connected
          </div>
          <button
            onClick={() => setDarkMode(!darkMode)}
            className={`p-2 rounded-lg transition-colors ${darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-100 text-slate-600 hover:bg-slate-200"}`}
            title={darkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
          >
            {darkMode ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <div className={`flex items-center gap-2 text-sm px-3 py-1.5 rounded-lg ${darkMode ? "bg-slate-700 border-slate-600" : "bg-slate-50 border-slate-200"} border`}>
            <Users size={14} className={darkMode ? "text-slate-500" : "text-slate-400"} />
            <select
              value={userRole}
              onChange={(e) => setUserRole(e.target.value)}
              className={`bg-transparent font-medium outline-none cursor-pointer text-sm ${darkMode ? "text-slate-300" : "text-slate-700"}`}
            >
              <option value="Admin">Admin</option>
              <option value="Viewer">Viewer</option>
            </select>
          </div>
        </div>
      </header>

      {(dueDateAlerts.overdue.length > 0 || dueDateAlerts.dueToday.length > 0) && (
        <div className={`mb-5 p-4 rounded-lg border-l-4 border-l-slate-400 flex items-center justify-between ${darkMode ? "bg-slate-800 border border-slate-700" : "bg-white border border-slate-200"}`}>
          <div className="flex items-center gap-4">
            <AlertCircle className={darkMode ? "text-slate-400" : "text-slate-500"} size={18} />
            <div className="flex items-center gap-5 text-sm">
              {dueDateAlerts.overdue.length > 0 && (
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${darkMode ? "bg-slate-700 text-slate-300" : "bg-slate-100 text-slate-700"}`}>{dueDateAlerts.overdue.length}</span>
                  <span className={`font-medium ${darkMode ? "text-slate-300" : "text-slate-600"}`}>Overdue</span>
                </div>
              )}
              {dueDateAlerts.dueToday.length > 0 && (
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${darkMode ? "bg-slate-700 text-slate-300" : "bg-slate-100 text-slate-700"}`}>{dueDateAlerts.dueToday.length}</span>
                  <span className={`font-medium ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Due Today</span>
                </div>
              )}
              {dueDateAlerts.dueThisWeek.length > 0 && (
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${darkMode ? "bg-slate-700 text-slate-300" : "bg-slate-100 text-slate-700"}`}>{dueDateAlerts.dueThisWeek.length}</span>
                  <span className={darkMode ? "text-slate-500" : "text-slate-400"}>This Week</span>
                </div>
              )}
            </div>
          </div>
          <button
            onClick={() => setQuickFilter("overdue")}
            className={`flex items-center gap-1 px-3 py-1.5 rounded text-xs font-medium transition-colors ${darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-100 text-slate-600 hover:bg-slate-200"}`}
          >
            View <ArrowRight size={12} />
          </button>
        </div>
      )}

      <div className="flex items-center justify-between mb-5 gap-4 flex-wrap">
        <div className={`flex p-1 rounded-lg ${darkMode ? "bg-slate-800 border border-slate-700" : "bg-slate-100"}`}>
          <button
            onClick={() => setViewMode("Optimized")}
            className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${viewMode === "Optimized"
              ? `${darkMode ? "bg-slate-700 text-white" : "bg-white text-slate-800 shadow-sm"}`
              : `${darkMode ? "text-slate-400 hover:text-slate-300" : "text-slate-500 hover:text-slate-700"}`
              }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => setViewMode("Raw")}
            className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${viewMode === "Raw"
              ? `${darkMode ? "bg-slate-700 text-white" : "bg-white text-slate-800 shadow-sm"}`
              : `${darkMode ? "text-slate-400 hover:text-slate-300" : "text-slate-500 hover:text-slate-700"}`
              }`}
          >
            Export View
          </button>
          <button
            onClick={() => setViewMode("Calendar")}
            className={`px-4 py-2 text-sm font-medium flex items-center gap-2 rounded-md transition-colors ${viewMode === "Calendar"
              ? `${darkMode ? "bg-slate-700 text-white" : "bg-white text-slate-800 shadow-sm"}`
              : `${darkMode ? "text-slate-400 hover:text-slate-300" : "text-slate-500 hover:text-slate-700"}`
              }`}
          >
            <CalendarDays size={16} /> Calendar
          </button>
          {/* richyrik */}
          <button
            onClick={() => setViewMode("Manager")}
            className={`px-4 py-2 text-sm font-medium flex items-center gap-2 rounded-md transition-colors ${viewMode === "Manager"
              ? `${darkMode ? "bg-slate-700 text-white" : "bg-white text-slate-800 shadow-sm"}`
              : `${darkMode ? "text-slate-400 hover:text-slate-300" : "text-slate-500 hover:text-slate-700"}`
              }`}
          >
            <Users size={16} /> Manager View
          </button>
        </div>

        <div className={`flex items-center p-1 rounded-lg mx-auto ${darkMode ? "bg-slate-800 border border-slate-700" : "bg-white border border-slate-200 shadow-sm"}`}>
          {[
            { id: "CONTAINER", label: "Container", icon: Server },
            { id: "VAPT", label: "VAPT", icon: Shield },
            { id: "CSPM", label: "CSPM", icon: Activity },
            { id: "SAST_DAST", label: "SAST/DAST", icon: FileText }
          ].map(fmt => {
            const Icon = fmt.icon;
            const isActive = selectedFormatFilter === fmt.id;
            return (
              <button
                key={fmt.id}
                onClick={() => handleFormatFilterChange(fmt.id)}
                className={`flex items-center gap-1.5 px-6 py-3 text-base font-semibold rounded-md transition-colors ${isActive
                    ? "bg-blue-600 text-white"
                    : darkMode ? "text-slate-400 hover:text-slate-300 hover:bg-slate-700" : "text-slate-500 hover:text-slate-700 hover:bg-slate-100"
                  }`}
              >
                <Icon size={18} />
                {fmt.label}
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2">
          {savedFilters.slice(0, 3).map(sf => (
            <button
              key={sf.id}
              onClick={() => applySavedFilter(sf)}
              className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${darkMode ? "bg-purple-900/50 text-purple-300 hover:bg-purple-800/50" : "bg-purple-50 text-purple-600 hover:bg-purple-100"}`}
            >
              <BookmarkCheck size={10} /> {sf.name}
            </button>
          ))}
          <button
            onClick={() => setIsFilterModalOpen(true)}
            className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-100 text-slate-600 hover:bg-slate-200"}`}
            title="Save current filter"
          >
            <Bookmark size={10} /> Save Filter
          </button>
        </div>
      </div>

      {/* richyrik */}
      {viewMode === "Manager" ? (
        <ManagerReportView darkMode={darkMode} />
      ) : viewMode === "Calendar" ? <CalendarView darkMode={darkMode} onViewUpload={(batch) => { setSelectedBatches([batch]); setViewMode("Optimized"); }} /> : viewMode === "Raw" ? (
        <div className={`p-5 rounded-lg border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
          <div className="flex justify-between items-center mb-4">
            <div>
              <h2 className={`font-semibold text-sm mb-0.5 ${darkMode ? "text-white" : "text-slate-800"}`}>
                Export Preview
              </h2>
              <p className={`text-xs ${darkMode ? "text-slate-400" : "text-slate-500"}`}>
                {activeIssues.length} records
              </p>
            </div>
            <button
              onClick={mexwfExport}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-colors ${darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-100 text-slate-700 hover:bg-slate-200"}`}
            >
              <Wrench size={14} /> Configure Columns
            </button>
          </div>

          <div className={`overflow-x-auto h-[600px] rounded-lg border ${darkMode ? "border-slate-700" : "border-slate-200"}`}>
            <table className="w-full text-left text-xs whitespace-nowrap">
              <thead className={`sticky top-0 z-10 ${darkMode ? "bg-slate-800" : "bg-slate-50"}`}>
                <tr>
                  {exportCols.map(col => (
                    <th key={col} className={`p-3 font-semibold text-[11px] uppercase tracking-wide ${darkMode ? "text-slate-400 border-b border-slate-700" : "text-slate-500 border-b border-slate-200"}`}>
                      {colHeaderMap[col] || col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className={darkMode ? "bg-slate-900" : "bg-white"}>
                {activeIssues.map((issue, idx) => {
                  return (
                    <tr key={idx} className={`transition-colors ${darkMode ? "hover:bg-slate-800/50 border-b border-slate-800" : "hover:bg-slate-50 border-b border-slate-100"}`}>
                      {exportCols.map(col => {
                        let fendralis = issue[col] !== undefined && issue[col] !== null ? String(issue[col]) : "";
                        if (["ID", "Project ID", "Projects"].includes(col) && fendralis === "") fendralis = "NA";
                        if ((col === "AffectedAsset" || col === "AssetName") && fendralis) {
                          fendralis = getShortAssetName(fendralis);
                        }
                        if (col === "VulnDescription" && (!fendralis || fendralis === "—" || fendralis.toLowerCase() === "na")) {
                          fendralis = generateVulnDescription(issue as Issue);
                        }
                        return (
                          <td key={col} className={`p-3 min-w-[120px] whitespace-normal ${darkMode ? "text-slate-300" : "text-slate-600"}`}>
                            {fendralis || "—"}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
                {activeIssues.length === 0 && (
                  <tr>
                    <td colSpan={exportCols.length || 1} className={`p-8 text-center ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                      No data matches current filters
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-5 mb-8">
            <Card
              title="Total Vulnerabilities"
              // richyrik
              val={mexwf.stats?.total || 0}
              Icon={Bug}
              color="text-indigo-500"
              bg={darkMode ? "bg-slate-800 border-slate-700" : "bg-white"}
            />
            <Card
              title="Unique CVEs"
              val={mexwf.stats?.uniqueVulns || 0}
              Icon={Shield}
              color="text-purple-600"
              bg={darkMode ? "bg-slate-800 border-slate-700" : "bg-white"}
            />
            <Card
              title="Affected Assets"
              val={mexwf.stats?.uniqueAssets || 0}
              Icon={Server}
              color="text-blue-600"
              bg={darkMode ? "bg-slate-800 border-slate-700" : "bg-white"}
            />
            <Card
              title="Critical Risks"
              val={mexwf.stats?.criticalOpen || 0}
              Icon={AlertTriangle}
              color="text-amber-500"
              bg={darkMode ? "bg-slate-800 border-slate-700" : "bg-white"}
            />
            <Card
              title="SLA Breached"
              val={mexwf.stats?.breached || 0}
              Icon={Flame}
              color="text-red-500"
              bg={darkMode ? "bg-slate-800 border-slate-700" : "bg-white"}
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            <div className={`p-6 rounded-2xl border shadow-sm transition-all duration-300 hover:shadow-md ${darkMode ? "bg-slate-800/80 border-slate-700/50" : "bg-white border-slate-200/60"}`}>
              <h2 className={`font-bold text-sm mb-5 flex items-center gap-2 ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                <div className={`p-1.5 rounded-lg ${darkMode ? "bg-emerald-900/30" : "bg-emerald-50"}`}>
                  <Target size={16} className="text-emerald-500" />
                </div>
                SLA Compliance
              </h2>
              <div className="flex items-center justify-center mb-4">
                <div className="relative w-32 h-32">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="64" cy="64" r="56" stroke={darkMode ? "#374151" : "#e2e8f0"} strokeWidth="12" fill="none" />
                    <circle
                      cx="64" cy="64" r="56"
                      stroke={mexwf.slaComplianceData.compliance >= 80 ? "#10b981" : mexwf.slaComplianceData.compliance >= 60 ? "#f59e0b" : "#ef4444"}
                      strokeWidth="12"
                      fill="none"
                      strokeLinecap="round"
                      strokeDasharray={`${(mexwf.slaComplianceData.compliance / 100) * 351.86} 351.86`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center flex-col">
                    <span className={`text-2xl font-bold ${mexwf.slaComplianceData.compliance >= 80 ? "text-emerald-600" : mexwf.slaComplianceData.compliance >= 60 ? "text-amber-600" : "text-red-600"}`}>
                      {mexwf.slaComplianceData.compliance}%
                    </span>
                    <span className={`text-[10px] ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Compliance</span>
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className={`p-2 rounded ${darkMode ? "bg-slate-700" : "bg-slate-50"}`}>
                  <p className={`text-lg font-bold ${darkMode ? "text-slate-200" : "text-slate-800"}`}>{mexwf.slaComplianceData.total}</p>
                  <p className={`text-[10px] ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Total Resolved</p>
                </div>
                <div className={`p-2 rounded ${darkMode ? "bg-emerald-900/30" : "bg-emerald-50"}`}>
                  <p className="text-lg font-bold text-emerald-600">{mexwf.slaComplianceData.onTime}</p>
                  <p className={`text-[10px] ${darkMode ? "text-emerald-400" : "text-emerald-600"}`}>On Time</p>
                </div>
                <div className={`p-2 rounded ${darkMode ? "bg-red-900/30" : "bg-red-50"}`}>
                  <p className="text-lg font-bold text-red-600">{mexwf.slaComplianceData.breached}</p>
                  <p className={`text-[10px] ${darkMode ? "text-red-400" : "text-red-600"}`}>Breached</p>
                </div>
              </div>
            </div>

            <div className={`p-5 rounded border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
              <h2 className={`font-semibold text-sm mb-4 flex items-center gap-2 ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                <Clock size={16} className="text-blue-500" /> Vulnerability Age Distribution
              </h2>
              <div className="h-48 flex items-center justify-center">
                {mexwf.ageDistributionData && mexwf.ageDistributionData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={mexwf.ageDistributionData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} stroke={darkMode ? "#374151" : "#e2e8f0"} />
                      <XAxis type="number" hide />
                      <YAxis dataKey="name" type="category" width={80} tick={{ fontSize: 11, fill: darkMode ? "#9ca3af" : "#64748b" }} axisLine={false} tickLine={false} />
                      <RechartsTooltip contentStyle={{ fontSize: "12px", border: "1px solid #e2e8f0", borderRadius: "4px", backgroundColor: darkMode ? "#1f2937" : "#fff" }} />
                      <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={20}>
                        {mexwf.ageDistributionData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={index === 3 ? "#ef4444" : index === 2 ? "#f59e0b" : "#3b82f6"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <p className={`text-xs uppercase font-semibold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>No open vulnerabilities</p>
                )}
              </div>
            </div>

            <div className={`p-5 rounded-2xl border shadow-sm transition-all duration-300 hover:shadow-md ${darkMode ? "bg-slate-800/80 border-slate-700/50" : "bg-white border-slate-200/60"}`}>
              <h2 className={`font-bold text-sm mb-5 flex items-center gap-2 ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                <div className={`p-1.5 rounded-lg ${darkMode ? "bg-blue-900/30" : "bg-blue-50"}`}>
                  <CheckCircle size={16} className="text-blue-500" />
                </div>
                Resolution Tracking
              </h2>
              <div className="flex flex-col justify-between h-48">
                <div className={`flex items-center justify-between px-4 py-2 rounded-lg border ${darkMode ? "bg-slate-900/50 border-slate-700" : "bg-white border-slate-200"}`}>
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-0.5">Open</p>
                    <p className={`text-lg font-bold ${darkMode ? "text-white" : "text-slate-800"}`}>{mexwf.pipeline?.open || 0}</p>
                  </div>
                  <div className={`p-1.5 rounded-md ${darkMode ? "bg-slate-800" : "bg-slate-100"}`}>
                    <AlertCircle size={16} className="text-slate-500" />
                  </div>
                </div>

                <div className={`flex items-center justify-between px-4 py-2 rounded-lg border ${darkMode ? "bg-slate-900/50 border-slate-700" : "bg-white border-slate-200"}`}>
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-0.5">In Progress</p>
                    <p className={`text-lg font-bold ${darkMode ? "text-white" : "text-slate-800"}`}>{mexwf.pipeline?.progress || 0}</p>
                  </div>
                  <div className={`p-1.5 rounded-md ${darkMode ? "bg-slate-800" : "bg-slate-100"}`}>
                    <Clock size={16} className="text-slate-500" />
                  </div>
                </div>

                <div className={`flex items-center justify-between px-4 py-2 rounded-lg border ${darkMode ? "bg-slate-900/50 border-slate-700" : "bg-white border-slate-200"}`}>
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-0.5">Resolved</p>
                    <p className={`text-lg font-bold ${darkMode ? "text-white" : "text-slate-800"}`}>{mexwf.pipeline?.resolved || 0}</p>
                  </div>
                  <div className={`p-1.5 rounded-md ${darkMode ? "bg-slate-800" : "bg-slate-100"}`}>
                    <CheckCircle size={16} className="text-slate-500" />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className={`p-5 rounded border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
            <h2 className={`font-semibold text-sm mb-4 flex items-center gap-2 ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
              <Zap size={16} className="text-amber-500" /> Risk Heatmap: Severity vs Department
            </h2>
            {mexwf.riskHeatmapData.depts.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr>
                      <th className={`p-2 text-left font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Department</th>
                      {mexwf.riskHeatmapData.severities.map(sev => (
                        <th key={sev} className={`p-2 text-center font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>{sev}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {mexwf.riskHeatmapData.depts.map(dept => (
                      <tr key={dept} className={darkMode ? "border-t border-slate-700" : "border-t border-slate-100"}>
                        <td className={`p-2 font-medium ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{dept}</td>
                        {mexwf.riskHeatmapData.severities.map(sev => {
                          const count = mexwf.riskHeatmapData.heatmap[dept]?.[sev] || 0;
                          const intensity = count === 0 ? "bg-slate-100" : count <= 2 ? "bg-yellow-100" : count <= 5 ? "bg-orange-200" : "bg-red-300";
                          const darkIntensity = count === 0 ? "bg-slate-700" : count <= 2 ? "bg-yellow-900/50" : count <= 5 ? "bg-orange-900/50" : "bg-red-900/50";
                          return (
                            <td key={sev} className={`p-2 text-center ${darkMode ? darkIntensity : intensity} rounded`}>
                              <span className={`font-bold ${count > 0 ? (darkMode ? "text-white" : "text-slate-800") : (darkMode ? "text-slate-500" : "text-slate-400")}`}>
                                {count}
                              </span>
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className={`text-xs text-center py-4 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>No data available for heatmap</p>
            )}
          </div>

          <div className={`p-5 rounded-sm border shadow-sm mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
            <div className="flex items-center justify-between mb-4 border-b pb-3" style={{ borderColor: darkMode ? "#374151" : "#f1f5f9" }}>
              <h2 className={`font-semibold text-sm flex items-center gap-2 ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                <Activity size={16} className={darkMode ? "text-slate-500" : "text-slate-400"} /> Asset
                Resolution Pipeline (MTTR)
              </h2>
              <span className="text-xs font-medium text-slate-500">
                Resolution Velocity:{" "}
                <strong className="text-slate-800">
                  {mexwf.stats?.total > 0 && mexwf.pipeline?.resolved !== undefined
                    ? ((mexwf.pipeline.resolved / mexwf.stats.total) * 100).toFixed(1)
                    : 0}
                  %
                </strong>
              </span>
            </div>
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex-1 w-full border border-slate-200 p-4 rounded-md flex justify-between items-center bg-slate-50">
                <p className="text-sm font-medium text-slate-600">
                  Open Assets
                </p>
                <p className="text-lg font-bold text-slate-800">
                  {mexwf.pipeline?.open || 0}
                </p>
              </div>
              <ArrowRight
                className="text-slate-400 hidden sm:block"
                size={16}
              />
              <div className="flex-1 w-full border border-blue-200 p-4 rounded-md flex justify-between items-center bg-blue-50/30">
                <p className="text-sm font-medium text-blue-700">In Progress</p>
                <p className="text-lg font-bold text-blue-800">
                  {mexwf.pipeline?.progress || 0}
                </p>
              </div>
              <ArrowRight
                className="text-slate-400 hidden sm:block"
                size={16}
              />
              <div className="flex-1 w-full border border-emerald-200 p-4 rounded-md flex justify-between items-center bg-emerald-50/30">
                <p className="text-sm font-medium text-emerald-700">Resolved</p>
                <p className="text-lg font-bold text-emerald-800">
                  {mexwf.pipeline?.resolved || 0}
                </p>
              </div>
            </div>
            <div className="mt-4 h-1.5 w-full bg-slate-100 rounded-sm overflow-hidden flex">
              <div
                style={{
                  width: `${mexwf.stats?.total > 0 && mexwf.pipeline?.open !== undefined
                    ? (mexwf.pipeline.open / mexwf.stats.total) * 100
                    : 0
                    }%`,
                }}
                className="bg-slate-400 h-full"
              />
              <div
                style={{
                  width: `${mexwf.stats?.total > 0 && mexwf.pipeline?.progress !== undefined
                    ? (mexwf.pipeline.progress / mexwf.stats.total) * 100
                    : 0
                    }%`,
                }}
                className="bg-blue-500 h-full"
              />
              <div
                style={{
                  width: `${mexwf.stats?.total > 0 && mexwf.pipeline?.resolved !== undefined
                    ? (mexwf.pipeline.resolved / mexwf.stats.total) * 100
                    : 0
                    }%`,
                }}
                className="bg-emerald-500 h-full"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
            <div className={`p-5 rounded border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
              <h2 className={`font-semibold text-sm mb-4 border-b pb-2 ${darkMode ? "text-slate-200 border-slate-700" : "text-slate-800 border-slate-100"}`}>
                Criticality Status
              </h2>
              <div className="flex flex-col items-center">
                <div className="h-48 w-full flex items-center justify-center">
                  {mexwf.severityPieData.data && mexwf.severityPieData.data.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={mexwf.severityPieData.data}
                          innerRadius={50}
                          outerRadius={70}
                          paddingAngle={2}
                          dataKey="value"
                        >
                          {mexwf.severityPieData.data.map((entry, index) => (
                            <Cell
                              key={`cell-${index}`}
                              fill={entry.color || "#000"}
                            />
                          ))}
                        </Pie>
                        <RechartsTooltip
                          contentStyle={{
                            fontSize: "12px",
                            border: "1px solid #e2e8f0",
                            borderRadius: "4px",
                            backgroundColor: darkMode ? "#1f2937" : "#fff",
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className={`text-xs uppercase font-semibold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                      No issues
                    </p>
                  )}
                </div>
                {mexwf.severityPieData.allData && mexwf.severityPieData.allData.length > 0 && (
                  <>
                    <div className="flex flex-wrap justify-center gap-3 mt-2">
                      {mexwf.severityPieData.allData.filter(item => item.value > 0).map((item) => (
                        <div key={item.name} className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }}></div>
                          <span className={`text-xs font-semibold ${darkMode ? "text-slate-300" : "text-slate-600"}`}>
                            {item.name}: {item.value}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div className={`mt-3 pt-2 border-t text-center ${darkMode ? "border-slate-700" : "border-slate-200"}`}>
                      <span className={`text-sm font-bold ${darkMode ? "text-slate-200" : "text-slate-700"}`}>
                        Total Vulnerabilities: {mexwf.severityPieData.total}
                      </span>
                    </div>
                  </>
                )}
              </div>
            </div>
            <div className={`lg:col-span-2 p-5 rounded border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
              <h2 className={`font-semibold text-sm mb-4 border-b pb-2 ${darkMode ? "text-slate-200 border-slate-700" : "text-slate-800 border-slate-100"}`}>
                Vulnerability Types
              </h2>
              <div className="h-64 flex items-center justify-center">
                {typeChartData && typeChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={typeChartData}
                      margin={{ left: 10, right: 20 }}
                    >
                      <CartesianGrid
                        strokeDasharray="3 3"
                        horizontal={true}
                        vertical={false}
                        stroke="#e2e8f0"
                      />
                      <XAxis type="number" hide />
                      <YAxis
                        dataKey="name"
                        type="category"
                        width={150}
                        tick={{ fontSize: 11, fill: "#64748b" }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <RechartsTooltip
                        cursor={{ fill: "#f1f5f9" }}
                        contentStyle={{
                          fontSize: "12px",
                          border: "1px solid #e2e8f0",
                          borderRadius: "4px",
                        }}
                      />
                      <Bar
                        dataKey="Issues"
                        fill="#3b82f6"
                        radius={[0, 2, 2, 0]}
                        barSize={20}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <p className="text-slate-400 text-xs uppercase font-semibold">
                    No active data
                  </p>
                )}
              </div>
            </div>
          </div>

          {(currentFormat === "CONTAINER" || selectedFormatFilter === "CONTAINER") && (
            <div className={`p-5 rounded border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
              <div className="flex items-center justify-between mb-4 border-b pb-2" style={{ borderColor: darkMode ? "#374151" : "#f1f5f9" }}>
                <h2 className={`font-semibold text-sm ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                  Container Sub-Types
                  {selectedOwners.length > 0 && (
                    <span className="text-xs text-slate-500 font-normal ml-2">
                      (Filtered by Owner)
                    </span>
                  )}
                </h2>
              </div>

              {/* richyrik - Checkboxes moved to Advanced Search panel; Sub-Type metric cards retained below */}

              {/* richyrik - Sub-Type metric cards replacing the error placeholder */}
              <div className="mb-6">
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                  {(["Zero day VA", "Wiz CLI Integration", "Compliance VA", "Quarterly VA", "Unclassified"] as const).map(subtype => {
                    const colorMap: Record<string, string> = {
                      "Zero day VA": "bg-red-50 border-red-200 text-red-700",
                      "Wiz CLI Integration": "bg-violet-50 border-violet-200 text-violet-700",
                      "Compliance VA": "bg-amber-50 border-amber-200 text-amber-700",
                      "Quarterly VA": "bg-sky-50 border-sky-200 text-sky-700",
                      "Unclassified": "bg-slate-50 border-slate-200 text-slate-600",
                    };
                    const darkColorMap: Record<string, string> = {
                      "Zero day VA": "bg-red-900/20 border-red-800 text-red-300",
                      "Wiz CLI Integration": "bg-violet-900/20 border-violet-800 text-violet-300",
                      "Compliance VA": "bg-amber-900/20 border-amber-800 text-amber-300",
                      "Quarterly VA": "bg-sky-900/20 border-sky-800 text-sky-300",
                      "Unclassified": "bg-slate-700/40 border-slate-600 text-slate-400",
                    };
                    const isSelected = selectedContainerSubTypes.includes(subtype);
                    const colorClass = darkMode ? darkColorMap[subtype] : colorMap[subtype];
                    return (
                      <button
                        key={subtype}
                        onClick={() => setSelectedContainerSubTypes(prev =>
                          isSelected ? prev.filter(s => s !== subtype) : [...prev, subtype]
                        )}
                        className={`flex flex-col items-start p-3 rounded-lg border-2 transition-all cursor-pointer text-left w-full ${isSelected
                            ? `${colorClass} ring-2 ring-offset-1 ${darkMode ? "ring-slate-400" : "ring-slate-500"}`
                            : `${colorClass} opacity-80 hover:opacity-100`
                          }`}
                      >
                        <span className="text-2xl font-bold tabular-nums">
                          {containerSubtypeStats[subtype] ?? 0}
                        </span>
                        <span className="text-xs font-semibold mt-1 leading-tight">{subtype}</span>
                        {isSelected && (
                          <span className="mt-1 text-[10px] font-medium opacity-70">● Filtering</span>
                        )}
                      </button>
                    );
                  })}
                </div>
                {selectedContainerSubTypes.length > 0 && (
                  <button
                    onClick={() => setSelectedContainerSubTypes([])}
                    className="mt-2 text-xs text-blue-500 hover:text-blue-700 underline"
                  >
                    Clear sub-type filter
                  </button>
                )}
              </div>

              <div className="h-80 mt-6">
                {containerChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={containerChartData}
                      margin={{ left: 20, right: 30, bottom: 80 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={darkMode ? "#374151" : "#e2e8f0"} />
                      <XAxis
                        dataKey="name"
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: darkMode ? '#94a3b8' : '#64748b', fontSize: 12 }}
                        angle={-45}
                        textAnchor="end"
                      />
                      <YAxis
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: darkMode ? '#94a3b8' : '#64748b', fontSize: 12 }}
                      />
                      <RechartsTooltip
                        cursor={{ fill: darkMode ? "#374151" : "#f1f5f9" }}
                        contentStyle={{
                          backgroundColor: darkMode ? "#1e293b" : "#fff",
                          borderColor: darkMode ? "#374151" : "#e2e8f0",
                          color: darkMode ? "#e2e8f0" : "#1e293b",
                          fontSize: "12px",
                          borderRadius: "4px",
                        }}
                      />
                      <Bar
                        dataKey="value"
                        fill="#8b5cf6"
                        radius={[0, 4, 4, 0]}
                        barSize={30}
                        onClick={(data) => {
                          if (!data || !data.name) return;
                          const subtype = data.name;
                          setSelectedContainerSubTypes(prev => {
                            if (prev.includes(subtype)) {
                              return prev.filter(s => s !== subtype);
                            } else {
                              return [...prev, subtype];
                            }
                          });
                        }}
                        style={{ cursor: "pointer" }}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full">
                    <p className="text-slate-400 text-sm">No data available for {selectedOwners.length > 0 ? selectedOwners.join(", ") : "All"}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {(currentFormat === "CSPM" || selectedFormatFilter === "CSPM") && cspmFindingChartData.length > 0 && (

            <div className={`p-5 rounded border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
              <div className="flex items-center justify-between mb-4 border-b pb-2" style={{ borderColor: darkMode ? "#374151" : "#f1f5f9" }}>
                <h2 className={`font-semibold text-sm ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                  CSPM Findings by Type
                </h2>
                {selectedFindingTypes.length > 0 && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-slate-500">Filtered:</span>
                    {selectedFindingTypes.map(ft => (
                      <span key={ft} className="px-2 py-1 bg-green-100 text-green-700 text-xs font-medium rounded flex items-center gap-1">
                        {ft.length > 20 ? ft.substring(0, 20) + "..." : ft}
                        <button onClick={() => setSelectedFindingTypes(prev => prev.filter(t => t !== ft))} className="ml-1 hover:text-green-900">✕</button>
                      </span>
                    ))}
                    {selectedFindingTypes.length > 1 && (
                      <button onClick={() => setSelectedFindingTypes([])} className="text-xs text-slate-500 hover:text-slate-700">Clear all</button>
                    )}
                  </div>
                )}
              </div>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={cspmFindingChartData}
                    margin={{ left: 20, right: 30, bottom: 80 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={darkMode ? "#374151" : "#e2e8f0"} />
                    <XAxis
                      dataKey="name"
                      tick={{ fontSize: 10, fill: darkMode ? "#9ca3af" : "#64748b" }}
                      angle={-45}
                      textAnchor="end"
                      height={80}
                      interval={0}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fontSize: 11, fill: darkMode ? "#9ca3af" : "#64748b" }}
                      axisLine={false}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <RechartsTooltip
                      cursor={{ fill: darkMode ? "#374151" : "#f1f5f9" }}
                      contentStyle={{
                        fontSize: "12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "4px",
                        backgroundColor: darkMode ? "#1f2937" : "#fff",
                      }}
                      formatter={(value) => [`${value} issues`, "Click to filter"]}
                    />
                    <Bar
                      dataKey="count"
                      name="Count"
                      radius={[4, 4, 0, 0]}
                      barSize={40}
                      cursor="pointer"
                      onClick={(data) => {
                        if (data && data.name) {
                          const fendralis = String(data.name);
                          setSelectedFindingTypes(prev =>
                            prev.includes(fendralis)
                              ? prev.filter(t => t !== fendralis)
                              : [...prev, fendralis]
                          );
                        }
                      }}
                    >
                      {cspmFindingChartData.map((entry: { name: string }, index: number) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={selectedFindingTypes.includes(entry.name) ? "#16a34a" : "#3b82f6"}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {currentFormat !== "CSPM" && (
            <div className="bg-white p-5 rounded-sm border border-slate-200 shadow-sm mb-6">
              <h2 className="font-semibold text-slate-800 text-sm mb-4 border-b border-slate-100 pb-2">
                Discovery Timeline
              </h2>
              <div className="h-64 flex items-center justify-center">
                {timelineChartData && timelineChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                      data={timelineChartData}
                      margin={{ bottom: 30, right: 20, top: 10 }}
                    >
                      <defs>
                        <linearGradient
                          id="colorIssues"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop
                            offset="5%"
                            stopColor="#ef4444"
                            stopOpacity={0.4}
                          />
                          <stop
                            offset="95%"
                            stopColor="#ef4444"
                            stopOpacity={0}
                          />
                        </linearGradient>
                      </defs>
                      <CartesianGrid
                        strokeDasharray="3 3"
                        vertical={false}
                        stroke="#e2e8f0"
                      />
                      <XAxis
                        dataKey="date"
                        tick={{ fontSize: 11, fill: "#64748b" }}
                        angle={-45}
                        textAnchor="end"
                        height={50}
                        axisLine={false}
                        tickLine={false}
                      />
                      <YAxis
                        allowDecimals={false}
                        tick={{ fontSize: 11, fill: "#64748b" }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <RechartsTooltip content={<CustomTimelineTooltip />} />
                      <Area
                        type="monotone"
                        dataKey="Issues"
                        stroke="#ef4444"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#colorIssues)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <p className="text-slate-400 text-xs uppercase font-semibold">
                    No active data
                  </p>
                )}
              </div>
            </div>
          )}

          <div className={`p-5 rounded border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
            <div className="flex items-center justify-between mb-4 border-b pb-2">
              <h2 className={`font-semibold text-sm ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                Workload & Risk Distribution by Assigned Owner
              </h2>
              {selectedOwners.length > 0 && (
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs text-slate-500">Filtered:</span>
                  {selectedOwners.map(owner => (
                    <span key={owner} className="px-2 py-1 bg-blue-100 text-blue-700 text-xs font-medium rounded flex items-center gap-1">
                      {owner}
                      <button onClick={() => setSelectedOwners(prev => prev.filter(o => o !== owner))} className="ml-1 hover:text-blue-900">✕</button>
                    </span>
                  ))}
                  {selectedOwners.length > 1 && (
                    <button onClick={() => setSelectedOwners([])} className="text-xs text-slate-500 hover:text-slate-700">Clear all</button>
                  )}
                </div>
              )}
            </div>
            <div className="h-72 flex items-center justify-center">
              {ownerChartData && ownerChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={ownerChartData}
                    margin={{ top: 10, right: 30, left: 0, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                    <XAxis
                      dataKey="name"
                      tick={{ fontSize: 11, fill: "#64748b" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fontSize: 11, fill: "#64748b" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <RechartsTooltip
                      cursor={{ fill: "#f1f5f9" }}
                      contentStyle={{
                        fontSize: "12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "4px",
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: "12px" }} />
                    <Bar
                      dataKey="Critical"
                      stackId="a"
                      fill="#dc2626"
                      barSize={30}
                      cursor="pointer"
                      onClick={(data) => toggleOwner(data?.name)}
                    />
                    <Bar
                      dataKey="High"
                      stackId="a"
                      fill="#f97316"
                      cursor="pointer"
                      onClick={(data) => toggleOwner(data?.name)}
                    />
                    <Bar
                      dataKey="Medium"
                      stackId="a"
                      fill="#eab308"
                      cursor="pointer"
                      onClick={(data) => toggleOwner(data?.name)}
                    />
                    <Bar
                      dataKey="Low"
                      stackId="a"
                      fill="#3b82f6"
                      radius={[4, 4, 0, 0]}
                      cursor="pointer"
                      onClick={(data) => toggleOwner(data?.name)}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-slate-400 text-xs uppercase font-semibold">
                  No active data
                </p>
              )}
            </div>
          </div>

          <div className={`p-5 rounded border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
            <div className="flex items-center justify-between mb-4 border-b pb-2">
              <h2 className={`font-semibold text-sm ${darkMode ? "text-slate-200" : "text-slate-800"}`}>Risk Distribution by Cluster</h2>
            </div>
            <div className="h-72 flex items-center justify-center">
              {clusterChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={clusterChartData} margin={{ top: 10, right: 30, left: 0, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={darkMode ? "#374151" : "#e2e8f0"} />
                    <XAxis dataKey="name" tick={{ fontSize: 11, fill: darkMode ? "#9ca3af" : "#64748b" }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fontSize: 11, fill: darkMode ? "#9ca3af" : "#64748b" }} axisLine={false} tickLine={false} />
                    <RechartsTooltip cursor={{ fill: darkMode ? "#374151" : "#f1f5f9" }} contentStyle={{ fontSize: "12px", border: "1px solid #e2e8f0", borderRadius: "4px", backgroundColor: darkMode ? "#1f2937" : "#fff" }} />
                    <Legend wrapperStyle={{ fontSize: "12px" }} />
                    <Bar dataKey="Critical" stackId="a" fill="#dc2626" barSize={30} />
                    <Bar dataKey="High" stackId="a" fill="#f97316" />
                    <Bar dataKey="Medium" stackId="a" fill="#eab308" />
                    <Bar dataKey="Low" stackId="a" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <p className="text-slate-400 text-xs uppercase font-semibold">No active data</p>}
            </div>
          </div>

          {(currentFormat === "VAPT" || selectedFormatFilter === "VAPT") && lobChartData.length > 0 && (
            <div className={`p-5 rounded border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
              <div className="flex items-center justify-between mb-4 border-b pb-2">
                <h2 className={`font-semibold text-sm ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                  Risk Distribution by LOB Name
                </h2>
                {selectedLOBs.length > 0 && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-slate-500">Filtered:</span>
                    {selectedLOBs.map(lob => (
                      <span key={lob} className="px-2 py-1 bg-orange-100 text-orange-700 text-xs font-medium rounded flex items-center gap-1">
                        {lob.length > 15 ? lob.substring(0, 15) + "..." : lob}
                        <button onClick={() => setSelectedLOBs(prev => prev.filter(l => l !== lob))} className="ml-1 hover:text-orange-900">✕</button>
                      </span>
                    ))}
                    {selectedLOBs.length > 1 && (
                      <button onClick={() => setSelectedLOBs([])} className="text-xs text-slate-500 hover:text-slate-700">Clear all</button>
                    )}
                  </div>
                )}
              </div>
              <div className="h-72 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={lobChartData}
                    margin={{ top: 10, right: 30, left: 0, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={darkMode ? "#374151" : "#e2e8f0"} />
                    <XAxis
                      dataKey="name"
                      tick={{ fontSize: 11, fill: darkMode ? "#9ca3af" : "#64748b" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fontSize: 11, fill: darkMode ? "#9ca3af" : "#64748b" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <RechartsTooltip
                      cursor={{ fill: darkMode ? "#374151" : "#f1f5f9" }}
                      contentStyle={{
                        fontSize: "12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "4px",
                        backgroundColor: darkMode ? "#1f2937" : "#fff",
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: "12px" }} />
                    <Bar
                      dataKey="Critical"
                      stackId="a"
                      fill="#dc2626"
                      barSize={30}
                      cursor="pointer"
                      onClick={(data) => toggleLOB(data?.name)}
                    />
                    <Bar
                      dataKey="High"
                      stackId="a"
                      fill="#f97316"
                      cursor="pointer"
                      onClick={(data) => toggleLOB(data?.name)}
                    />
                    <Bar
                      dataKey="Medium"
                      stackId="a"
                      fill="#eab308"
                      cursor="pointer"
                      onClick={(data) => toggleLOB(data?.name)}
                    />
                    <Bar
                      dataKey="Low"
                      stackId="a"
                      fill="#3b82f6"
                      radius={[4, 4, 0, 0]}
                      cursor="pointer"
                      onClick={(data) => toggleLOB(data?.name)}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          <SecurityAgent contextData={displayedIssues} />

          <div className={`rounded border overflow-hidden z-30 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
            <div className={`p-4 border-b flex flex-col xl:flex-row xl:items-center justify-between gap-4 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
              <div className="flex items-center gap-4 flex-1">
                <div className={`flex items-center gap-2 font-semibold text-sm border-r pr-4 ${darkMode ? "text-slate-200 border-slate-600" : "text-slate-800 border-slate-300"}`}>
                  <Filter size={14} className="text-slate-500" />
                  Vulnerability Groups
                </div>
                <div className="flex gap-2 w-full max-w-sm">
                  <input
                    type="text"
                    placeholder="Search vulnerabilities..."
                    className={`flex-1 px-3 py-1.5 rounded border text-sm focus:border-purple-500 outline-none ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300"}`}
                    value={localSearch}
                    onChange={(e) => setLocalSearch(e.target.value)}
                  />
                  {/* richyrik: Modified button to include Filter icon */}
                  <button
                    onClick={() => setIsAdvancedSearchOpen(!isAdvancedSearchOpen)}
                    className={`px-3 py-1.5 rounded border text-xs font-semibold flex items-center gap-1 transition-colors ${isAdvancedSearchOpen
                      ? "bg-purple-100 border-purple-300 text-purple-700"
                      : darkMode
                        ? "bg-slate-800 border-slate-600 text-slate-300 hover:bg-slate-700"
                        : "bg-white border-slate-300 text-slate-700 hover:bg-slate-50"
                      }`}
                  >
                    <Filter size={14} />
                    Advanced Search <ChevronDown size={14} className={`transition-transform ${isAdvancedSearchOpen ? "rotate-180" : ""}`} />
                  </button>
                </div>

                <div className="relative" ref={tableColDropdownRef}>
                  <button
                    onClick={() => setIsTableColDropdownOpen(!isTableColDropdownOpen)}
                    className="flex items-center gap-2 px-3 py-1.5 bg-white border border-slate-300 rounded-sm text-xs font-semibold hover:bg-slate-50 transition-colors shadow-sm ml-2"
                  >
                    <Layers size={14} className="text-purple-600" />
                    <span>View Columns ({tableCols.length})</span>
                    <ChevronDown
                      size={14}
                      className={`transition-transform ${isTableColDropdownOpen ? "rotate-180" : ""}`}
                    />
                  </button>

                  {isTableColDropdownOpen && (
                    <div className="absolute left-0 mt-2 w-72 bg-white border border-slate-200 shadow-xl rounded-md z-[9999] overflow-hidden">
                      <div className="p-2 border-b border-slate-100 bg-slate-50 flex justify-between gap-2">
                        <button
                          onClick={() => setTableCols(tableAvailableCols)}
                          className="text-[10px] uppercase font-bold text-purple-600 hover:text-purple-800 px-2 py-1"
                        >
                          Select All
                        </button>
                        <button
                          onClick={() => setTableCols(defaultTableCols)}
                          className="text-[10px] uppercase font-bold text-slate-500 hover:text-slate-800 px-2 py-1"
                        >
                          Default
                        </button>
                      </div>
                      <div className="max-h-80 overflow-y-auto py-1 p-2 grid grid-cols-1 gap-1">
                        {tableAvailableCols.map((col) => (
                          <label
                            key={col}
                            className="flex items-center gap-3 px-2 py-1.5 hover:bg-purple-50 cursor-pointer rounded transition-colors"
                          >
                            <input
                              type="checkbox"
                              checked={tableCols.includes(col)}
                              onChange={() => {
                                setTableCols((prev) =>
                                  prev.includes(col)
                                    ? prev.filter((c) => c !== col)
                                    : [...prev, col]
                                );
                              }}
                              className="rounded border-slate-300 text-purple-600 focus:ring-purple-500 w-3.5 h-3.5"
                            />
                            <span className="text-xs font-semibold text-slate-700 truncate">
                              {colHeaderMap[col] || col}
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div className="relative" ref={dropdownRef}>
                  <button
                    onClick={() => setIsBatchDropdownOpen(!isBatchDropdownOpen)}
                    className="flex items-center gap-2 px-3 py-1.5 bg-white border border-slate-300 rounded-sm text-xs font-semibold hover:bg-slate-50 transition-colors shadow-sm"
                  >
                    <Layers size={14} className="text-blue-600" />
                    <span>Datasets ({selectedBatches?.length || 0})</span>
                    <ChevronDown
                      size={14}
                      className={`transition-transform ${isBatchDropdownOpen ? "rotate-180" : ""
                        }`}
                    />
                  </button>

                  {isBatchDropdownOpen && (
                    <div className="absolute right-0 mt-2 w-72 bg-white border border-slate-200 shadow-xl rounded-md z-[9999] overflow-hidden">
                      <div className="p-2 border-b border-slate-100 bg-slate-50 flex justify-between gap-2">
                        <button
                          onClick={() => setSelectedBatches(batches)}
                          className="text-[10px] uppercase font-bold text-blue-600 hover:text-blue-800 px-2 py-1"
                        >
                          Select All
                        </button>
                        <button
                          onClick={() =>
                            batches &&
                            batches.length > 0 &&
                            setSelectedBatches([batches[0]])
                          }
                          className="text-[10px] uppercase font-bold text-slate-500 hover:text-slate-800 px-2 py-1"
                        >
                          Latest Only
                        </button>
                      </div>
                      <div className="max-h-60 overflow-y-auto py-1">
                        {batches &&
                          batches.map((batch) => {
                            const format = batchFormats[batch] || "CONTAINER";
                            return (
                              <div
                                key={batch}
                                onClick={() => toggleBatch(batch)}
                                className="flex items-center gap-3 px-4 py-2 hover:bg-blue-50 cursor-pointer transition-colors border-b border-slate-50 last:border-0"
                              >
                                {selectedBatches.includes(batch) ? (
                                  <CheckSquare
                                    size={16}
                                    className="text-blue-600"
                                  />
                                ) : (
                                  <Square size={16} className="text-slate-300" />
                                )}
                                {/* richyrik: prepend "VUL - " to every dataset name in the dropdown */}
                                <span
                                  className={`text-xs flex-1 ${selectedBatches.includes(batch)
                                    ? "font-bold text-slate-900"
                                    : "text-slate-600"
                                    }`}
                                >
                                  {`VUL - ${batch}`}
                                </span>
                                <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${format === "SAST_DAST" ? "bg-purple-100 text-purple-700" :
                                  format === "CSPM" ? "bg-green-100 text-green-700" :
                                    format === "VAPT" ? "bg-orange-100 text-orange-700" :
                                      "bg-blue-100 text-blue-700"
                                  }`}>
                                  {format === "SAST_DAST" ? "SAST/DAST" : format}
                                </span>
                              </div>
                            )
                          })}
                      </div>
                      {userRole === "Admin" && (
                        <div className="p-2 bg-slate-50 border-t border-slate-100">
                          <button
                            onClick={handleDeleteSelectedBatches}
                            className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-red-50 text-red-700 rounded text-[10px] font-bold uppercase hover:bg-red-100 transition-colors"
                          >
                            <Trash2 size={12} /> Delete Selected
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>





                {userRole === "Admin" && (
                  <>
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileSelect}
                      className="hidden"
                    />
                    <button
                      onClick={() => fileInputRef.current?.click()}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-sm border border-blue-600 text-xs font-medium bg-blue-50 text-blue-700 hover:bg-blue-100 transition-colors"
                    >
                      <Upload size={14} /> Upload Dataset
                    </button>
                  </>
                )}

                {userRole === "Admin" && (
                  <button
                    onClick={() => setIsAiModalOpen(true)}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-sm border border-purple-600 text-xs font-medium bg-purple-50 text-purple-700 hover:bg-purple-100 transition-colors"
                  >
                    <Bot size={14} /> Send Mail
                  </button>
                )}

                <div className="flex gap-2">
                  <button
                    onClick={mexwfExport}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-sm border border-emerald-600 text-xs font-medium bg-emerald-50 text-emerald-700 hover:bg-emerald-100 transition-colors"
                  >
                    <Download size={14} /> Custom Export
                  </button>

                  <button
                    onClick={exportToPDF}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-sm border border-red-600 text-xs font-medium bg-red-50 text-red-700 hover:bg-red-100 transition-colors"
                  >
                    <FileText size={14} /> PDF
                  </button>
                </div>
              </div>
            </div>

            {/* Advanced Search Panel */}
            {isAdvancedSearchOpen && (
              <div className={`border-b ${darkMode ? "bg-slate-900 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
                <div className="p-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">

                  {/* Assigned To */}
                  <div className="flex flex-col gap-2">
                    <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Assigned To</label>
                    <select
                      value={draftFilters.assignedTo}
                      onChange={e => setDraftFilters(prev => ({ ...prev, assignedTo: e.target.value }))}
                      className={`p-2 rounded-lg border text-sm outline-none ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300"}`}
                    >
                      <option value="All Owners">All Owners</option>
                      <option value="Unassigned">Unassigned</option>
                      {metadataOwners.map(owner => (
                        <option key={owner} value={owner}>{owner}</option>
                      ))}
                    </select>
                  </div>

                  <div className="flex flex-col gap-2">
                    <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Cluster</label>
                    <select value={draftFilters.cluster} onChange={e => setDraftFilters(prev => ({ ...prev, cluster: e.target.value }))} className={`p-2 rounded-lg border text-sm outline-none ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300"}`}>
                      <option value="All Clusters">All Clusters</option>
                      {metadataClusters.map(cluster => <option key={cluster} value={cluster}>{cluster}</option>)}
                    </select>
                  </div>

                  {/* Resolution Status */}
                  <div className="flex flex-col gap-2">
                    <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Resolution Status</label>
                    <select
                      value={draftFilters.resolutionStatus}
                      onChange={e => setDraftFilters(prev => ({ ...prev, resolutionStatus: e.target.value }))}
                      className={`p-2 rounded-lg border text-sm outline-none ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300"}`}
                    >
                      <option value="All">All</option>
                      <option value="Open">Open</option>
                      <option value="Progress">Progress</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>

                  {/* Dataset */}
                  <div className="flex flex-col gap-2">
                    <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Dataset</label>
                    <div className={`flex flex-col gap-1 max-h-32 overflow-y-auto p-2 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
                      {batches.filter(b => draftFilters.format === "All" || (batchFormats[b] || "CONTAINER") === draftFilters.format).map(batch => (
                        <label key={batch} className={`flex items-center gap-2 text-xs cursor-pointer px-1 py-0.5 rounded ${darkMode ? "text-slate-300 hover:bg-slate-700" : "text-slate-700 hover:bg-slate-50"}`}>
                          <input
                            type="checkbox"
                            checked={selectedBatches.includes(batch)}
                            onChange={() => setSelectedBatches(prev => prev.includes(batch) ? prev.filter(b => b !== batch) : [...prev, batch])}
                            className="accent-blue-600"
                          />
                          <span className="truncate" title={batch}>{batch}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Date Range */}
                  <div className="flex flex-col gap-2">
                    <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Date Range</label>
                    <div className={`flex flex-col gap-2 p-2 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
                      <div className="flex items-center gap-2">
                        <label className={`text-xs w-10 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>From</label>
                        <input
                          type="date"
                          value={draftFilters.dateFrom}
                          onChange={e => setDraftFilters(prev => ({ ...prev, dateFrom: e.target.value }))}
                          className={`flex-1 px-2 py-1 rounded border text-xs outline-none ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300"}`}
                        />
                      </div>
                      <div className="flex items-center gap-2">
                        <label className={`text-xs w-10 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>To</label>
                        <input
                          type="date"
                          value={draftFilters.dateTo}
                          onChange={e => setDraftFilters(prev => ({ ...prev, dateTo: e.target.value }))}
                          className={`flex-1 px-2 py-1 rounded border text-xs outline-none ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300"}`}
                        />
                      </div>
                      {(draftFilters.dateFrom || draftFilters.dateTo) && (
                        <button
                          onClick={() => setDraftFilters(prev => ({ ...prev, dateFrom: "", dateTo: "" }))}
                          className={`text-xs text-left ${darkMode ? "text-red-400" : "text-red-600"} hover:underline`}
                        >Clear dates</button>
                      )}
                    </div>
                  </div>

                  {/* Severity */}
                  <div className="flex flex-col gap-2">
                    <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Severity</label>
                    <div className={`flex flex-wrap gap-1.5 p-2 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
                      {["All", "Critical", "High", "Medium", "Low"].map(sev => (
                        <button
                          key={sev}
                          onClick={() => setDraftFilters(prev => ({ ...prev, severity: sev }))}
                          className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${draftFilters.severity === sev
                              ? sev === "Critical" ? "bg-red-600 text-white"
                                : sev === "High" ? "bg-orange-500 text-white"
                                  : sev === "Medium" ? "bg-yellow-500 text-white"
                                    : sev === "Low" ? "bg-blue-500 text-white"
                                      : "bg-slate-600 text-white"
                              : darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                            }`}
                        >{sev}</button>
                      ))}
                    </div>
                  </div>

                  {/* richyrik: Advanced Search - Container Sub-Types */}
                  {selectedFormatFilter === "CONTAINER" && (
                    <div className="flex flex-col gap-2 md:col-span-2 lg:col-span-3">
                      <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-600"}`}>
                        Container Sub-Types
                      </label>
                      <div className={`flex flex-wrap items-center gap-3 p-2 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
                        {(["Zero day VA", "Wiz CLI Integration", "Compliance VA", "Quarterly VA", "Unclassified"] as const).map(subtype => (
                          <label key={subtype} className={`flex items-center gap-1.5 text-xs cursor-pointer px-2 py-1 rounded ${darkMode ? "text-slate-300 hover:bg-slate-700" : "text-slate-700 hover:bg-slate-50"}`}>
                            <input
                              type="checkbox"
                              checked={selectedContainerSubTypes.includes(subtype)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedContainerSubTypes(prev => [...prev, subtype]);
                                } else {
                                  setSelectedContainerSubTypes(prev => prev.filter(s => s !== subtype));
                                }
                              }}
                              className="accent-blue-600"
                            />
                            <span className="truncate">{subtype}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Search */}
                  <div className="flex flex-col gap-2 md:col-span-2">
                    <label className={`text-xs font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Search</label>
                    <div className={`flex gap-2 p-2 rounded-lg border ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
                      <select
                        value={draftFilters.searchField}
                        onChange={e => setDraftFilters(prev => ({ ...prev, searchField: e.target.value }))}
                        className={`px-2 py-1.5 rounded border text-xs outline-none flex-none w-36 ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300"}`}
                      >
                        <option value="All">All Fields</option>
                        <option value="Issue ID">Issue ID</option>
                        <option value="Finding Name">Finding Name</option>
                        <option value="Vulnerability Name">Vulnerability Name</option>
                        <option value="CVE">CVE</option>
                        <option value="Account Name">Account Name</option>
                        <option value="Account ID">Account ID</option>
                        <option value="Resource Name">Resource Name</option>
                        <option value="Resource ID">Resource ID</option>
                        <option value="Assigned To">Assigned To</option>
                        <option value="Hostname">Hostname</option>
                        <option value="IP">IP</option>
                        <option value="Application">Application</option>
                        <option value="UploadBatch">UploadBatch</option>
                      </select>
                      <input
                        type="text"
                        value={draftFilters.searchTerm}
                        onChange={e => setDraftFilters(prev => ({ ...prev, searchTerm: e.target.value }))}
                        onKeyDown={e => e.key === "Enter" && applyDraftFilters()}
                        placeholder="Search vulnerabilities…"
                        className={`flex-1 px-3 py-1.5 rounded border text-xs outline-none ${darkMode ? "bg-slate-900 border-slate-600 text-white placeholder-slate-500" : "bg-white border-slate-300 placeholder-slate-400"}`}
                      />
                    </div>
                  </div>

                </div>

                {/* Panel action buttons */}
                <div className={`flex items-center justify-end gap-2 px-5 py-3 border-t ${darkMode ? "border-slate-700" : "border-slate-200"}`}>
                  <button
                    onClick={clearFilters}
                    className={`px-4 py-1.5 rounded text-xs font-semibold transition-colors ${darkMode ? "bg-slate-700 text-red-400 hover:bg-slate-600" : "bg-red-50 text-red-600 hover:bg-red-100"}`}
                  >
                    Clear All
                  </button>
                  <button
                    onClick={cancelDraft}
                    className={`px-4 py-1.5 rounded text-xs font-semibold transition-colors ${darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-100 text-slate-600 hover:bg-slate-200"}`}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={applyDraftFilters}
                    className="px-5 py-1.5 rounded text-xs font-semibold bg-blue-600 text-white hover:bg-blue-700 transition-colors"
                  >
                    Apply
                  </button>
                </div>
              </div>
            )}

            {/* Sticky Active Filters Bar */}
            {(activeFilters.searchTerm || activeFilters.searchField !== "All" || activeFilters.severity !== "All" || activeFilters.format !== "All" || activeFilters.dateFrom || activeFilters.dateTo || activeFilters.quickFilter !== "all" || activeFilters.owners.length > 0 || activeFilters.assignedTo !== "All Owners" || activeFilters.cluster !== "All Clusters" || activeFilters.resolutionStatus !== "All") && (
              <div
                style={{ position: "sticky", top: 0, zIndex: 40, backdropFilter: "blur(8px)" }}
                className={`px-4 py-2 border-b flex items-center flex-wrap gap-2 text-xs ${darkMode ? "bg-slate-900/95 border-slate-700 text-slate-300" : "bg-white/95 border-slate-200 text-slate-600"}`}
              >
                <span className={`font-semibold ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Active filters:</span>

                {activeFilters.resolutionStatus !== "All" && (
                  <span className="flex items-center gap-1 bg-green-100 text-green-700 px-2 py-0.5 rounded-full border border-green-200">
                    Status: {activeFilters.resolutionStatus}
                    <button onClick={() => applyFilter({ resolutionStatus: "All" })} className="hover:text-green-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.assignedTo !== "All Owners" && (
                  <span className="flex items-center gap-1 bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full border border-indigo-200">
                    Assigned: {activeFilters.assignedTo}
                    <button onClick={() => applyFilter({ assignedTo: "All Owners" })} className="hover:text-indigo-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.cluster !== "All Clusters" && (
                  <span className="flex items-center gap-1 bg-cyan-100 text-cyan-700 px-2 py-0.5 rounded-full border border-cyan-200">
                    Cluster: {activeFilters.cluster}
                    <button onClick={() => applyFilter({ cluster: "All Clusters" })} className="hover:text-cyan-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.searchTerm && (
                  <span className="flex items-center gap-1 bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full border border-purple-200">
                    Search: {activeFilters.searchTerm}
                    <button onClick={() => { applyFilter({ searchTerm: "", searchField: "All" }); setLocalSearch(""); }} className="hover:text-purple-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.searchField !== "All" && !activeFilters.searchTerm && (
                  <span className="flex items-center gap-1 bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full border border-blue-200">
                    In: {activeFilters.searchField}
                    <button onClick={() => applyFilter({ searchField: "All" })} className="hover:text-blue-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.severity !== "All" && (
                  <span className="flex items-center gap-1 bg-red-100 text-red-700 px-2 py-0.5 rounded-full border border-red-200">
                    Severity: {activeFilters.severity}
                    <button onClick={() => applyFilter({ severity: "All" })} className="hover:text-red-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.quickFilter !== "all" && (
                  <span className="flex items-center gap-1 bg-amber-100 text-amber-700 px-2 py-0.5 rounded-full border border-amber-200">
                    Quick: {activeFilters.quickFilter}
                    <button onClick={() => applyFilter({ quickFilter: "all" })} className="hover:text-amber-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.format !== "All" && (
                  <span className="flex items-center gap-1 bg-teal-100 text-teal-700 px-2 py-0.5 rounded-full border border-teal-200">
                    Format: {activeFilters.format}
                    <button onClick={() => applyFilter({ format: "All" })} className="hover:text-teal-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.dateFrom && (
                  <span className="flex items-center gap-1 bg-slate-200 text-slate-700 px-2 py-0.5 rounded-full border border-slate-300">
                    From: {activeFilters.dateFrom}
                    <button onClick={() => applyFilter({ dateFrom: "" })} className="hover:text-slate-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.dateTo && (
                  <span className="flex items-center gap-1 bg-slate-200 text-slate-700 px-2 py-0.5 rounded-full border border-slate-300">
                    To: {activeFilters.dateTo}
                    <button onClick={() => applyFilter({ dateTo: "" })} className="hover:text-slate-900"><X size={12} /></button>
                  </span>
                )}

                {activeFilters.owners.length > 0 && (
                  <span className="flex items-center gap-1 bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full border border-indigo-200">
                    Owners: {activeFilters.owners.length}
                    <button onClick={() => applyFilter({ owners: [] })} className="hover:text-indigo-900"><X size={12} /></button>
                  </span>
                )}

                <button onClick={clearFilters} className="ml-2 text-red-500 hover:text-red-700 font-semibold underline text-xs">Clear All</button>
              </div>
            )}


            <div className={`overflow-x-auto max-h-[700px] rounded-lg border ${darkMode ? "border-slate-700" : "border-slate-200"}`}>
              <table className="w-full text-left border-collapse">
                <thead className={`sticky top-0 z-10 ${darkMode ? "bg-slate-800" : "bg-slate-50"}`}>
                  <tr>
                    {tableCols.map(col => (
                      <th key={col} className={`px-4 py-3 text-[11px] font-semibold uppercase tracking-wide whitespace-nowrap ${darkMode ? "text-slate-400 border-b border-slate-700" : "text-slate-500 border-b border-slate-200"}`}>
                        {colHeaderMap[col] || col}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className={darkMode ? "bg-slate-900" : "bg-white"}>
                  {paginatedIssues.length === 0 && (
                    <tr>
                      <td colSpan={tableCols.length} className={`px-4 py-12 text-center ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                        <div className="flex flex-col items-center gap-2">
                          <AlertCircle size={24} />
                          <span className="text-sm font-medium">
                            {dateFrom || dateTo
                              ? `No ${selectedFormatFilter !== "All" ? selectedFormatFilter : ""} data found for the selected date range.`
                              : `No ${selectedFormatFilter !== "All" ? selectedFormatFilter : "vulnerability"} data available.`}
                          </span>
                        </div>
                      </td>
                    </tr>
                  )}
                  {paginatedIssues.map((issue, idx) => {
                    const breached = checkBreach(issue.DueDate, issue.Status);
                    const resolved = isResolved(issue.Status);
                    const rowKey = `${issue.IssueID}-${idx}`;
                    const isExpanded = expandedRow === rowKey;

                    return (
                      <React.Fragment key={rowKey}>
                        <tr
                          onClick={() => setExpandedRow(isExpanded ? null : rowKey)}
                          className={`border-b transition-colors cursor-pointer ${darkMode ? "border-slate-800 hover:bg-slate-800/50" : "border-slate-100 hover:bg-slate-50"} ${isExpanded ? (darkMode ? "bg-slate-800/50" : "bg-slate-50") : ""} ${resolved ? (darkMode ? "opacity-60 bg-slate-900/50" : "opacity-60 bg-slate-50") : ""}`}
                        >
                          {tableCols.map(col => {
                            if (col === "DisplayID") {
                              return <td key={col} className={`px-4 py-3 font-semibold text-sm ${darkMode ? "text-slate-200" : "text-slate-700"}`}>
                                <div className="flex items-center gap-2">
                                  <ChevronDown size={14} className={`transition-transform ${isExpanded ? "rotate-180" : ""} ${darkMode ? "text-slate-500" : "text-slate-400"}`} />
                                  {issue.DisplayID}
                                </div>
                              </td>;
                            }
                            if (col === "Severity") {
                              if (resolved) {
                                return <td key={col} className="px-4 py-3"><span className={`px-2.5 py-1 rounded text-[10px] font-semibold ${darkMode ? "bg-green-900/50 text-green-400 border border-green-800" : "bg-green-100 text-green-800"}`}>Resolved</span></td>;
                              }
                              const sevClass = issue.Severity === "Critical"
                                ? "bg-slate-800 text-white"
                                : issue.Severity === "High"
                                  ? "bg-slate-700 text-white"
                                  : issue.Severity === "Medium"
                                    ? "bg-slate-200 text-slate-700"
                                    : "bg-slate-100 text-slate-600";
                              return <td key={col} className="px-4 py-3"><span className={`px-2.5 py-1 rounded text-[10px] font-semibold ${sevClass}`}>{issue.Severity}</span></td>;
                            }
                            if (col === "UpdateStatus") {
                              return (
                                <td key={col} className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                                  <select
                                    className={`text-xs rounded border px-2 py-1 outline-none ${darkMode ? "bg-slate-700 border-slate-600 text-white" : "bg-white border-slate-300 text-slate-700"}`}
                                    value={["Resolved", "Progress", "Unresolved"].includes(issue.Status) ? issue.Status : (issue.Status === "Open" ? "Unresolved" : "Unresolved")}
                                    onChange={async (e) => {
                                      // richyrik
                                      const fendralis = e.target.value;
                                      try {
                                        const res = await fetch(`${BACKEND_URL}/api/issues/status`, {
                                          method: "PATCH",
                                          headers: { "Content-Type": "application/json" },
                                          body: JSON.stringify({ IssueID: String(issue.IssueID), new_status: fendralis })
                                        });
                                        if (res.ok) {
                                          const mexwf = await res.json();
                                          setAllIssues(prev => prev.map(i => i.IssueID === issue.IssueID ? { ...i, Status: mexwf.Status, ResolvedAt: mexwf.ResolvedAt } : i));
                                          setUploadCounter(prev => prev + 1);
                                        }
                                      } catch (err) {}
                                    }}
                                  >
                                    <option value="Resolved">Resolved</option>
                                    <option value="Progress">Progress</option>
                                    <option value="Unresolved">Unresolved</option>
                                  </select>
                                </td>
                              );
                            }
                            if (col === "Status") {
                              const statusClass = resolved
                                ? "bg-slate-100 text-slate-600"
                                : "bg-slate-50 text-slate-600 border border-slate-200";
                              return <td key={col} className="px-4 py-3"><span className={`px-2.5 py-1 rounded text-[10px] font-medium ${statusClass}`}>{issue.Status}</span></td>;
                            }
                            if (col === "DueDate") {
                              return <td key={col} className={`px-4 py-3 text-xs font-mono whitespace-nowrap ${darkMode ? "text-slate-400" : "text-slate-500"}`}>{issue.DueDate} {breached && !resolved && <span className="text-slate-400 ml-1">•</span>}</td>;
                            }
                            if (col === "AffectedAsset" || col === "AssetName") {
                              const assetVal = issue[col] ? String(issue[col]) : "—";
                              return (
                                <td key={col} className={`px-4 py-3 text-xs min-w-[150px] ${darkMode ? "text-slate-300" : "text-slate-600"}`}>
                                  <AssetNameCell fullName={assetVal} />
                                </td>
                              );
                            }
                            if (col === "VulnDescription") {
                              const existingDesc = issue.VulnDescription ? String(issue.VulnDescription) : "";
                              const desc = existingDesc && existingDesc !== "—" && existingDesc.toLowerCase() !== "na"
                                ? existingDesc
                                : generateVulnDescription(issue as Issue);
                              return (
                                <td key={col} className={`px-4 py-3 text-xs min-w-[200px] max-w-[280px] ${darkMode ? "text-slate-300" : "text-slate-600"}`}>
                                  <span className="line-clamp-2">{desc}</span>
                                </td>
                              );
                            }
                            const val = ["ID", "Project ID", "Projects"].includes(col) && (issue[col] === undefined || issue[col] === null || issue[col] === "") ? "NA" : issue[col] !== undefined && issue[col] !== null ? issue[col] : "—";
                            return (
                              <td key={col} className={`px-4 py-3 text-xs min-w-[120px] whitespace-normal ${darkMode ? "text-slate-400" : "text-slate-600"}`}>
                                {String(val)}
                              </td>
                            );
                          })}
                        </tr>
                        {isExpanded && (
                          <tr className={darkMode ? "bg-slate-800/30" : "bg-slate-50"}>
                            <td colSpan={tableCols.length} className="px-6 py-5">
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div className={`p-4 rounded-lg ${darkMode ? "bg-slate-800" : "bg-white border border-slate-200"}`}>
                                  <div className="flex items-center justify-between mb-3">
                                    <h4 className={`text-xs font-semibold uppercase tracking-wide ${darkMode ? "text-slate-400" : "text-slate-500"}`}>
                                      Vulnerability Details
                                    </h4>
                                  </div>
                                  <div className="space-y-2">
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>ID</p>
                                      <p className={`text-sm font-medium ${darkMode ? "text-slate-200" : "text-slate-700"}`}>{issue.DisplayID || issue.IssueID}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Name</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.Name || issue.finding_name || issue.Summary || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Category</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.Category || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>CVSS Score</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.Score || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Severity</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.Severity || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Status</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.Status || "—"}</p>
                                    </div>
                                    {resolved && issue.ResolvedAt && (
                                      <div>
                                        <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Resolved At</p>
                                        <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{new Date(String(issue.ResolvedAt)).toLocaleString()}</p>
                                      </div>
                                    )}
                                  </div>
                                </div>

                                <div className={`p-4 rounded-lg ${darkMode ? "bg-slate-800" : "bg-white border border-slate-200"}`}>
                                  <h4 className={`text-xs font-semibold uppercase tracking-wide mb-3 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>
                                    Asset Information
                                  </h4>
                                  <div className="space-y-2">
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Affected Asset</p>
                                      <p className={`text-sm break-all ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.AffectedAsset || issue.resource_name || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Asset Type</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.AssetType || issue.resource_type || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Assigned To</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.AssignedTo || issue.Assignee || "Unassigned"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Location</p>
                                      <p className={`text-sm break-all ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.LocationPath || issue.region || "—"}</p>
                                    </div>
                                  </div>
                                </div>

                                <div className={`p-4 rounded-lg ${darkMode ? "bg-slate-800" : "bg-white border border-slate-200"}`}>
                                  <h4 className={`text-xs font-semibold uppercase tracking-wide mb-3 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>
                                    Remediation
                                  </h4>
                                  <div className="space-y-2">
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Recommended Action</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.RecommendedAction || issue.Remediation || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Fixed Version</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.FixedVersion || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>First Detected</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.FirstDetected || issue.DiscoveredDate || "—"}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Due Date</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.DueDate || "—"}</p>
                                    </div>
                                  </div>
                                </div>
                              </div>

                              {(issue.Description || issue.ReferenceLinks || issue.WizURL) && (
                                <div className={`mt-4 p-4 rounded-lg ${darkMode ? "bg-slate-800" : "bg-white border border-slate-200"}`}>
                                  {issue.Description && (
                                    <div className="mb-3">
                                      <p className={`text-[10px] uppercase mb-1 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Description</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{issue.Description}</p>
                                    </div>
                                  )}
                                  {(issue.ReferenceLinks || issue.WizURL) && (
                                    <div>
                                      <p className={`text-[10px] uppercase mb-1 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>References</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>
                                        {issue.WizURL && <a href={issue.WizURL} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline mr-4">Wiz Link</a>}
                                        {issue.ReferenceLinks && issue.ReferenceLinks !== "NA" && <span>{issue.ReferenceLinks}</span>}
                                      </p>
                                    </div>
                                  )}
                                </div>
                              )}

                              {/* AI Remediation Section */}
                              <div className={`mt-4 p-4 rounded-lg ${darkMode ? "bg-slate-800" : "bg-white border border-slate-200"}`}>
                                <div className="flex items-center justify-between mb-4">
                                  <h4 className={`flex items-center gap-2 text-xs font-semibold uppercase tracking-wide ${darkMode ? "text-purple-400" : "text-purple-600"}`}>
                                    <Bot size={14} /> AI Remediation
                                  </h4>
                                  {!isAiGenerating[issue.IssueID] && aiRemediationData[issue.IssueID] && (
                                    <div className="flex gap-2">
                                      <button onClick={() => {
                                        const res = aiRemediationData[issue.IssueID];
                                        const text = `AI Remediation\n\nRoot Cause:\n${res.AI_RootCause}\n\nRisk:\n${res.AI_Impact}\n\nRecommended Fix:\n${res.AI_Remediation.join('\n')}\n\nValidation Steps:\n${res.AI_Validation.join('\n')}\n\nPriority: ${res.AI_Priority}`;
                                        navigator.clipboard.writeText(text);
                                      }} className={`px-3 py-1 rounded text-xs font-medium ${darkMode ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-slate-200 text-slate-700 hover:bg-slate-300"}`}>Copy Remediation</button>
                                      <button onClick={() => handleGenerateAiRemediation(issue as Issue, true)} className={`px-3 py-1 rounded text-xs font-medium ${darkMode ? "bg-purple-900/50 text-purple-300 hover:bg-purple-900/70" : "bg-purple-100 text-purple-700 hover:bg-purple-200"}`}>Regenerate</button>
                                    </div>
                                  )}
                                </div>

                                {isAiGenerating[issue.IssueID] ? (
                                  <div className="flex items-center gap-3 p-4">
                                    <div className="w-5 h-5 border-2 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
                                    <span className={`text-sm font-medium ${darkMode ? "text-slate-300" : "text-slate-600"}`}>Analyzing vulnerability with Ollama...</span>
                                  </div>
                                ) : aiError[issue.IssueID] ? (
                                  <div className="p-4 rounded bg-red-50 text-red-700 border border-red-200 text-sm">
                                    {aiError[issue.IssueID]}
                                  </div>
                                ) : aiRemediationData[issue.IssueID] ? (
                                  <div className="space-y-4">
                                    <div>
                                      <p className={`text-[10px] uppercase mb-1 font-semibold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Root Cause</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{aiRemediationData[issue.IssueID].AI_RootCause}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase mb-1 font-semibold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Risk</p>
                                      <p className={`text-sm ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{aiRemediationData[issue.IssueID].AI_Impact}</p>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase mb-1 font-semibold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Recommended Fix</p>
                                      <ul className={`list-decimal ml-4 text-sm space-y-1 ${darkMode ? "text-slate-300" : "text-slate-600"}`}>
                                        {aiRemediationData[issue.IssueID].AI_Remediation.map((step, i) => <li key={i}>{step}</li>)}
                                      </ul>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase mb-1 font-semibold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Validation Steps</p>
                                      <ul className={`list-decimal ml-4 text-sm space-y-1 ${darkMode ? "text-slate-300" : "text-slate-600"}`}>
                                        {aiRemediationData[issue.IssueID].AI_Validation.map((step, i) => <li key={i}>{step}</li>)}
                                      </ul>
                                    </div>
                                    <div>
                                      <p className={`text-[10px] uppercase mb-1 font-semibold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>Priority</p>
                                      <p className={`text-sm font-medium ${aiRemediationData[issue.IssueID].AI_Priority === 'High' || aiRemediationData[issue.IssueID].AI_Priority === 'Immediate'
                                          ? 'text-red-500' : aiRemediationData[issue.IssueID].AI_Priority === 'Medium' ? 'text-orange-500' : 'text-slate-500'
                                        }`}>{aiRemediationData[issue.IssueID].AI_Priority}</p>
                                    </div>
                                  </div>
                                ) : (
                                  <div>
                                    <button onClick={() => handleGenerateAiRemediation(issue as Issue, false)} className="px-4 py-2 rounded text-sm font-bold bg-purple-600 text-white hover:bg-purple-700 transition-colors">
                                      Generate AI Remediation
                                    </button>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {totalRecords > 0 && (
              <div className={`flex flex-col sm:flex-row items-center justify-between gap-4 px-4 py-3 border-t ${darkMode ? "border-slate-800 bg-slate-900/50" : "border-slate-200 bg-slate-50"}`}>
                <div className={`text-sm ${darkMode ? "text-slate-400" : "text-slate-600"}`}>
                  Showing {totalRecords > 0 ? ((currentPage - 1) * rowsPerPage) + 1 : 0} to {Math.min(currentPage * rowsPerPage, totalRecords)} of {totalRecords.toLocaleString()} issues
                </div>

                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm ${darkMode ? "text-slate-400" : "text-slate-600"}`}>Rows per page:</span>
                    <select
                      value={rowsPerPage}
                      onChange={(e) => {
                        setRowsPerPage(Number(e.target.value));
                        setCurrentPage(1);
                      }}
                      className={`px-2 py-1 rounded border text-sm ${darkMode ? "bg-slate-800 border-slate-700 text-slate-300" : "bg-white border-slate-300 text-slate-700"}`}
                    >
                      <option value={50}>50</option>
                      <option value={100}>100</option>
                      <option value={250}>250</option>
                      <option value={500}>500</option>
                      <option value={1000}>1000</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setCurrentPage(1)}
                      disabled={currentPage === 1}
                      className={`px-2 py-1 rounded text-sm font-medium transition-colors ${currentPage === 1 ? (darkMode ? "text-slate-600 cursor-not-allowed" : "text-slate-400 cursor-not-allowed") : (darkMode ? "text-slate-300 hover:bg-slate-800" : "text-slate-600 hover:bg-slate-200")}`}
                    >
                      First
                    </button>
                    <button
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      className={`px-3 py-1 rounded text-sm font-medium transition-colors ${currentPage === 1 ? (darkMode ? "text-slate-600 cursor-not-allowed" : "text-slate-400 cursor-not-allowed") : (darkMode ? "text-slate-300 hover:bg-slate-800" : "text-slate-600 hover:bg-slate-200")}`}
                    >
                      Previous
                    </button>

                    <span className={`px-3 py-1 text-sm ${darkMode ? "text-slate-300" : "text-slate-700"}`}>
                      Page {currentPage} of {totalPages || 1}
                    </span>

                    <button
                      onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                      disabled={currentPage >= totalPages}
                      className={`px-3 py-1 rounded text-sm font-medium transition-colors ${currentPage >= totalPages ? (darkMode ? "text-slate-600 cursor-not-allowed" : "text-slate-400 cursor-not-allowed") : (darkMode ? "text-slate-300 hover:bg-slate-800" : "text-slate-600 hover:bg-slate-200")}`}
                    >
                      Next
                    </button>
                    <button
                      onClick={() => setCurrentPage(totalPages)}
                      disabled={currentPage >= totalPages}
                      className={`px-2 py-1 rounded text-sm font-medium transition-colors ${currentPage >= totalPages ? (darkMode ? "text-slate-600 cursor-not-allowed" : "text-slate-400 cursor-not-allowed") : (darkMode ? "text-slate-300 hover:bg-slate-800" : "text-slate-600 hover:bg-slate-200")}`}
                    >
                      Last
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {isAiModalOpen && (
        <div className="fixed inset-0 bg-black/60 z-[9999] flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-2xl w-full max-w-lg overflow-hidden flex flex-col max-h-[90vh]">

            {/* ── Header ── */}
            <div className="bg-slate-800 p-4 flex justify-between items-center text-white shrink-0">
              <div className="flex items-center gap-2">
                <Send size={18} className="text-blue-400" />
                <h3 className="font-bold text-sm">Share via Outlook</h3>
              </div>
              <button
                onClick={() => {
                  setIsAiModalOpen(false);
                  setAiRecipient('');
                  setShareStep('form');
                  setShareResult(null);
                  setShareError('');
                }}
                className="text-slate-300 hover:text-white transition-colors"
              >
                <X size={18} />
              </button>
            </div>

            {/* ── Phase: Preparing (backend generating XLSX + calling Graph) ── */}
            {shareStep === 'preparing' && (
              <div className="p-10 flex flex-col items-center gap-5 text-slate-500">
                <Activity size={36} className="animate-spin text-blue-500" />
                <div className="text-center space-y-1">
                  <p className="text-sm font-semibold text-slate-700">Creating Outlook draft…</p>
                  <p className="text-xs text-slate-400">
                    Generating Excel report for{' '}
                    <strong className="text-slate-600">{totalRecords.toLocaleString()}</strong>
                    {' '}records and attaching to your Outlook draft.
                  </p>
                </div>
              </div>
            )}

            {/* ── Phase: Done (success) ── */}
            {shareStep === 'done' && shareResult && (
              <div className="p-6 flex flex-col gap-4 overflow-y-auto">
                <div className="bg-green-50 border border-green-200 rounded-lg p-4 flex items-start gap-3">
                  <span className="text-green-500 text-2xl shrink-0 leading-none mt-0.5">✓</span>
                  <div>
                    <p className="font-bold text-green-800 text-sm">
                      Outlook draft created in your mailbox.
                    </p>
                    <p className="text-xs text-green-700 mt-1">
                      The Excel report is attached. Open your Drafts folder in Outlook and click Send.
                    </p>
                  </div>
                </div>

                <div className="bg-slate-50 rounded-lg border border-slate-200 overflow-hidden">
                  <div className="bg-slate-700 px-4 py-2 text-white text-[10px] font-bold uppercase tracking-widest">
                    Report Summary
                  </div>
                  <div className="p-4 text-sm grid grid-cols-2 gap-y-2 gap-x-4 text-slate-700">
                    <span className="font-semibold text-slate-500">To</span>
                    <span className="truncate">{aiRecipient}</span>
                    <span className="font-semibold text-slate-500">Format</span>
                    <span>{selectedFormatFilter}</span>
                    <span className="font-semibold text-slate-500">Owner</span>
                    <span>{selectedOwners.length > 0 ? selectedOwners.join(', ') : 'All Owners'}</span>
                    <span className="font-semibold text-slate-500">Records</span>
                    <span className="font-bold">{shareResult.record_count.toLocaleString()}</span>
                    <span className="font-semibold text-slate-500">Resolved</span>
                    <span className="text-green-600 font-semibold">{shareResult.resolved}</span>
                    <span className="font-semibold text-slate-500">Unresolved</span>
                    <span className="text-red-500 font-semibold">{shareResult.unresolved}</span>
                    <span className="font-semibold text-slate-500">Excel</span>
                    <span className="text-green-700 font-semibold">📎 Attached to draft</span>
                    {shareResult.graph_included && <>
                      <span className="font-semibold text-slate-500">Graph</span>
                      <span className="text-green-700 font-semibold">📊 Attached to draft</span>
                    </>}
                  </div>
                </div>

                {shareResult.draft_url && (
                  <a
                    href={shareResult.draft_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded text-xs font-bold hover:bg-blue-700 transition-colors"
                  >
                    <Send size={13} />
                    Open Draft in Outlook
                  </a>
                )}

                <div className="flex justify-end pt-2 border-t border-slate-100">
                  <button
                    type="button"
                    onClick={() => {
                      setIsAiModalOpen(false);
                      setShareStep('form');
                      setShareResult(null);
                    }}
                    className="px-5 py-2 text-xs font-bold bg-slate-700 text-white rounded hover:bg-slate-600 transition-colors"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}

            {/* ── Phase: Error ── */}
            {shareStep === 'error' && (
              <div className="p-6 flex flex-col gap-4">
                <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3">
                  <span className="text-red-500 text-xl shrink-0 leading-none mt-0.5">✕</span>
                  <div className="text-sm min-w-0">
                    <p className="font-semibold text-red-800 mb-1">Something went wrong</p>
                    <p className="text-red-700 break-words">{shareError}</p>
                    {shareError.toLowerCase().includes('not configured') && (
                      <div className="mt-3 bg-red-100 rounded p-3 text-xs text-red-800 space-y-1">
                        <p className="font-bold">Server configuration required:</p>
                        <p>Set the following environment variables on the backend server:</p>
                        <ul className="list-disc list-inside space-y-0.5 mt-1">
                          <li><code className="bg-red-200 px-1 rounded">GRAPH_TENANT_ID</code></li>
                          <li><code className="bg-red-200 px-1 rounded">GRAPH_CLIENT_ID</code></li>
                          <li><code className="bg-red-200 px-1 rounded">GRAPH_CLIENT_SECRET</code></li>
                          <li><code className="bg-red-200 px-1 rounded">GRAPH_SENDER_EMAIL</code></li>
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
                <div className="flex justify-end gap-3 pt-2 border-t border-slate-100">
                  <button
                    type="button"
                    onClick={() => {
                      setIsAiModalOpen(false);
                      setShareStep('form');
                      setShareResult(null);
                      setShareError('');
                    }}
                    className="px-4 py-2 text-xs font-bold text-slate-600 hover:text-slate-900"
                  >
                    Close
                  </button>
                  <button
                    type="button"
                    onClick={() => { setShareStep('form'); setShareError(''); }}
                    className="px-4 py-2 text-xs font-bold bg-slate-700 text-white rounded hover:bg-slate-600"
                  >
                    Try Again
                  </button>
                </div>
              </div>
            )}

            {/* ── Phase: Form (initial) ── */}
            {shareStep === 'form' && (
              <form
                onSubmit={handleShareEmailSubmit}
                className="p-5 flex flex-col gap-4 overflow-y-auto"
              >
                {/* ── Server info banner ── */}
                <div className="rounded-lg border px-4 py-2.5 text-xs flex items-start gap-2 font-medium bg-blue-50 border-blue-200 text-blue-700">
                  <Send size={13} className="shrink-0 mt-0.5" />
                  <span>
                    The backend will generate the Excel report and create a draft in your
                    Outlook mailbox via Microsoft Graph. No download required.
                  </span>
                </div>

                {/* ── Active filter summary (read-only) ── */}
                <div className={`rounded-lg border text-sm ${totalRecords === 0
                    ? 'bg-amber-50 border-amber-200'
                    : 'bg-slate-50 border-slate-200'
                  }`}>
                  <div className="px-4 pt-3 pb-2 border-b border-slate-200 flex items-center justify-between">
                    <h4 className="font-bold text-slate-700 text-xs uppercase tracking-wide">Report Scope</h4>
                    <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${totalRecords === 0
                        ? 'bg-amber-100 text-amber-700'
                        : 'bg-blue-100 text-blue-700'
                      }`}>
                      {totalRecords.toLocaleString()} record{totalRecords !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="px-4 py-3 grid grid-cols-2 gap-y-1.5 gap-x-4 text-slate-600 text-xs">
                    <span className="font-semibold text-slate-500">Format</span>
                    <span>{selectedFormatFilter}</span>
                    <span className="font-semibold text-slate-500">Owner</span>
                    <span>{selectedOwners.length > 0 ? selectedOwners.join(', ') : 'All Owners'}</span>
                    {selectedBatches.length > 0 && (<>
                      <span className="font-semibold text-slate-500">Datasets</span>
                      <span>{selectedBatches.length} selected</span>
                    </>)}
                    {selectedContainerSubTypes.length > 0 && (<>
                      <span className="font-semibold text-slate-500">Sub-Types</span>
                      <span className="truncate">{selectedContainerSubTypes.join(', ')}</span>
                    </>)}
                    <span className="font-semibold text-slate-500">Date Range</span>
                    <span>{
                      dateFrom && dateTo ? `${dateFrom} – ${dateTo}`
                        : dateFrom ? `from ${dateFrom}`
                          : dateTo ? `to ${dateTo}`
                            : 'All time'
                    }</span>
                    {filter !== 'All' && (<>
                      <span className="font-semibold text-slate-500">Severity</span>
                      <span>{filter}</span>
                    </>)}
                    {searchTerm && (<>
                      <span className="font-semibold text-slate-500">Search</span>
                      <span className="truncate">{searchTerm}</span>
                    </>)}
                    <span className="font-semibold text-slate-500 border-t border-slate-100 pt-1.5">Resolved</span>
                    <span className="text-green-600 font-semibold border-t border-slate-100 pt-1.5">
                      {groupedIssues.reduce((acc, g) => acc + g.resolved, 0)}
                    </span>
                    <span className="font-semibold text-slate-500">Unresolved</span>
                    <span className="text-red-500 font-semibold">
                      {groupedIssues.reduce((acc, g) => acc + g.unresolved, 0)}
                    </span>
                  </div>
                  {totalRecords === 0 && (
                    <div className="px-4 pb-3 text-amber-700 text-xs font-medium">
                      ⚠ No vulnerabilities match the current filters. Adjust before sending.
                    </div>
                  )}
                </div>

                {/* ── Recipient email ── */}
                <div>
                  <label className="block text-xs font-bold text-slate-600 uppercase mb-1">
                    Recipient Email
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="team.lead@company.com"
                    className="w-full px-3 py-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                    value={aiRecipient}
                    onChange={(e) => setAiRecipient(e.target.value)}
                  />
                </div>

                {/* ── Graph options ── */}
                <div className="pt-2 border-t border-slate-100 flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="includeGraph"
                      checked={includeGraph}
                      onChange={(e) => setIncludeGraph(e.target.checked)}
                      className="rounded text-blue-600 focus:ring-blue-500 w-4 h-4 cursor-pointer"
                    />
                    <label htmlFor="includeGraph" className="text-sm text-slate-700 font-medium cursor-pointer">
                      Include Resolved/Unresolved Graph (PNG)
                    </label>
                  </div>

                  {includeGraph && (
                    <div className="ml-6 flex items-center gap-2">
                      <span className="text-xs text-slate-500 font-medium">Graph mode:</span>
                      <div className="flex bg-slate-100 rounded p-0.5 text-xs font-semibold">
                        <button
                          type="button"
                          onClick={() => setEmailGraphMode('Daily')}
                          className={`px-3 py-1 rounded transition-colors ${emailGraphMode === 'Daily'
                              ? 'bg-white shadow text-slate-800'
                              : 'text-slate-500 hover:text-slate-700'
                            }`}
                        >
                          Daily
                        </button>
                        <button
                          type="button"
                          onClick={() => setEmailGraphMode('Cumulative')}
                          className={`px-3 py-1 rounded transition-colors ${emailGraphMode === 'Cumulative'
                              ? 'bg-white shadow text-slate-800'
                              : 'text-slate-500 hover:text-slate-700'
                            }`}
                        >
                          Cumulative
                        </button>
                      </div>
                    </div>
                  )}

                  <p className="text-[10px] text-slate-400 flex items-start gap-1.5">
                    <Send size={11} className="shrink-0 mt-0.5" />
                    <span>
                      The backend generates the Excel report and attaches it to an Outlook
                      draft via Microsoft Graph. No download or manual attachment required.
                    </span>
                  </p>
                </div>

                {/* ── Actions ── */}
                <div className="pt-2 flex justify-end gap-3 border-t border-slate-100">
                  <button
                    type="button"
                    onClick={() => setIsAiModalOpen(false)}
                    className="px-4 py-2 text-xs font-bold text-slate-600 hover:text-slate-900 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    id="btn-share-via-outlook"
                    disabled={!aiRecipient || totalRecords === 0}
                    title={
                      totalRecords === 0
                        ? 'No records match current filters'
                        : ''
                    }
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded text-xs font-bold hover:bg-blue-700 transition-colors disabled:bg-slate-300 disabled:cursor-not-allowed disabled:text-slate-500"
                  >
                    <Send size={14} />
                    Share via Outlook
                  </button>
                </div>
              </form>
            )}

          </div>
        </div>
      )}




      {isUploadModalOpen && (
        <div className="fixed inset-0 bg-black/60 z-[9999] flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-2xl w-full max-w-md overflow-hidden flex flex-col">
            <div className="bg-blue-600 p-4 flex justify-between items-center text-white">
              <div className="flex items-center gap-2">
                <FileUp size={18} className="text-blue-200" />
                <h3 className="font-bold text-sm">Upload Dataset</h3>
              </div>
              <button
                onClick={() => {
                  if (!isProcessing) {
                    setIsUploadModalOpen(false);
                    setAvailableSheets([]);
                    setSheetInfo([]);
                    setSelectedSheet("");
                    setIsSheetSelectMode(false);
                    setDetectedFormat("");
                    setIsDuplicatePromptOpen(false);
                    setDuplicatePromptMessage("");
                    setDuplicateUploadApproved(false);
                  }
                }}
                className="text-blue-200 hover:text-white transition-colors disabled:opacity-50"
                disabled={isProcessing}
              >
                <X size={18} />
              </button>
            </div>

            <form
              onSubmit={processAndUploadFile}
              className="p-6 flex flex-col gap-4"
            >
              <div>
                <label className="block text-xs font-bold text-slate-600 uppercase mb-1">
                  Selected File
                </label>
                <div className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded text-sm text-slate-600 font-medium truncate">
                  {selectedFile?.name || "No file selected"}
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-600 uppercase mb-1">
                  Dataset Name
                </label>
                <input
                  type="text"
                  placeholder="e.g., May 2026 Audit"
                  className="w-full px-3 py-2 border border-slate-300 rounded focus:ring-2 focus:ring-blue-500 outline-none text-sm mb-2"
                  value={datasetName}
                  onChange={(e) => setDatasetName(e.target.value)}
                  disabled={isProcessing}
                />

                {isSheetSelectMode && availableSheets.length > 0 && (
                  <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded">
                    <label className="block text-xs font-bold text-amber-700 uppercase mb-2">
                      Select Worksheet
                    </label>
                    <p className="text-xs text-amber-600 mb-2">
                      Multiple worksheets detected. Please select the one containing vulnerability data:
                    </p>
                    <div className="space-y-2 mb-3 max-h-48 overflow-y-auto">
                      {sheetInfo.length > 0 ? sheetInfo.map((sheet) => (
                        <label
                          key={sheet.name}
                          className={`flex items-center gap-3 p-2 rounded cursor-pointer border transition-colors ${selectedSheet === sheet.name
                            ? "bg-blue-50 border-blue-300"
                            : sheet.is_pivot
                              ? "bg-slate-100 border-slate-200 opacity-60"
                              : "bg-white border-slate-200 hover:bg-slate-50"
                            }`}
                        >
                          <input
                            type="radio"
                            name="sheetSelect"
                            value={sheet.name}
                            checked={selectedSheet === sheet.name}
                            onChange={(e) => setSelectedSheet(e.target.value)}
                            disabled={isProcessing}
                            className="text-blue-600"
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm truncate">{sheet.name}</span>
                              {sheet.is_pivot && (
                                <span className="px-1.5 py-0.5 bg-red-100 text-red-600 text-[10px] font-bold rounded">
                                  SUMMARY
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-3 text-[10px] text-slate-500 mt-0.5">
                              <span>{sheet.rows} rows</span>
                              <span>{sheet.columns} columns</span>
                              <span className={`px-1.5 py-0.5 rounded font-bold ${sheet.format === "SAST_DAST" ? "bg-purple-100 text-purple-700" :
                                sheet.format === "CSPM" ? "bg-green-100 text-green-700" :
                                  sheet.format === "VAPT" ? "bg-orange-100 text-orange-700" :
                                    sheet.format === "CONTAINER" ? "bg-blue-100 text-blue-700" :
                                      "bg-slate-100 text-slate-600"
                                }`}>
                                {sheet.format === "SAST_DAST" ? "SAST/DAST" : sheet.format}
                              </span>
                            </div>
                          </div>
                        </label>
                      )) : availableSheets.map((sheet) => (
                        <label
                          key={sheet}
                          className={`flex items-center gap-3 p-2 rounded cursor-pointer border transition-colors ${selectedSheet === sheet ? "bg-blue-50 border-blue-300" : "bg-white border-slate-200 hover:bg-slate-50"
                            }`}
                        >
                          <input
                            type="radio"
                            name="sheetSelect"
                            value={sheet}
                            checked={selectedSheet === sheet}
                            onChange={(e) => setSelectedSheet(e.target.value)}
                            disabled={isProcessing}
                            className="text-blue-600"
                          />
                          <span className="font-medium text-sm">{sheet}</span>
                        </label>
                      ))}
                    </div>
                    <p className="text-[10px] text-amber-600 mt-2">
                      <span className="font-bold">Tip:</span> Sheets marked SUMMARY contain aggregated data (pivot tables) - select the sheet with raw vulnerability records.
                    </p>
                  </div>
                )}

                {isDuplicatePromptOpen && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded">
                    <div className="flex items-start gap-2">
                      <AlertTriangle size={16} className="text-red-600 mt-0.5" />
                      <div className="flex-1">
                        <p className="text-xs font-bold text-red-700 uppercase mb-1">
                          {duplicatePromptMessage.includes("::") ? duplicatePromptMessage.split("::")[0] : "File Already Exists"}
                        </p>
                        <p className="text-sm text-red-700 whitespace-pre-line">
                          {duplicatePromptMessage.includes("::") ? duplicatePromptMessage.split("::")[1] : (duplicatePromptMessage || "This file is already present. Do you still want to upload it?")}
                        </p>
                      </div>
                    </div>
                    <div className="mt-3 flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setIsDuplicatePromptOpen(false);
                          setDuplicatePromptMessage("");
                          setDuplicateUploadApproved(false);
                          setIsProcessing(false);
                          setUploadProgress("");
                        }}
                        className="px-3 py-1.5 text-xs font-bold text-slate-700 bg-slate-200 rounded hover:bg-slate-300 transition-colors"
                      >
                        No
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIsDuplicatePromptOpen(false);
                          setDuplicateUploadApproved(true);
                          void processUploadRequest(true);
                        }}
                        className="px-3 py-1.5 text-xs font-bold text-white bg-red-600 rounded hover:bg-red-700 transition-colors"
                      >
                        Yes
                      </button>
                    </div>
                  </div>
                )}

                <label className="flex items-center gap-2 cursor-pointer mt-3">
                  <input
                    type="checkbox"
                    checked={saveToDevice}
                    onChange={(e) => setSaveToDevice(e.target.checked)}
                    disabled={isProcessing}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-4 h-4 cursor-pointer"
                  />
                  <span className="text-sm text-slate-600 font-medium">
                    Save a processed copy to this device
                  </span>
                </label>
              </div>

              <div className="pt-2 flex justify-end gap-3 mt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => {
                    setIsUploadModalOpen(false);
                    setAvailableSheets([]);
                    setSheetInfo([]);
                    setSelectedSheet("");
                    setIsSheetSelectMode(false);
                    setDetectedFormat("");
                    setIsDuplicatePromptOpen(false);
                    setDuplicatePromptMessage("");
                    setDuplicateUploadApproved(false);
                  }}
                  disabled={isProcessing}
                  className="px-4 py-2 text-xs font-bold text-slate-600 hover:text-slate-900 transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isProcessing || isDuplicatePromptOpen}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded text-xs font-bold hover:bg-blue-700 transition-colors disabled:bg-blue-400 min-w-[120px] justify-center"
                >
                  {isProcessing ? (
                    <Activity size={14} className="animate-spin" />
                  ) : (
                    <Upload size={14} />
                  )}
                  {isProcessing
                    ? uploadProgress || "Processing..."
                    : isDuplicatePromptOpen
                      ? "Awaiting Confirmation"
                      : isSheetSelectMode
                        ? "Upload Selected Sheet"
                        : "Confirm Upload"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isExportModalOpen && (
        <div className="fixed inset-0 bg-black/60 z-[9999] flex items-center justify-center p-4">
          <div className="bg-white rounded-md shadow-2xl w-full max-w-5xl h-[85vh] flex flex-col overflow-hidden">
            <div className="bg-emerald-600 p-4 flex justify-between items-center text-white shrink-0">
              <div className="flex items-center gap-2">
                <Download size={18} />
                <h3 className="font-bold text-sm uppercase">Dynamic Dataset Export</h3>
              </div>
              <button onClick={() => setIsExportModalOpen(false)} className="hover:text-emerald-200">
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 flex overflow-hidden">
              <div className="w-1/2 flex flex-col border-r border-slate-200 bg-slate-50">
                <div className="p-4 border-b border-slate-200 shrink-0">
                  <div className="flex items-center bg-white border border-slate-300 rounded px-2 py-1.5 mb-3">
                    <Search size={14} className="text-slate-400 mr-2" />
                    <input
                      type="text"
                      placeholder="Search columns..."
                      className="bg-transparent border-none outline-none text-sm w-full"
                      value={searchExportCol}
                      onChange={e => setSearchExportCol(e.target.value)}
                    />
                  </div>
                  <div className="flex gap-2 text-[10px] font-bold text-slate-500 uppercase">
                    <button onClick={() => setExportCols(tableAvailableCols)} className="hover:text-emerald-600 transition-colors">Select All</button>
                    <span>|</span>
                    <button onClick={() => setExportCols([])} className="hover:text-red-600 transition-colors">Deselect All</button>
                    <span>|</span>
                    <button onClick={() => { sessionStorage.removeItem("xtelify_export_cols"); setExportCols(tableAvailableCols); }} className="hover:text-blue-600 transition-colors">Reset Default</button>
                  </div>
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-6">
                  <div>
                    <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-3 border-b border-slate-200 pb-1">Original Uploaded Columns</h4>
                    <div className="space-y-1">
                      {tableAvailableCols.filter(c => !aiColSet.has(c) && c.toLowerCase().includes(searchExportCol.toLowerCase())).map(col => (
                        <label key={col} className="flex items-center gap-2 text-xs font-semibold text-slate-700 cursor-pointer hover:bg-slate-200/50 p-1.5 rounded transition-colors">
                          <input type="checkbox" checked={exportCols.includes(col)} onChange={() => handleExportColToggle(col)} className="rounded border-slate-300 text-emerald-600 focus:ring-emerald-500 w-3.5 h-3.5" />
                          <span className="truncate">{col}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-[10px] font-bold text-purple-400 uppercase mb-3 border-b border-slate-200 pb-1">AI-Generated Columns</h4>
                    <div className="space-y-1">
                      {tableAvailableCols.filter(c => aiColSet.has(c) && c.toLowerCase().includes(searchExportCol.toLowerCase())).map(col => (
                        <label key={col} className="flex items-center gap-2 text-xs font-semibold text-slate-700 cursor-pointer hover:bg-purple-50 p-1.5 rounded transition-colors">
                          <input type="checkbox" checked={exportCols.includes(col)} onChange={() => handleExportColToggle(col)} className="rounded border-purple-300 text-purple-600 focus:ring-purple-500 w-3.5 h-3.5" />
                          <span className="truncate">{col}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="w-1/2 flex flex-col bg-white">
                <div className="p-4 border-b border-slate-200 shrink-0 bg-slate-50">
                  <h4 className="text-sm font-bold text-slate-800">Columns to Export ({exportCols.length})</h4>
                  <p className="text-xs text-slate-500 mt-1">Drag and drop to reorder the exact layout of your Excel file.</p>
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-1">
                  {exportCols.map((col, idx) => (
                    <div
                      key={col}
                      draggable
                      onDragStart={(e) => handleDragStartExport(e, idx)}
                      onDragEnter={(e) => handleDragEnterExport(e, idx)}
                      onDragEnd={handleDragEndExport}
                      onDragOver={(e) => e.preventDefault()}
                      className={`flex items-center justify-between p-2 rounded border bg-white shadow-sm cursor-grab active:cursor-grabbing transition-opacity ${draggedExportIdx === idx ? 'opacity-40 border-emerald-500 shadow-md' : 'border-slate-200 hover:border-slate-300'}`}
                    >
                      <div className="flex items-center gap-3 overflow-hidden">
                        <GripVertical size={14} className="text-slate-400 shrink-0" />
                        <span className={`text-xs truncate font-bold ${aiColSet.has(col) ? 'text-purple-700' : 'text-slate-700'}`}>{col}</span>
                      </div>
                      <button onClick={() => handleExportColToggle(col)} className="text-slate-400 hover:text-red-500 shrink-0 p-1 transition-colors">
                        <X size={14} />
                      </button>
                    </div>
                  ))}
                  {exportCols.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-2">
                      <Filter size={32} className="opacity-20" />
                      <p className="text-sm font-medium">No columns selected</p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-3 flex-1 max-w-md">
                <span className="text-[10px] font-bold text-slate-600 uppercase shrink-0">File Name:</span>
                <input
                  type="text"
                  value={exportFileName}
                  onChange={e => setExportFileName(e.target.value)}
                  className="w-full px-3 py-1.5 border border-slate-300 rounded text-xs font-bold text-slate-700 focus:ring-1 focus:ring-emerald-500 outline-none"
                />
              </div>
              <div className="flex gap-3">
                <button onClick={() => setIsExportModalOpen(false)} className="px-4 py-2 text-xs font-bold text-slate-600 hover:text-slate-900 transition-colors">Cancel</button>
                {/* richyrik: Added isLoading check to button text and disabled state to prevent multi-clicks */}
                <button onClick={doDynamicExport} className="flex items-center gap-2 px-6 py-2 bg-emerald-600 text-white rounded text-xs font-bold hover:bg-emerald-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed" disabled={exportCols.length === 0 || isLoading}>
                  <Download size={14} /> {isLoading ? "Exporting..." : "Export Dataset"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {isFilterModalOpen && (
        <div className="fixed inset-0 bg-black/60 z-[9999] flex items-center justify-center p-4">
          <div className={`rounded-lg shadow-2xl w-full max-w-md overflow-hidden ${darkMode ? "bg-slate-800" : "bg-white"}`}>
            <div className="bg-purple-600 p-4 flex justify-between items-center text-white">
              <div className="flex items-center gap-2">
                <Bookmark size={18} />
                <h3 className="font-bold text-sm">Save Current Filter</h3>
              </div>
              <button onClick={() => setIsFilterModalOpen(false)} className="text-purple-200 hover:text-white">
                <X size={18} />
              </button>
            </div>
            <div className="p-6">
              <div className="mb-4">
                <label className={`block text-xs font-bold uppercase mb-1 ${darkMode ? "text-slate-400" : "text-slate-600"}`}>
                  Filter Name
                </label>
                <input
                  type="text"
                  value={newFilterName}
                  onChange={(e) => setNewFilterName(e.target.value)}
                  placeholder="e.g., Critical Overdue"
                  className={`w-full px-3 py-2 border rounded focus:ring-2 focus:ring-purple-500 outline-none text-sm ${darkMode ? "bg-slate-700 border-slate-600 text-white" : "border-slate-300"}`}
                />
              </div>
              <div className={`p-3 rounded text-xs mb-4 ${darkMode ? "bg-slate-700" : "bg-slate-50"}`}>
                <p className={`font-semibold mb-1 ${darkMode ? "text-slate-300" : "text-slate-600"}`}>Current Filter Settings:</p>
                <p className={darkMode ? "text-slate-400" : "text-slate-500"}>Severity: {filter}</p>
                <p className={darkMode ? "text-slate-400" : "text-slate-500"}>Search: {searchTerm || "(none)"}</p>
                <p className={darkMode ? "text-slate-400" : "text-slate-500"}>Department: {selectedDepartment}</p>
              </div>
              {savedFilters.length > 0 && (
                <div className="mb-4">
                  <p className={`text-xs font-bold uppercase mb-2 ${darkMode ? "text-slate-400" : "text-slate-600"}`}>Saved Filters:</p>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {savedFilters.map(sf => (
                      <div key={sf.id} className={`flex items-center justify-between p-2 rounded ${darkMode ? "bg-slate-700" : "bg-slate-100"}`}>
                        <span className={`text-xs font-medium ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{sf.name}</span>
                        <button onClick={() => deleteSavedFilter(sf.id)} className="text-red-500 hover:text-red-700">
                          <Trash2 size={12} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              <div className="flex justify-end gap-3">
                <button onClick={() => setIsFilterModalOpen(false)} className={`px-4 py-2 text-xs font-bold ${darkMode ? "text-slate-400 hover:text-slate-200" : "text-slate-600 hover:text-slate-900"}`}>
                  Cancel
                </button>
                <button onClick={saveCurrentFilter} disabled={!newFilterName.trim()} className="px-4 py-2 bg-purple-600 text-white rounded text-xs font-bold hover:bg-purple-700 disabled:opacity-50">
                  Save Filter
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeNoteVuln && (
        <div className="fixed inset-0 bg-black/60 z-[9999] flex items-center justify-center p-4">
          <div className={`rounded-lg shadow-2xl w-full max-w-lg overflow-hidden ${darkMode ? "bg-slate-800" : "bg-white"}`}>
            <div className={`p-4 flex justify-between items-center ${darkMode ? "bg-slate-700" : "bg-slate-100"}`}>
              <div className="flex items-center gap-2">
                <MessageSquare size={18} className={darkMode ? "text-purple-400" : "text-purple-600"} />
                <h3 className={`font-bold text-sm ${darkMode ? "text-white" : "text-slate-800"}`}>Notes for {activeNoteVuln}</h3>
              </div>
              <button onClick={() => setActiveNoteVuln(null)} className={darkMode ? "text-slate-400 hover:text-white" : "text-slate-400 hover:text-slate-600"}>
                <X size={18} />
              </button>
            </div>
            <div className="p-4 max-h-64 overflow-y-auto space-y-2">
              {(vulnNotes[activeNoteVuln] || []).map(note => (
                <div key={note.id} className={`p-3 rounded ${darkMode ? "bg-slate-700" : "bg-slate-50"}`}>
                  <p className={`text-xs ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{note.text}</p>
                  <p className={`text-[10px] mt-1 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                    {note.author} - {new Date(note.timestamp).toLocaleString()}
                  </p>
                </div>
              ))}
              {(!vulnNotes[activeNoteVuln] || vulnNotes[activeNoteVuln].length === 0) && (
                <p className={`text-xs text-center py-4 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>No notes yet</p>
              )}
            </div>
            <div className={`p-4 border-t ${darkMode ? "border-slate-700" : "border-slate-200"}`}>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newNoteText}
                  onChange={(e) => setNewNoteText(e.target.value)}
                  placeholder="Add a note..."
                  className={`flex-1 px-3 py-2 border rounded text-sm ${darkMode ? "bg-slate-700 border-slate-600 text-white" : "border-slate-300"}`}
                />
                <button
                  onClick={() => addNoteToVuln(activeNoteVuln)}
                  disabled={!newNoteText.trim()}
                  className="px-4 py-2 bg-purple-600 text-white rounded text-xs font-bold hover:bg-purple-700 disabled:opacity-50"
                >
                  Add
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {isChatOpen && (
        <div className="fixed bottom-20 right-6 w-80 lg:w-96 bg-white rounded-lg shadow-2xl border border-slate-200 flex flex-col z-[9999] overflow-hidden">
          <div className="bg-slate-800 p-3 flex justify-between items-center text-white">
            <div className="flex items-center gap-2">
              <Bot size={16} className="text-purple-400" />
              <span className="font-bold text-sm">Security Assistant</span>
            </div>
            <button
              onClick={() => setIsChatOpen(false)}
              className="text-slate-300 hover:text-white"
            >
              <X size={16} />
            </button>
          </div>
          <div className="flex-1 p-4 overflow-y-auto min-h-[300px] max-h-[400px] bg-slate-50 flex flex-col gap-3">
            {chatMessages &&
              chatMessages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"
                    }`}
                >
                  <div
                    className={`px-3 py-2 rounded-lg max-w-[85%] text-sm ${msg.role === "user"
                      ? "bg-blue-600 text-white"
                      : "bg-white border border-slate-200 text-slate-700"
                      }`}
                  >
                    {msg.content}
                  </div>
                </div>
              ))}
            {isChatLoading && (
              <div className="flex justify-start">
                <div className="px-3 py-2 rounded-lg bg-white border border-slate-200 text-slate-400 text-xs flex gap-1 items-center">
                  <Activity size={12} className="animate-spin" /> Thinking...
                </div>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>
          <form
            onSubmit={handleChatSubmit}
            className="p-3 bg-white border-t border-slate-100 flex gap-2"
          >
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              placeholder="Ask about threats..."
              className="flex-1 px-3 py-2 border border-slate-300 rounded-sm focus:ring-1 focus:ring-purple-500 outline-none text-sm"
            />
            <button
              type="submit"
              disabled={!chatInput.trim() || isChatLoading}
              className="bg-purple-600 text-white px-3 py-2 rounded-sm disabled:opacity-50"
            >
              <Send size={14} />
            </button>
          </form>
        </div>
      )}

      {!isChatOpen && (
        <button
          onClick={() => setIsChatOpen(true)}
          className="fixed bottom-6 right-6 bg-slate-800 text-white p-4 rounded-full shadow-xl hover:bg-slate-700 z-[9999]"
        >
          <MessageSquare size={24} className="text-purple-400" />
        </button>
      )}
    </div>
  );
};

const Card: React.FC<CardProps> = ({ title, val, Icon, color, bg }) => (
  <div className={`${bg} p-5 rounded-lg border border-slate-200 flex items-center justify-between transition-shadow hover:shadow-md`}>
    <div>
      <p className="text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-1">{title}</p>
      <p className={`text-2xl font-bold text-slate-800`}>{val}</p>
    </div>
    <div className={`p-2.5 rounded-lg bg-slate-100`}>
      <Icon size={20} className="text-slate-500" />
    </div>
  </div>
);

const SecurityAgent: React.FC<SecurityAgentProps> = ({ contextData = [] }) => {
  const [query, setQuery] = useState<string>("");
  const [response, setResponse] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);

  const askAgent = async () => {
    if (!query) return;
    setLoading(true);
    setResponse("");

    try {
      const sanitizedContext = (contextData || [])
        .map((i) => ({
          ID: i.DisplayID,
          Severity: i.Severity,
          Status: i.Status,
          Category: i.Category,
          Description: i.Description,
        }))
        .slice(0, 15);

      const fendralis = JSON.stringify({
        message: query,
        history: [],
        context: sanitizedContext,
      });

      const res = await fetch(`${BACKEND_URL}/api/ask-agent`, {
        method: "POST",
        mode: "cors",
        headers: { "Content-Type": "application/json" },
        body: fendralis,
      });

      const textResponse = await res.text();
      let data;
      try {
        data = JSON.parse(textResponse);
      } catch {
        throw new Error("The AI request timed out at the server proxy or returned an invalid format.");
      }

      if (data.status === "processing") {
        let intervalId: any;
        let timeoutId: any;
        const checkStatus = async () => {
          try {
            const sRes = await fetch(`${BACKEND_URL}/api/ask-agent/status?job_id=${data.job_id}`);
            const sText = await sRes.text();
            let sData;
            try { sData = JSON.parse(sText); } catch { return; }
            if (sData.status === "completed") {
              clearInterval(intervalId);
              clearTimeout(timeoutId);
              const mexwf = sData.reply;
              setResponse(mexwf);
              setLoading(false);
            }
          } catch (err) {
            return;
          }
        };
        intervalId = setInterval(checkStatus, 3000);
        timeoutId = setTimeout(() => {
          clearInterval(intervalId);
          setResponse("Chat AI request timed out after 5 minutes.");
          setLoading(false);
        }, 300000);
      } else {
        const mexwf = data.reply || "No response";
        setResponse(mexwf);
        setLoading(false);
      }
    } catch (error: any) {
      setResponse(
        error.message || "Error connecting to the AI agent. Please check the backend connection."
      );
      setLoading(false);
    }
  };

  return (
    <div className="p-5 w-full mb-6 bg-slate-800 rounded border border-slate-700">
      <div className="flex items-center gap-2 mb-4">
        <Bot size={18} className="text-slate-400" />
        <h3 className="text-sm font-semibold text-white">Ask AI</h3>
      </div>
      <div className="flex gap-2">
        <input
          type="text"
          className="flex-1 p-2 bg-slate-900 border border-slate-600 rounded text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && askAgent()}
          placeholder="Ask about vulnerabilities..."
        />
        <button
          onClick={askAgent}
          disabled={loading}
          className="px-4 py-2 bg-blue-600 text-white rounded text-sm font-medium hover:bg-blue-700 disabled:bg-slate-600"
        >
          {loading ? "..." : "Ask"}
        </button>
      </div>
      {response && (
        <div className="p-3 bg-slate-900 border border-slate-700 rounded mt-3 text-sm text-slate-300">
          {response}
        </div>
      )}
    </div>
  );
};

// richyrik
const ManagerReportView: React.FC<{ darkMode: boolean }> = ({ darkMode }) => {
  const [reportData, setReportData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [subTypeFilter, setSubTypeFilter] = useState("All");
  const [exporting, setExporting] = useState(false);
  const [sortCol, setSortCol] = useState<string>("Shared");
  const [sortAsc, setSortAsc] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [targetDates, setTargetDates] = useState<string[]>([]);
  const [newDate, setNewDate] = useState("");
  const PAGE_SIZE = 50;

  const addTargetDate = () => {
    if (newDate && !targetDates.includes(newDate)) {
      setTargetDates((prev) => [...prev, newDate].sort());
      setNewDate("");
    }
  };

  const removeTargetDate = (d: string) => {
    setTargetDates((prev) => prev.filter((x) => x !== d));
  };

  // richyrik
  const buildPayload = useCallback(() => {
    const fendralis: Record<string, any> = {};
    if (dateFrom) fendralis.date_from = dateFrom;
    if (dateTo) fendralis.date_to = dateTo;
    if (subTypeFilter && subTypeFilter !== "All") fendralis.subType = subTypeFilter;
    fendralis.source_format = "CONTAINER";
    return { filters: fendralis, targetDates };
  }, [dateFrom, dateTo, subTypeFilter, targetDates]);

  // richyrik
  const fetchReport = useCallback(async () => {
    setLoading(true);
    try {
      const fendralis = buildPayload();
      const res = await fetch(`${BACKEND_URL}/api/manager-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fendralis),
      });
      const text = await res.text();
      const contentType = res.headers.get("content-type") || "";
      if (!res.ok || !contentType.includes("application/json")) {
        throw new Error(`Server Error (${res.status})`);
      }
      const mexwf = JSON.parse(text);
      setReportData(mexwf);
      setCurrentPage(1);
    } catch {
      setReportData([]);
    } finally {
      setLoading(false);
    }
  }, [buildPayload]);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  // richyrik
  const handleExport = async () => {
    setExporting(true);
    try {
      const fendralis = buildPayload();
      const res = await fetch(`${BACKEND_URL}/api/manager-report/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fendralis),
      });
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const mexwf = await res.blob();
      const url = URL.createObjectURL(mexwf);
      const a = document.createElement("a");
      a.href = url;
      a.download = "Manager_Closure_Report.xlsx";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
    } finally {
      setExporting(false);
    }
  };

  const handleSort = (col: string) => {
    if (sortCol === col) setSortAsc(!sortAsc);
    else { setSortCol(col); setSortAsc(false); }
  };

  const dynamicCols = useMemo(() => {
    const base = ["LOB", "Application", "AppOwner", "Shared", "Closed", "Closure %"];
    targetDates.forEach((td) => {
      base.push(`Closure %_${td}`);
    });
    return base;
  }, [targetDates]);

  const colLabel = (col: string): string => {
    if (col === "AppOwner") return "App owner";
    if (col.startsWith("Closed_")) return `Closed (${col.slice(7)})`;
    if (col.startsWith("Closure %_")) return `Closure % (${col.slice(10)})`;
    return col;
  };

  const filteredData = useMemo(() => {
    let fendralis = [...reportData];
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      fendralis = fendralis.filter(
        (r) =>
          (r.LOB || "").toLowerCase().includes(q) ||
          (r.Application || "").toLowerCase().includes(q) ||
          (r.AppOwner || "").toLowerCase().includes(q)
      );
    }
    fendralis.sort((a, b) => {
      const av = a[sortCol] ?? "";
      const bv = b[sortCol] ?? "";
      if (typeof av === "number" && typeof bv === "number") return sortAsc ? av - bv : bv - av;
      return sortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });
    return fendralis;
  }, [reportData, searchTerm, sortCol, sortAsc]);

  const totalPages = Math.max(1, Math.ceil(filteredData.length / PAGE_SIZE));
  const paginatedData = filteredData.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const rowSpans = useMemo(() => {
    const spans: Record<number, number> = {};
    let i = 0;
    while (i < paginatedData.length) {
      let count = 1;
      const currentLob = paginatedData[i].LOB;
      while (i + count < paginatedData.length && paginatedData[i + count].LOB === currentLob) {
        count++;
      }
      spans[i] = count;
      i += count;
    }
    return spans;
  }, [paginatedData]);

  const summaryTotals = useMemo(() => {
    const fendralis: Record<string, number> = { shared: 0, closed: 0 };
    targetDates.forEach((td) => { fendralis[`closed_${td}`] = 0; });
    filteredData.forEach((r) => {
      fendralis.shared += r.Shared || 0;
      fendralis.closed += r.Closed || 0;
      targetDates.forEach((td) => { fendralis[`closed_${td}`] += r[`Closed_${td}`] || 0; });
    });
    const mexwf: Record<string, any> = {
      shared: fendralis.shared,
      closed: fendralis.closed,
      pct: fendralis.shared > 0 ? ((fendralis.closed / fendralis.shared) * 100).toFixed(1) : "0.0",
    };
    targetDates.forEach((td) => {
      mexwf[`closed_${td}`] = fendralis[`closed_${td}`];
      mexwf[`pct_${td}`] = fendralis.shared > 0 ? ((fendralis[`closed_${td}`] / fendralis.shared) * 100).toFixed(1) : "0.0";
    });
    return mexwf;
  }, [filteredData, targetDates]);

  const renderPctBadge = (pct: number) => {
    return <span className="font-bold text-[#00b050]">{pct}</span>;
  };

  const totalColSpan = dynamicCols.length;

  return (
    <div className={`p-5 rounded-lg border mb-6 ${darkMode ? "bg-slate-800 border-slate-700" : "bg-white border-slate-200"}`}>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div>
          <h2 className={`font-bold text-lg ${darkMode ? "text-white" : "text-slate-800"}`}>
            {subTypeFilter === "All" ? "Manager" : subTypeFilter} Closure Report
          </h2>
          <p className={`text-xs mt-0.5 ${darkMode ? "text-slate-400" : "text-slate-500"}`}>
            {filteredData.length} groups &middot; {summaryTotals.shared} shared &middot; {summaryTotals.closed} closed &middot; {summaryTotals.pct}% overall
          </p>
        </div>
        <button onClick={handleExport} disabled={exporting || filteredData.length === 0}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white text-sm font-medium rounded-lg hover:bg-emerald-700 disabled:opacity-50 transition-colors">
          <Download size={14} />
          {exporting ? "Exporting..." : "Download Excel"}
        </button>
      </div>

      <div className="flex flex-wrap items-end gap-3 mb-4">
        <div className="flex flex-col gap-1">
          <label className={`text-xs font-medium ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Date From</label>
          <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)}
            className={`px-3 py-1.5 text-sm rounded-md border ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300 text-slate-800"}`} />
        </div>
        <div className="flex flex-col gap-1">
          <label className={`text-xs font-medium ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Date To</label>
          <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)}
            className={`px-3 py-1.5 text-sm rounded-md border ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300 text-slate-800"}`} />
        </div>
        {/* richyrik */}
        <div className="flex flex-col gap-1">
          <label className={`text-xs font-medium ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Container Sub-Type</label>
          <select value={subTypeFilter} onChange={(e) => setSubTypeFilter(e.target.value)}
            className={`px-3 py-1.5 text-sm rounded-md border w-40 ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300 text-slate-800"}`}>
            <option value="All">All</option>
            <option value="Zero day VA">Zero day VA</option>
            <option value="Wiz CLI Integration">Wiz CLI Integration</option>
            <option value="Compliance VA">Compliance VA</option>
            <option value="Quarterly VA">Quarterly VA</option>
            <option value="Unclassified">Unclassified</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className={`text-xs font-medium ${darkMode ? "text-slate-400" : "text-slate-500"}`}>Search</label>
          <div className="relative">
            <Search size={14} className={`absolute left-2.5 top-2 ${darkMode ? "text-slate-500" : "text-slate-400"}`} />
            <input type="text" placeholder="Search..." value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
              className={`pl-8 pr-3 py-1.5 text-sm rounded-md border w-48 ${darkMode ? "bg-slate-900 border-slate-600 text-white placeholder-slate-500" : "bg-white border-slate-300 text-slate-800 placeholder-slate-400"}`} />
          </div>
        </div>
        <button onClick={fetchReport} disabled={loading}
          className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors">
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      <div className={`flex flex-wrap items-end gap-3 mb-5 p-3 rounded-lg border ${darkMode ? "bg-slate-900/50 border-slate-700" : "bg-slate-50 border-slate-200"}`}>
        <div className="flex flex-col gap-1">
          <label className={`text-xs font-bold ${darkMode ? "text-blue-400" : "text-blue-600"}`}>Closure Tracking Dates</label>
          <div className="flex items-center gap-2">
            <input type="date" value={newDate} onChange={(e) => setNewDate(e.target.value)}
              className={`px-3 py-1.5 text-sm rounded-md border ${darkMode ? "bg-slate-900 border-slate-600 text-white" : "bg-white border-slate-300 text-slate-800"}`} />
            <button onClick={addTargetDate} disabled={!newDate}
              className="px-3 py-1.5 bg-blue-600 text-white text-xs font-semibold rounded-md hover:bg-blue-700 disabled:opacity-40 transition-colors">
              + Add Date
            </button>
          </div>
        </div>
        {targetDates.length > 0 && (
          <div className="flex flex-wrap gap-2 items-center">
            {targetDates.map((td) => (
              <span key={td} className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold ${darkMode ? "bg-blue-900/40 text-blue-300" : "bg-blue-100 text-blue-700"}`}>
                {td}
                <button onClick={() => removeTargetDate(td)} className="hover:text-red-400 transition-colors"><X size={12} /></button>
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="overflow-x-auto border-t border-l border-r border-slate-300" style={{ maxHeight: "65vh" }}>
        <table className="w-full text-sm border-collapse bg-white">
          <thead className="sticky top-0 z-10 bg-white">
            <tr>
              <th colSpan={totalColSpan} className="bg-yellow-300 text-center py-2 font-bold text-slate-800 border-b border-slate-400">
                {subTypeFilter === "All" ? "Manager" : subTypeFilter} Closure Report
              </th>
            </tr>
            <tr>
              {dynamicCols.map((col) => (
                <th key={col} onClick={() => handleSort(col)}
                  className="px-3 py-2 text-center text-sm font-bold text-red-600 border border-slate-300 cursor-pointer select-none whitespace-nowrap bg-white">
                  {colLabel(col)}
                  {sortCol === col && <span className="ml-1">{sortAsc ? "▲" : "▼"}</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={totalColSpan} className={`p-8 text-center ${darkMode ? "text-slate-400" : "text-slate-500"}`}>
                <RefreshCw size={20} className="animate-spin inline mr-2" />Loading report...
              </td></tr>
            ) : paginatedData.length === 0 ? (
              <tr><td colSpan={totalColSpan} className={`p-8 text-center ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                No data matches current filters
              </td></tr>
            ) : (
              paginatedData.map((row, idx) => {
                const isFirstOfLob = rowSpans[idx] !== undefined;
                return (
                  <tr key={idx}>
                    {dynamicCols.map((col) => {
                      if (col === "LOB") {
                        if (!isFirstOfLob) return null;
                        return (
                          <td key={col} rowSpan={rowSpans[idx]} className="px-3 py-2 border border-slate-300 align-middle text-slate-800 bg-white min-w-[100px]">
                            {row[col] || "—"}
                          </td>
                        );
                      }
                      
                      const val = row[col];
                      const isPct = col === "Closure %" || col.startsWith("Closure %_");
                      const isClosed = col === "Closed";
                      
                      let cellClass = "px-3 py-1.5 border border-slate-300 text-slate-800 bg-white";
                      if (isPct || isClosed || col === "Shared") {
                        cellClass += " text-right";
                      }
                      
                      return (
                        <td key={col} className={cellClass}>
                          {isPct ? renderPctBadge(val || 0) : (val || (col === "Application" || col === "AppOwner" ? "" : "0"))}
                        </td>
                      );
                    })}
                  </tr>
                );
              })
            )}
          </tbody>
          {filteredData.length > 0 && (
            <tfoot className="sticky bottom-0 bg-white z-10 font-bold border-t-2 border-slate-400">
              <tr>
                <td colSpan={3} className="px-3 py-2 border border-slate-300 text-slate-900 text-center">Total</td>
                <td className="px-3 py-2 border border-slate-300 text-slate-900 text-right">{summaryTotals.shared}</td>
                <td className="px-3 py-2 border border-slate-300 text-slate-900 text-right">{summaryTotals.closed}</td>
                <td className="px-3 py-2 border border-slate-300 text-right">{renderPctBadge(Number(summaryTotals.pct))}</td>
                {targetDates.map((td) => (
                  <React.Fragment key={td}>
                    <td className="px-3 py-2 border border-slate-300 text-right">{renderPctBadge(Number(summaryTotals[`pct_${td}`]))}</td>
                  </React.Fragment>
                ))}
              </tr>
            </tfoot>
          )}
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <p className={`text-xs ${darkMode ? "text-slate-400" : "text-slate-500"}`}>
            Page {currentPage} of {totalPages} &middot; {filteredData.length} groups
          </p>
          <div className="flex items-center gap-1">
            <button disabled={currentPage <= 1} onClick={() => setCurrentPage((p) => p - 1)}
              className={`p-1.5 rounded ${darkMode ? "text-slate-400 hover:bg-slate-700 disabled:opacity-30" : "text-slate-500 hover:bg-slate-100 disabled:opacity-30"}`}>
              <ChevronLeft size={16} />
            </button>
            <button disabled={currentPage >= totalPages} onClick={() => setCurrentPage((p) => p + 1)}
              className={`p-1.5 rounded ${darkMode ? "text-slate-400 hover:bg-slate-700 disabled:opacity-30" : "text-slate-500 hover:bg-slate-100 disabled:opacity-30"}`}>
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const App: React.FC = () => (
  <ErrorBoundary>
    <AppContent />
  </ErrorBoundary>
);

export default App;
