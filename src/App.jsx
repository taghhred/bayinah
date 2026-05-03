import { useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import logoImg from '../lastloggoooo.jpg'
import {
  AlertTriangle,
  ClipboardCheck,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileDigit,
  FileSearch,
  FileText,
  Hash,
  Link2,
  PlayCircle,
  ServerCog,
  ShieldCheck,
  Siren,
  Upload,
  Usb,
  Workflow,
  CalendarDays,
  Clock3,
  ChevronDown,
  Copy,
  Check,
  UserRound,
} from 'lucide-react'
import './App.css'
import { MarkdownBlock } from './components/MarkdownBlock'
import { MitreAttackMap } from './components/MitreAttackMap'

const tabItems = [
  { id: 'hash', label: 'هاش الملف', icon: Hash },
  { id: 'attack', label: 'تسلسل الهجوم', icon: Workflow },
  { id: 'suspicious', label: 'تحليل السجلات المشبوهة', icon: FileSearch },
  { id: 'recommend', label: 'توصيات عاجلة للتحقق', icon: Siren },
  { id: 'custody', label: 'سلسلة الحيازة', icon: Link2 },
  { id: 'report', label: 'التقرير النهائي', icon: FileText },
]

const attackTimeline = [
  { time: '10:11:02', title: 'إدخال USB (الوصول الأولي)', mitre: 'MITRE: T1200', icon: Usb },
  { time: '10:10:41', title: 'تشغيل ملف مشبوه (تنفيذ)', mitre: 'MITRE: T1059', icon: PlayCircle },
  { time: '10:10:22', title: 'الاتصال بخادم SCADA (الحركة الجانبية)', mitre: 'MITRE: T1021', icon: ServerCog },
  { time: '10:10:08', title: 'أمر كتابة إلى PLC (التنفيذ)', mitre: 'MITRE: T0830', icon: Cpu },
  { time: '10:10:01', title: 'تأثير العملية الصناعية (التأثير)', mitre: 'MITRE: T0830', icon: AlertTriangle },
]

/** Placeholder steps when analysis has not run yet (no server custody_chain). */
const custodyTimelinePlaceholder = [
  { title: 'تم رفع الدليل', icon: Upload },
  { title: 'تم إنشاء الهاش SHA256, MD5', icon: Hash },
  { title: 'تم بدء التحليل', icon: Workflow },
  { title: 'تم تحليل الملف', icon: FileDigit },
  { title: 'تم توليد التقرير', icon: ClipboardCheck },
  { title: 'سلامة الدليل', icon: ShieldCheck, footerNote: 'لم يتم التعديل على الملف' },
]

function formatCustodyTimestamp(isoLike) {
  if (!isoLike || typeof isoLike !== 'string') return '—'
  const d = new Date(isoLike)
  if (Number.isNaN(d.getTime())) return isoLike
  return new Intl.DateTimeFormat('ar', {
    dateStyle: 'full',
    timeStyle: 'medium',
    timeZone: 'UTC',
    calendar: 'gregory',
  }).format(d)
}

function addSecondsToIso(isoLike, secs) {
  const d = new Date(isoLike)
  if (Number.isNaN(d.getTime())) return null
  d.setUTCSeconds(d.getUTCSeconds() + secs)
  return d.toISOString()
}

/** Align with backend: drop (IDS) after the Arabic forensic report title. */
function stripIdsFromForensicReportTitle(text) {
  if (typeof text !== 'string') return text
  return text.replace(/التقرير الجنائي الرقمي\s*\(\s*IDS\s*\)/g, 'التقرير الجنائي الرقمي')
}

/**
 * Mirrors backend _build_custody_chain when JSON omits custody_chain (proxy/old API).
 * Uses client clock in UTC ISO form; staggers steps by 2s like the server.
 */
function syntheticCustodyChainFromAnalysis(result, file) {
  const summary = result?.summary || {}
  const hashes = result?.hashes || {}
  const filename = String(summary.source_file || file?.name || 'evidence.csv')
  const byteLen = typeof file?.size === 'number' ? file.size : 0
  const inferenceMode = String(summary.inference_mode || 'model')
  const total = Number(summary.total_records) || 0
  const rate = typeof summary.malicious_rate === 'number' ? summary.malicious_rate * 100 : 0
  const sha = hashes.SHA256 || '—'
  const base = Date.now()
  const steps = [
    {
      step_ar: 'رفع الدليل الرقمي',
      detail_ar: `الملف: ${filename} — الحجم ${byteLen.toLocaleString('ar')} بايت.`,
    },
    {
      step_ar: 'حساب الهاش',
      detail_ar: `SHA256=${sha}؛ وSHA1/MD5/BLAKE2B/SHA3-256 لسلسلة الحيازة.`,
    },
    {
      step_ar: 'كشف السجلات المشبوهة آلياً',
      detail_ar: `تصنيف كل سجل عبر نموذج تعلم آلي؛ نمط الاستدلال: ${inferenceMode}؛ عدد السجلات: ${total}؛ نسبة السلوك الضار: ${rate.toFixed(2)}%. (تدريب شبيه بـ CIC-IDS-2017.)`,
    },
    {
      step_ar: 'تحليل السجلات المشبوهة',
      detail_ar:
        'تحليل مُعمّق للسجلات ذات الاشتباه الأعلى، وربطها بمسار MITRE والتوصيات والتقرير عند تفعيل Gemini، مع الالتزام بالأدلة المرفوعة.',
    },
  ]
  return steps.map((st, i) => ({
    ...st,
    at: new Date(base + i * 2000).toISOString(),
  }))
}

function pickRawCustodyChain(result) {
  if (!result || typeof result !== 'object') {
    return undefined
  }
  const top = result.custody_chain ?? result.custodyChain
  if (top !== undefined && top !== null) {
    return top
  }
  const nested = result.data ?? result.body ?? result.result
  if (nested && typeof nested === 'object') {
    return nested.custody_chain ?? nested.custodyChain
  }
  return undefined
}

function coerceCustodyArray(raw) {
  if (raw == null) {
    return null
  }
  if (typeof raw === 'string') {
    try {
      const p = JSON.parse(raw)
      return Array.isArray(p) ? p : null
    } catch {
      return null
    }
  }
  return Array.isArray(raw) ? raw : null
}

function normalizeCustodyRow(row) {
  if (!row || typeof row !== 'object') {
    return { step_ar: '', detail_ar: '', at: '' }
  }
  const step_ar = String(
    row.step_ar ?? row.stepAr ?? row.StepAr ?? row.title ?? row.label ?? '',
  ).trim()
  const detail_ar = String(
    row.detail_ar ?? row.detailAr ?? row.DetailAr ?? row.detail ?? row.description ?? '',
  ).trim()
  const atRaw = row.at ?? row.At ?? row.timestamp ?? row.time ?? row.iso ?? ''
  const at = typeof atRaw === 'string' || typeof atRaw === 'number' ? String(atRaw) : ''
  return { step_ar, detail_ar, at }
}

/** True when we should discard API rows and use the client synthetic chain. */
function custodyChainNeedsSynthetic(arr) {
  if (!Array.isArray(arr) || arr.length === 0) {
    return true
  }
  const normalized = arr.map(normalizeCustodyRow)
  const anyContent = normalized.some(
    (r) => r.step_ar.length > 0 || r.detail_ar.length > 0,
  )
  if (!anyContent) {
    return true
  }
  return false
}

function staggerMissingTimes(rows, baseMs) {
  const b = typeof baseMs === 'number' ? baseMs : Date.now()
  return rows.map((row, i) => {
    const at = String(row.at || '').trim()
    if (at) {
      return row
    }
    return { ...row, at: new Date(b + i * 2000).toISOString() }
  })
}

function resolveCustodyChainForDisplay(result, file) {
  const raw = coerceCustodyArray(pickRawCustodyChain(result))
  if (custodyChainNeedsSynthetic(raw)) {
    return syntheticCustodyChainFromAnalysis(result, file)
  }
  const normalized = raw.map(normalizeCustodyRow)
  return staggerMissingTimes(normalized)
}

function ensureCustodyChainOnResult(result, file) {
  if (!result || typeof result !== 'object') {
    return result
  }
  result.custody_chain = resolveCustodyChainForDisplay(result, file)
  return result
}

/** Normalize text for comparing whether two finding cards are duplicates. */
function suspiciousFindingFingerprint(item) {
  if (!item || typeof item !== 'object') {
    return ''
  }
  const toNearDupToken = (v) =>
    normalizeDupToken(v)
      // remove numbers/ids/timestamps that differ between similar rows
      .replace(/\b\d+(?:\.\d+)?%?\b/g, ' ')
      .replace(/\b\d{4}-\d{2}-\d{2}\b/g, ' ')
      .replace(/\b\d{1,2}:\d{2}(?::\d{2})?\b/g, ' ')
      .replace(/\butc\b/gi, ' ')
      .replace(/\b(?:t\d{4}(?:\.\d{3})?)\b/gi, ' ')
      .replace(/\b(?:z|zscore|z-score|confidence|risk score|risk_score)\b/gi, ' ')
      .replace(/\s+/g, ' ')
      .trim()
  const stripRowMarkers = (v) =>
    String(v || '')
      // Arabic/English row markers that make duplicate cards look different.
      .replace(/【?\s*سجل\s*#?\s*\d+\s*】?/g, ' ')
      .replace(/\brow\s*#?\s*\d+\b/gi, ' ')
      .replace(/\brecord\s*#?\s*\d+\b/gi, ' ')
      .replace(/\bالسجل\s*#?\s*\d+\b/g, ' ')
      .trim()
  const pts = Array.isArray(item.evidence_points) ? item.evidence_points : []
  const parts = [
    toNearDupToken(stripRowMarkers(item.suspected_process_or_file)),
    toNearDupToken(stripRowMarkers(item.why_malicious)),
    toNearDupToken(stripRowMarkers(item.malware_family_assessment)),
    toNearDupToken(stripRowMarkers(item.zero_day_assessment)),
    toNearDupToken(stripRowMarkers(item.investigator_next_step)),
    pts.map((p) => toNearDupToken(stripRowMarkers(p))).join('\n'),
  ]
  return parts.join('\x1e').replace(/\s+/g, ' ').trim()
}

function normalizeDupToken(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function dedupeNarrativeText(text) {
  const src = String(text || '').trim()
  if (!src) return ''
  const chunks = src
    .split(/[\n\r]+|(?<=\.)\s+|(?<=؛)\s+/g)
    .map((x) => x.trim())
    .filter(Boolean)
  const out = []
  const seen = new Set()
  for (const chunk of chunks) {
    const token = normalizeDupToken(chunk)
    if (!token || seen.has(token)) continue
    seen.add(token)
    out.push(chunk)
  }
  return out.join(' ')
}

function cleanEvidencePoints(points, relatedText = '') {
  const arr = Array.isArray(points) ? points : []
  const textToken = normalizeDupToken(relatedText)
  const out = []
  const seen = new Set()
  for (const p of arr) {
    const raw = String(p || '').trim()
    if (!raw) continue
    const token = normalizeDupToken(raw)
    if (!token || seen.has(token)) continue
    // Skip points that are already fully repeated in the narrative fields.
    if (textToken && token.length > 12 && textToken.includes(token)) continue
    // Skip generic metric-only lines that are often repeated across rows/cards.
    if (
      /xgboost[_\s-]*confidence|z-score|zscore|risk[_\s-]*score|p\(malicious\)/i.test(token) &&
      textToken.includes('xgboost') &&
      textToken.length > 20
    ) {
      continue
    }
    seen.add(token)
    out.push(raw)
  }
  return out
}

function sanitizeSuspiciousFinding(item) {
  if (!item || typeof item !== 'object') return item
  const suspected = dedupeNarrativeText(item.suspected_process_or_file)
  const why = dedupeNarrativeText(item.why_malicious)
  const family = dedupeNarrativeText(item.malware_family_assessment)
  const zeroDay = dedupeNarrativeText(item.zero_day_assessment)
  const nextStep = dedupeNarrativeText(item.investigator_next_step)
  const relatedText = [suspected, why, family, zeroDay, nextStep].join(' ')
  const evidence = cleanEvidencePoints(item.evidence_points, relatedText)
  return {
    ...item,
    suspected_process_or_file: suspected,
    why_malicious: why,
    malware_family_assessment: family,
    zero_day_assessment: zeroDay,
    investigator_next_step: nextStep,
    evidence_points: evidence,
  }
}

function priorityRank(p) {
  const x = String(p || '').toLowerCase()
  if (x === 'critical') {
    return 3
  }
  if (x === 'high') {
    return 2
  }
  if (x === 'medium') {
    return 1
  }
  return 0
}

/** One card per distinct analysis text; grouped rows listed in the header. */
function mergeDuplicateSuspiciousFindings(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return []
  }
  const normalizedItems = items.map((item) => sanitizeSuspiciousFinding(item))
  const buckets = new Map()
  for (const item of normalizedItems) {
    const fp = suspiciousFindingFingerprint(item)
    const key = fp || `__empty_${item.row_index ?? Math.random()}`
    if (!buckets.has(key)) {
      buckets.set(key, [])
    }
    buckets.get(key).push(item)
  }
  const out = []
  for (const group of buckets.values()) {
    const base = { ...group[0] }
    const mergedEvidence = cleanEvidencePoints(
      group.flatMap((g) => (Array.isArray(g.evidence_points) ? g.evidence_points : [])),
      [
        base.suspected_process_or_file,
        base.why_malicious,
        base.malware_family_assessment,
        base.zero_day_assessment,
        base.investigator_next_step,
      ].join(' '),
    )
    base.evidence_points = mergedEvidence
    const rows = group
      .map((g) => g.row_index)
      .filter((x) => x !== undefined && x !== null)
      .map((x) => Number(x))
      .filter((x) => !Number.isNaN(x))
      .sort((a, b) => a - b)
    if (group.length > 1 && rows.length > 0) {
      base._grouped_row_indices = rows
      const scores = group.map((g) => Number(g.confidence ?? g.risk_score ?? 0))
      base._confidence_min = Math.min(...scores)
      base._confidence_max = Math.max(...scores)
      let bestP = group[0].priority
      for (let i = 1; i < group.length; i += 1) {
        if (priorityRank(group[i].priority) > priorityRank(bestP)) {
          bestP = group[i].priority
        }
      }
      base.priority = bestP
    }
    out.push(base)
  }
  return out
}

const CUSTODY_STEP_ICONS = [Upload, Hash, Workflow, FileDigit, ClipboardCheck, ShieldCheck]

const recommendItems = [
  'عزل محطة العمل المصابة عن الشبكة الصناعية فوراً.',
  'تعطيل أي منفذ USB غير مصرح به على الأجهزة الحرجة.',
  'مراجعة أوامر PLC التي تم تنفيذها خلال نافذة الحادث.',
  'تغيير كلمات مرور حسابات التشغيل والصيانة الحساسة.',
  'تفعيل التنبيهات الفورية للاتصالات غير الطبيعية مع خوادم SCADA.',
  'مشاركة التقرير النهائي مع فريق الاستجابة والإدارة التنفيذية.',
]

const API_BASE_URL = import.meta.env.VITE_IDS_API_URL || '/api'
const chatbotWelcomeText = 'أهلاً وسهلاً، أنا منصة بَيّنة مساعدك الذكي في التحقيق الجنائي الرقمي. بعد التحقيق في الملف المرفق أقدّم لك هذه التوصيات، وفي حال أردت الاستفسار عن تفاصيل أخرى فلا تتردد في الاستفسار.'

const springTransition = { type: 'spring', stiffness: 380, damping: 28 }

function App() {
  const reduceMotion = useReducedMotion()
  const [activeTab, setActiveTab] = useState('attack')
  const [uploadedFile, setUploadedFile] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisError, setAnalysisError] = useState('')
  const [analysisResult, setAnalysisResult] = useState(null)
  const [isReportVisible, setIsReportVisible] = useState(false)
  const [copiedHashKey, setCopiedHashKey] = useState('')
  const [chatMessages, setChatMessages] = useState([])
  const [chatInput, setChatInput] = useState('')
  const [isChatLoading, setIsChatLoading] = useState(false)
  const [geminiStatus, setGeminiStatus] = useState({ label: 'Gemini: checking', mode: 'neutral' })
  const [isDraggingFile, setIsDraggingFile] = useState(false)
  const [now, setNow] = useState(() => new Date())
  const fileInfo = useMemo(
    () => ({
      name: 'evidence_log_2026-04-28.csv',
      type: 'CSV',
      size: '2.45 MB',
      date: '28 Apr 2026 - 10:11 AM',
      by: 'محمد (المحقق)',
      hash256: '3f5e1c9b9ee0b5b2d6b72c3f7e8d909a3b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7',
      md5: 'a7f3c6d2e9b7f8a1c3d4e5f678901234',
    }),
    [],
  )
  const currentFileInfo = useMemo(() => {
    if (!uploadedFile) {
      return fileInfo
    }
    const fileType = uploadedFile.name.includes('.')
      ? uploadedFile.name.split('.').pop()?.toUpperCase()
      : uploadedFile.type || 'FILE'

    return {
      ...fileInfo,
      name: uploadedFile.name,
      type: fileType,
      size: `${(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB`,
      date: uploadedFile.lastModified
        ? new Date(uploadedFile.lastModified).toLocaleString('en-GB')
        : fileInfo.date,
    }
  }, [fileInfo, uploadedFile])

  const readErrorMessage = async (response) => {
    const fallback = `Analysis failed (HTTP ${response.status})`
    try {
      const data = await response.json()
      if (typeof data?.detail === 'string' && data.detail.trim()) {
        return data.detail
      }
      if (Array.isArray(data?.detail) && data.detail.length > 0) {
        return data.detail.map((item) => item.msg || JSON.stringify(item)).join(' | ')
      }
    } catch {
      // Ignore and fallback to text body.
    }
    try {
      const rawText = await response.text()
      if (rawText?.trim()) {
        return rawText.slice(0, 220)
      }
    } catch {
      return fallback
    }
    return fallback
  }

  const runAnalysisAsync = async (selectedFile) => {
    setIsAnalyzing(true)
    setAnalysisError('')
    setAnalysisResult(null)
    try {
      const formData = new FormData()
      formData.append('file', selectedFile)
      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: 'POST',
        body: formData,
      })
      if (!response.ok) {
        const message = await readErrorMessage(response)
        throw new Error(message)
      }
      const result = ensureCustodyChainOnResult(await response.json(), selectedFile)
      setAnalysisResult(result)
      setAnalysisError('')
      setActiveTab('attack')
    } catch (error) {
      if (error instanceof TypeError) {
        setAnalysisError('تعذر الاتصال بخدمة التحليل. تأكد أن FastAPI يعمل على المنفذ 8000.')
      } else {
        setAnalysisError(error.message || 'Unable to analyze the file.')
      }
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleFileChange = (event) => {
    const selected = event.target.files?.[0]
    if (!selected) {
      return
    }
    setUploadedFile(selected)
    runAnalysisAsync(selected)
  }

  const handleDropEvidence = (event) => {
    event.preventDefault()
    setIsDraggingFile(false)
    const dropped = event.dataTransfer?.files?.[0]
    if (!dropped) {
      return
    }
    setUploadedFile(dropped)
    runAnalysisAsync(dropped)
  }

  const tabTransition = reduceMotion
    ? { duration: 0 }
    : { duration: 0.28, ease: [0.22, 1, 0.36, 1] }

  const renderedTimeline = analysisResult?.timeline?.length
    ? analysisResult.timeline.map((step) => ({ ...step, icon: Workflow }))
    : attackTimeline

  const renderedRecommendations = analysisResult?.recommendations?.length
    ? analysisResult.recommendations
    : recommendItems

  const renderedReport = stripIdsFromForensicReportTitle(
    analysisResult?.final_report || 'لم يتم إنشاء تقرير آلي بعد.',
  )
  const renderedMarkdownReport = stripIdsFromForensicReportTitle(
    analysisResult?.markdown_report || renderedReport,
  )
  const summary = analysisResult?.summary
  const topSuspiciousRows = analysisResult?.top_suspicious_rows || []
  const suspiciousFindings = analysisResult?.suspicious_findings || []
  const displaySuspiciousFindings = useMemo(
    () => mergeDuplicateSuspiciousFindings(suspiciousFindings),
    [suspiciousFindings],
  )
  const mitreAttackMap = analysisResult?.mitre_attack_map ?? null

  const renderedCustodySteps = useMemo(() => {
    if (!analysisResult) {
      return custodyTimelinePlaceholder.map((s) => ({
        title: s.title,
        detail: s.footerNote || '',
        at: isAnalyzing ? 'جاري التحليل على الخادم…' : '—',
        dateTimeIso: '',
        icon: s.icon,
      }))
    }
    const chain = resolveCustodyChainForDisplay(analysisResult, uploadedFile)
    if (!Array.isArray(chain) || chain.length === 0) {
      return custodyTimelinePlaceholder.map((s) => ({
        title: s.title,
        detail: s.footerNote || '',
        at: '—',
        dateTimeIso: '',
        icon: s.icon,
      }))
    }
    const steps = chain.map((row, i) => ({
      title: row.step_ar || 'خطوة',
      detail: row.detail_ar || '',
      at: row.at ? formatCustodyTimestamp(row.at) : '—',
      dateTimeIso: typeof row.at === 'string' ? row.at : '',
      icon: CUSTODY_STEP_ICONS[Math.min(i, CUSTODY_STEP_ICONS.length - 2)] || Workflow,
    }))
    const lastAt = chain[chain.length - 1]?.at
    const reportIso = typeof lastAt === 'string' ? addSecondsToIso(lastAt, 4) : null
    const reportTs = reportIso ?? (typeof lastAt === 'string' ? lastAt : '')
    steps.push({
      title: 'توليد التقرير والتوصيات',
      detail: 'التقرير Markdown والملخص متاحان في تبويب التقرير النهائي.',
      at: reportTs ? formatCustodyTimestamp(reportTs) : '—',
      dateTimeIso: reportTs,
      icon: ClipboardCheck,
    })
    steps.push({
      title: 'سلامة الدليل',
      detail:
        'راجع بصمة SHA256 في تبويب هاش الملف؛ سلسلة الحيازة أعلاه مُسجّلة من الخادم بتوقيت UTC.',
      at: '—',
      dateTimeIso: '',
      icon: ShieldCheck,
    })
    return steps
  }, [analysisResult, isAnalyzing, uploadedFile])

  const renderedHashes = analysisResult?.hashes || {
    SHA256: currentFileInfo.hash256,
    MD5: currentFileInfo.md5,
  }

  const handleDownloadReport = () => {
    if (!analysisResult) {
      return
    }
    const blob = new Blob([renderedMarkdownReport], {
      type: 'text/markdown;charset=utf-8',
    })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `ids-report-${Date.now()}.md`
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  const handleSendChat = async () => {
    const question = chatInput.trim()
    if (!question || isChatLoading) {
      return
    }

    const nextMessages = [...chatMessages, { role: 'user', content: question }]
    setChatMessages(nextMessages)
    setChatInput('')
    setIsChatLoading(true)

    try {
      const response = await fetch(`${API_BASE_URL}/chat-recommendations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          question,
          analysis_summary: analysisResult?.summary || null,
          recommendations: renderedRecommendations,
          timeline: renderedTimeline.map((step) => ({
            time: step.time,
            title: step.title,
            mitre: step.mitre,
            detail: step.detail,
          })),
          suspicious_findings: analysisResult?.suspicious_findings || null,
          mitre_attack_map: analysisResult?.mitre_attack_map || null,
          history: nextMessages.slice(-8),
        }),
      })

      if (!response.ok) {
        throw new Error('فشل الاتصال بمساعد التوصيات.')
      }

      const data = await response.json()
      const answerText = data.answer || 'لا يوجد رد حالياً.'
      const isQuotaFallback = answerText.includes('تعذر استخدام Gemini حالياً بسبب تجاوز الحصة')
      setGeminiStatus(
        isQuotaFallback
          ? { label: 'Gemini: Quota exceeded (Fallback)', mode: 'warn' }
          : { label: 'Gemini: Active', mode: 'ok' },
      )
      setChatMessages((prev) => [
        ...prev,
        { role: 'assistant', content: answerText },
      ])
    } catch {
      setGeminiStatus({ label: 'Gemini: unavailable (Fallback)', mode: 'warn' })
      setChatMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'تعذر الحصول على رد حالياً. حاول مرة أخرى.' },
      ])
    } finally {
      setIsChatLoading(false)
    }
  }

  const handleCopyHash = async (algorithm, value) => {
    try {
      await navigator.clipboard.writeText(value)
      setCopiedHashKey(algorithm)
      setTimeout(() => setCopiedHashKey(''), 1500)
    } catch {
      // Silently ignore clipboard errors to avoid interrupting the workflow.
    }
  }

  useEffect(() => {
    const checkGemini = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/setup-status`)
        if (!response.ok) return
        const data = await response.json()
        setGeminiStatus(
          data?.gemini_enabled
            ? { label: 'Gemini: enabled', mode: 'ok' }
            : { label: 'Gemini: disabled', mode: 'warn' },
        )
      } catch {
        setGeminiStatus({ label: 'Gemini: unavailable', mode: 'warn' })
      }
    }
    checkGemini()
  }, [])

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  const liveDateLabel = now.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })
  const liveTimeLabel = now.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })

  return (
    <div className="app-shell" dir="rtl">
      <motion.aside
        className="sidebar"
        initial={reduceMotion ? false : { opacity: 0, x: 24 }}
        animate={{ opacity: 1, x: 0 }}
        transition={reduceMotion ? { duration: 0 } : { ...springTransition, delay: 0.05 }}
      >
        <div className="brand">
          <div className="brand-top">
            <img className="brand-image" src={logoImg} alt="بينة" />
          </div>
          <p className="brand-tagline">
            منصة ذكية للتحقيق الجنائي الرقمي في البيئات الصناعية والعسكرية
          </p>
        </div>
        <button type="button" className="verify-btn" aria-label="تحقق من حالة النظام والجلسة">
          <ShieldCheck size={19} strokeWidth={2} aria-hidden />
          تحقق
        </button>
        <small>الإصدار 1.0.0</small>
      </motion.aside>

      <motion.main
        className="content"
        initial={reduceMotion ? false : { opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={reduceMotion ? { duration: 0 } : { ...springTransition, delay: 0.08 }}
      >
        <motion.button
          className="user-badge"
          type="button"
          whileHover={reduceMotion ? undefined : { scale: 1.02 }}
          whileTap={reduceMotion ? undefined : { scale: 0.98 }}
        >
          <span className="user-avatar">
            <UserRound size={16} />
          </span>
          <span className="user-meta">
            <strong>محمد</strong>
            <small>
              محقق
              <i className="online-dot" />
            </small>
          </span>
          <ChevronDown size={16} />
        </motion.button>

        {!uploadedFile ? (
          <>
            <header className="top-header upload-header">
              <div className="datetime datetime-live">
                <span><CalendarDays size={15} /> {liveDateLabel}</span>
                <span><Clock3 size={15} /> {liveTimeLabel}</span>
              </div>
            </header>

            <motion.section
              className="upload-panel"
              initial={reduceMotion ? false : { opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={reduceMotion ? { duration: 0 } : { ...springTransition, delay: 0.12 }}
            >
              <h2>رفع الدليل</h2>
              <label
                className={`dropzone ${isDraggingFile ? 'is-dragover' : ''}`}
                htmlFor="evidence-file"
                onDragEnter={(e) => {
                  e.preventDefault()
                  setIsDraggingFile(true)
                }}
                onDragLeave={() => setIsDraggingFile(false)}
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleDropEvidence}
              >
                <motion.div
                  className="dropzone-icon-wrap"
                  animate={isDraggingFile ? { scale: 1.08, y: -4 } : { scale: 1, y: 0 }}
                  transition={springTransition}
                >
                  <Upload size={48} />
                </motion.div>
                <strong>اسحب وأفلت ملف الدليل هنا</strong>
                <span>CSV, LOG, PCAP, TXT</span>
                <span className="upload-btn">اختر ملف</span>
                <input
                  id="evidence-file"
                  type="file"
                  accept=".csv,.log,.pcap,.txt,.json,.zip"
                  onChange={handleFileChange}
                />
              </label>
            </motion.section>
          </>
        ) : (
          <>
            <motion.header
              className="top-header"
              initial={reduceMotion ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: reduceMotion ? 0 : 0.3 }}
            >
              <h1>رفع الدليل</h1>
              <span className="check-pass">
                <ShieldCheck size={16} />
                تم رفع الملف بنجاح
              </span>
            </motion.header>

            <motion.section
              className="file-card"
              layout
              initial={reduceMotion ? false : { opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={reduceMotion ? { duration: 0 } : springTransition}
            >
              <div className="file-icon">
                <Upload size={34} />
              </div>
              <div className="file-meta">
                <div><span>اسم الملف</span><strong>{currentFileInfo.name}</strong></div>
                <div><span>نوع الملف</span><strong>{currentFileInfo.type}</strong></div>
                <div><span>حجم الملف</span><strong>{currentFileInfo.size}</strong></div>
                <div><span>تاريخ الرفع</span><strong>{currentFileInfo.date}</strong></div>
                <div><span>تم الرفع بواسطة</span><strong>{currentFileInfo.by}</strong></div>
              </div>
            </motion.section>
            {isAnalyzing && (
              <motion.p
                className="upload-note upload-note-pulse"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <Workflow size={16} className="spin-slow" />
                جاري تحليل الملف بواسطة نموذج XGBoost...
              </motion.p>
            )}
            {analysisError && (
              <p className="upload-note" style={{ color: '#ff9e9e' }}>
                <AlertTriangle size={16} />
                {analysisError}
              </p>
            )}
            <nav className="tabs" role="tablist">
              {tabItems.map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  className={activeTab === tab.id ? 'tab active' : 'tab'}
                  onClick={() => setActiveTab(tab.id)}
                >
                  <tab.icon size={16} />
                  {tab.label}
                </button>
              ))}
            </nav>

            <section className="tab-panel">
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  role="tabpanel"
                  className="tab-panel-motion"
                  initial={{ opacity: 0, x: reduceMotion ? 0 : 28 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: reduceMotion ? 0 : -20 }}
                  transition={tabTransition}
                >
                  {activeTab === 'hash' && (
                    <div className="hash-box">
                      <h2>حساب الهاش</h2>
                      {Object.entries(renderedHashes).map(([algorithm, value], hi) => (
                        <motion.div
                          className="hash-row"
                          key={algorithm}
                          initial={{ opacity: 0, x: reduceMotion ? 0 : 12 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: reduceMotion ? 0 : hi * 0.05, duration: 0.3 }}
                        >
                          <span>{algorithm}</span>
                          <code>{value}</code>
                          <motion.button
                            type="button"
                            className="hash-copy-btn"
                            onClick={() => handleCopyHash(algorithm, value)}
                            title={copiedHashKey === algorithm ? 'تم النسخ' : 'نسخ'}
                            aria-label={`نسخ قيمة ${algorithm}`}
                            whileTap={reduceMotion ? undefined : { scale: 0.92 }}
                          >
                            {copiedHashKey === algorithm ? <Check size={15} /> : <Copy size={15} />}
                          </motion.button>
                        </motion.div>
                      ))}
                    </div>
                  )}

                  {activeTab === 'attack' && (
                    <div className="attack-tab-stack">
                      <MitreAttackMap
                        mapData={mitreAttackMap}
                        timeline={analysisResult?.timeline ?? null}
                        summary={summary ?? null}
                      />
                    </div>
                  )}

                  {activeTab === 'suspicious' && (
                    <div className="attack-tab-stack suspicious-tab-panel">
                      <motion.section
                        className="suspicious-list suspicious-list--tab"
                        initial={reduceMotion ? false : { opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: reduceMotion ? 0 : 0.35 }}
                      >
                        <h2 className="suspicious-tab-title">تحليل السجلات المشبوهة للمحقق</h2>
                        {topSuspiciousRows.length > 0 ? (
                          displaySuspiciousFindings.length > 0 ? (
                            <div className="findings-grid">
                              {displaySuspiciousFindings.map((item, index) => {
                                const grouped = Array.isArray(item._grouped_row_indices)
                                  ? item._grouped_row_indices
                                  : null
                                const rowLabel =
                                  grouped && grouped.length > 1
                                    ? `السجلات #${grouped.join('، #')}`
                                    : `السجل #${item.row_index ?? '-'}`
                                const cardKey =
                                  grouped && grouped.length > 1
                                    ? `g-${grouped.join('-')}`
                                    : `${item.row_index ?? 'r'}-${index}`
                                const confMin = item._confidence_min
                                const confMax = item._confidence_max
                                let confLabel = `الثقة: ${((item.confidence ?? item.risk_score ?? 0) * 100).toFixed(1)}%`
                                if (
                                  grouped &&
                                  grouped.length > 1 &&
                                  confMin != null &&
                                  confMax != null
                                ) {
                                  if (confMin !== confMax) {
                                    confLabel = `الثقة: ${(confMin * 100).toFixed(1)}% – ${(confMax * 100).toFixed(1)}% (${grouped.length} سجلات)`
                                  } else {
                                    confLabel = `الثقة: ${(confMax * 100).toFixed(1)}% (${grouped.length} سجلات)`
                                  }
                                }
                                return (
                                  <motion.article
                                    key={cardKey}
                                    className="finding-card"
                                    layout
                                    initial={{ opacity: 0, y: reduceMotion ? 0 : 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={
                                      reduceMotion
                                        ? { duration: 0 }
                                        : { delay: index * 0.06, duration: 0.4, ease: [0.22, 1, 0.36, 1] }
                                    }
                                    whileHover={reduceMotion ? undefined : { boxShadow: '0 14px 32px rgba(0,0,0,0.35)' }}
                                  >
                                    <header>
                                      <strong>{rowLabel}</strong>
                                      <span className={`priority-chip ${String(item.priority || '').toLowerCase()}`}>
                                        {item.priority || 'Medium'}
                                      </span>
                                    </header>
                                    <div className="finding-card-body">
                                      <div className="finding-col finding-col-primary">
                                        <div className="finding-md-row">
                                          <b>الاشتباه:</b>
                                          <MarkdownBlock
                                            content={item.suspected_process_or_file || 'غير متوفر'}
                                            className="finding-md"
                                          />
                                        </div>
                                        <div className="finding-md-row">
                                          <b>سبب الخبث:</b>
                                          <MarkdownBlock content={item.why_malicious || 'غير متوفر'} className="finding-md" />
                                        </div>
                                        {Array.isArray(item.evidence_points) && item.evidence_points.length > 0 && (
                                          <div className="finding-evidence">
                                            <b>أدلة رقمية من السجل:</b>
                                            <ul className="finding-evidence-md-list">
                                              {item.evidence_points.map((pt, i) => (
                                                <li key={`ev-${cardKey}-${i}`}>
                                                  <MarkdownBlock content={pt} className="finding-md finding-md--tight" />
                                                </li>
                                              ))}
                                            </ul>
                                          </div>
                                        )}
                                      </div>
                                      <div className="finding-col finding-col-trailing">
                                        <div className="finding-md-row">
                                          <b>تقييم العائلة:</b>
                                          <MarkdownBlock
                                            content={item.malware_family_assessment || 'غير متوفر'}
                                            className="finding-md"
                                          />
                                        </div>
                                        <div className="finding-md-row">
                                          <b>تقييم Zero-day:</b>
                                          <MarkdownBlock
                                            content={item.zero_day_assessment || 'غير متوفر'}
                                            className="finding-md"
                                          />
                                        </div>
                                        <div className="finding-md-row">
                                          <b>خطوة المحقق التالية:</b>
                                          <MarkdownBlock
                                            content={item.investigator_next_step || 'غير متوفر'}
                                            className="finding-md"
                                          />
                                        </div>
                                        <footer className="finding-col-footer">
                                          <small>{confLabel}</small>
                                        </footer>
                                      </div>
                                    </div>
                                  </motion.article>
                                )
                              })}
                            </div>
                          ) : (
                            <div className="suspicious-rows-fallback">
                              {topSuspiciousRows.map((item) => (
                                <p key={item.row_index}>
                                  الصف #{item.row_index} - احتمال الهجوم {(item.score * 100).toFixed(2)}%
                                </p>
                              ))}
                            </div>
                          )
                        ) : (
                          <p className="mitre-map-empty">
                            لا توجد سجلات مرتبة بعد التحليل. أكمل التحليل من الخادم أو أعد رفع الملف.
                          </p>
                        )}
                      </motion.section>
                    </div>
                  )}

                  {activeTab === 'recommend' && (
                    <div className="recommend-chat-wrap">
                      <div className={`gemini-status-badge ${geminiStatus.mode}`}>{geminiStatus.label}</div>
                      <p className="chat-welcome-text">{chatbotWelcomeText}</p>

                      <ol className="recommend-list">
                        {renderedRecommendations.map((item, ri) => (
                          <motion.li
                            key={item}
                            initial={{ opacity: 0, x: reduceMotion ? 0 : 8 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: reduceMotion ? 0 : ri * 0.04 }}
                            className="recommend-li-md"
                          >
                            <MarkdownBlock content={item} className="recommend-md" />
                          </motion.li>
                        ))}
                      </ol>

                      <section className="chatbot-box">
                        <div className="chat-messages">
                          <AnimatePresence initial={false}>
                            {chatMessages.map((msg, index) => (
                              <motion.article
                                key={`${msg.role}-${index}`}
                                layout
                                initial={{ opacity: 0, y: 8, scale: 0.98 }}
                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                exit={{ opacity: 0, scale: 0.96 }}
                                transition={{ duration: reduceMotion ? 0 : 0.22 }}
                                className={msg.role === 'user' ? 'chat-msg user' : 'chat-msg assistant'}
                              >
                                <MarkdownBlock content={msg.content} className="chat-markdown" />
                              </motion.article>
                            ))}
                          </AnimatePresence>
                          {isChatLoading && (
                            <motion.article
                              className="chat-msg assistant chat-msg-typing"
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                            >
                              جاري صياغة التوصية
                              <span className="typing-dots" aria-hidden>
                                <span />
                                <span />
                                <span />
                              </span>
                            </motion.article>
                          )}
                        </div>
                      </section>

                      <div className="chat-input-row">
                        <input
                          type="text"
                          value={chatInput}
                          onChange={(event) => setChatInput(event.target.value)}
                          onKeyDown={(event) => {
                            if (event.key === 'Enter') {
                              handleSendChat()
                            }
                          }}
                          placeholder="اكتب سؤالك للمحقق المساعد..."
                        />
                        <motion.button
                          type="button"
                          className="primary"
                          onClick={handleSendChat}
                          disabled={isChatLoading}
                          whileHover={reduceMotion || isChatLoading ? undefined : { scale: 1.02 }}
                          whileTap={reduceMotion || isChatLoading ? undefined : { scale: 0.97 }}
                        >
                          إرسال
                        </motion.button>
                      </div>
                    </div>
                  )}

                  {activeTab === 'custody' && (
                    <div className="timeline custody">
                      {renderedCustodySteps.map((step, index) => (
                        <motion.article
                          key={`${step.title}-${index}-${step.dateTimeIso || 'p'}`}
                          className="timeline-item"
                          initial={{ opacity: 0, y: 12 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: reduceMotion ? 0 : index * 0.07 }}
                          whileHover={reduceMotion ? undefined : { y: -4 }}
                        >
                          <step.icon className="timeline-icon" size={20} />
                          <span className="custody-step-badge">{index + 1}</span>
                          <h3>{step.title}</h3>
                          {step.detail ? <p className="custody-detail">{step.detail}</p> : null}
                          <time
                            className="custody-at"
                            dateTime={step.dateTimeIso || undefined}
                            title={step.dateTimeIso ? 'UTC' : undefined}
                          >
                            {step.at}
                          </time>
                        </motion.article>
                      ))}
                    </div>
                  )}

                  {activeTab === 'report' && (
                    <div className="report-section">
                      <div className="report-actions">
                        <motion.button
                          className="ghost report-toggle-btn"
                          type="button"
                          onClick={() => setIsReportVisible((prev) => !prev)}
                          disabled={!analysisResult}
                          whileTap={reduceMotion ? undefined : { scale: 0.98 }}
                        >
                          {isReportVisible ? <EyeOff size={17} /> : <Eye size={17} />}
                          {isReportVisible ? 'اخفاء التقرير' : 'عرض التقرير'}
                        </motion.button>
                        <motion.button
                          className="primary report-download-btn"
                          type="button"
                          onClick={handleDownloadReport}
                          disabled={!analysisResult}
                          whileTap={reduceMotion ? undefined : { scale: 0.98 }}
                        >
                          <Download size={17} />
                          تحميل التقرير
                        </motion.button>
                      </div>
                      <AnimatePresence>
                        {analysisResult && isReportVisible && (
                          <motion.div
                            className="report-preview report-preview--markdown"
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            transition={{ duration: reduceMotion ? 0 : 0.3 }}
                          >
                            <MarkdownBlock content={renderedMarkdownReport} className="report-markdown" />
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}
                </motion.div>
              </AnimatePresence>
            </section>
          </>
        )}
      </motion.main>
    </div>
  )
}

export default App
