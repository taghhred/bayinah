import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { ExternalLink, Route } from 'lucide-react'
import { MarkdownBlock } from './MarkdownBlock'

/** Official MITRE ATT&CK technique page (incl. sub-techniques Txxxx.yyy). */
function mitreTechniqueUrl(techniqueId) {
  if (!techniqueId || techniqueId === '—' || techniqueId === 'TBD') {
    return null
  }
  const raw = String(techniqueId).trim().toUpperCase()
  const sub = raw.match(/^(T\d{4})\.(\d{1,3})$/i)
  if (sub) {
    const subNum = sub[2].padStart(3, '0')
    return `https://attack.mitre.org/techniques/${sub[1]}/${subNum}/`
  }
  const base = raw.match(/^T\d{4}/i)
  return base ? `https://attack.mitre.org/techniques/${base[0]}/` : null
}

const TID_RE = /T\d{4}(?:\.\d{3})?/gi

/** Mirrors backend _TECHNIQUE_TO_ICS_TA / _ICS_TA_AR for client fallback & labels. */
const TID_TO_ICS_TA = {
  T1200: 'TA0108', T1091: 'TA0109', T1189: 'TA0108', T1190: 'TA0108', T1133: 'TA0108',
  T1566: 'TA0108', T0817: 'TA0108', T0822: 'TA0108', T0847: 'TA0108', T0886: 'TA0108',
  T1059: 'TA0104', T1203: 'TA0104', T1204: 'TA0104', T1106: 'TA0104', T0858: 'TA0104',
  T0807: 'TA0104', T0871: 'TA0104', T0853: 'TA0110', T1543: 'TA0110', T1547: 'TA0110',
  T1078: 'TA0111', T0868: 'TA0111', T0874: 'TA0103', T0856: 'TA0103', T1046: 'TA0102',
  T1040: 'TA0102', T1049: 'TA0102', T1018: 'TA0102', T1087: 'TA0102', T0866: 'TA0102',
  T0867: 'TA0102', T0888: 'TA0102', T0846: 'TA0102', T0882: 'TA0102', T1021: 'TA0109',
  T1028: 'TA0109', T1550: 'TA0109', T1072: 'TA0109', T1105: 'TA0109', T1048: 'TA0100',
  T1020: 'TA0100', T1537: 'TA0100', T1005: 'TA0100', T1041: 'TA0100', T1071: 'TA0101',
  T1092: 'TA0101', T1573: 'TA0101', T0869: 'TA0101', T0884: 'TA0101', T0852: 'TA0101',
  T0809: 'TA0107', T0813: 'TA0107', T0815: 'TA0107', T0829: 'TA0107', T0837: 'TA0107',
  T0800: 'TA0106', T0806: 'TA0106', T0814: 'TA0106', T0827: 'TA0106', T0830: 'TA0106',
  T0831: 'TA0106', T0832: 'TA0106', T0855: 'TA0106', T0843: 'TA0106', T0845: 'TA0106',
  T0851: 'TA0106', T1498: 'TA0105', T1499: 'TA0105', T1496: 'TA0105',
}

const ICS_TACTIC_AR = {
  TA0108: 'الوصول الأولي (ICS)',
  TA0104: 'التنفيذ (ICS)',
  TA0110: 'الإصرار / الاستمرارية (ICS)',
  TA0111: 'تصعيد الصلاحيات (ICS)',
  TA0103: 'التهرب (ICS)',
  TA0102: 'الاستطلاع والاكتشاف (ICS)',
  TA0109: 'الحركة الجانبية (ICS)',
  TA0100: 'الجمع (ICS)',
  TA0101: 'القيادة والتحكم (ICS)',
  TA0107: 'إعاقة وظيفة الاستجابة (ICS)',
  TA0106: 'إعاقة التحكم بالعملية (ICS)',
  TA0105: 'التأثير (ICS)',
}

/** English labels aligned with MITRE ATT&CK for ICS matrix (for cross-reference). */
const ICS_TACTIC_EN = {
  TA0108: 'Initial Access',
  TA0104: 'Execution',
  TA0110: 'Persistence',
  TA0111: 'Privilege Escalation',
  TA0103: 'Stealth',
  TA0102: 'Discovery',
  TA0109: 'Lateral Movement',
  TA0100: 'Collection',
  TA0101: 'Command and Control',
  TA0107: 'Defense Impairment',
  TA0106: 'Impair Process Control',
  TA0105: 'Impact',
}

function icsTacticIdFromTechnique(techniqueId) {
  const raw = String(techniqueId || '').toUpperCase()
  const m = raw.match(/^T\d{4}/)
  const tid = m ? m[0] : ''
  if (tid && TID_TO_ICS_TA[tid]) {
    return TID_TO_ICS_TA[tid]
  }
  if (tid.startsWith('T08')) {
    return 'TA0106'
  }
  return 'TA0102'
}

function tacticLabelsForTechnique(techniqueId) {
  const ta = icsTacticIdFromTechnique(techniqueId)
  return {
    tacticId: ta,
    tacticAr: ICS_TACTIC_AR[ta] || 'تكتيك ICS',
    tacticEn: ICS_TACTIC_EN[ta] || '',
  }
}

function stripTrailingPhaseFromTitle(title, phaseEn) {
  const src = String(title || '').trim()
  if (!src) return src
  const phase = String(phaseEn || '').trim()
  const known = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Stealth',
    'Defense Impairment',
    'Discovery',
    'Lateral Movement',
    'Command and Control',
    'Exfiltration',
    'Impact',
  ]
  const phases = phase ? [phase, ...known] : known
  let out = src
  for (const p of phases) {
    const esc = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    out = out
      .replace(new RegExp(`\\s*\\(\\s*${esc}\\s*\\)\\s*$`, 'i'), '')
      .replace(new RegExp(`\\s*[\\-–—]\\s*${esc}\\s*$`, 'i'), '')
      .trim()
  }
  return out || src
}

function dedupeMitreFlowSteps(steps) {
  if (!Array.isArray(steps) || steps.length === 0) {
    return steps
  }
  const out = []
  const seenExact = new Set()
  const seenTacticTechnique = new Set()
  const seenPhase = new Set()
  for (const s of steps) {
    const keyExact = [
      s.technique_id,
      s.time,
      (s.name_ar || '').replace(/\s+/g, ' ').trim().slice(0, 140),
    ].join('|')
    const keyTT = [s.tacticId || '', s.technique_id || ''].join('|')
    if (seenExact.has(keyExact)) {
      continue
    }
    // Keep only first occurrence of each phase in the flow rail.
    if ((s.tacticId || '') && seenPhase.has(s.tacticId)) {
      continue
    }
    // Keep one card for same tactic+technique to avoid visual duplicates.
    if ((s.tacticId || '') && (s.technique_id || '') && seenTacticTechnique.has(keyTT)) {
      continue
    }
    seenExact.add(keyExact)
    if (s.tacticId || '') {
      seenPhase.add(s.tacticId)
    }
    if ((s.tacticId || '') && (s.technique_id || '')) {
      seenTacticTechnique.add(keyTT)
    }
    out.push(s)
  }
  return out
}

function coerceTechniqueId(node) {
  const raw = node?.technique_id ?? node?.techniqueId ?? node?.id ?? node?.mitre_id ?? ''
  let tid = String(raw).trim().toUpperCase()
  if (!tid.startsWith('T')) {
    const m = tid.match(/T\d{4}(?:\.\d{3})?/i)
    tid = m ? m[0].toUpperCase() : ''
  }
  return tid || 'T1071'
}

/**
 * Linear attack-flow steps derived from server map (Gemini + normalizer).
 * Each node is one step; tactic context is duplicated per node for clarity.
 */
function flattenStagesToSteps(stages) {
  const steps = []
  if (!Array.isArray(stages)) {
    return steps
  }
  stages.forEach((stage) => {
    if (!stage || typeof stage !== 'object') {
      return
    }
    let nodes = stage.nodes ?? stage.Nodes
    if (nodes && typeof nodes === 'object' && !Array.isArray(nodes)) {
      nodes = [nodes]
    }
    if (!Array.isArray(nodes)) {
      nodes = []
    }
    const tacticId = String(stage.tactic_id ?? stage.tacticId ?? '')
    const tacticAr = String(stage.tactic_ar ?? stage.tacticAr ?? '')
    nodes.forEach((node) => {
      if (!node || typeof node !== 'object') {
        return
      }
      const tid = coerceTechniqueId(node)
      const derived = tacticLabelsForTechnique(tid)
      const tacticIdResolved = tacticId || derived.tacticId
      const tacticArResolved = tacticAr || derived.tacticAr
      const stageEn = String(stage.tactic_en ?? stage.tacticEn ?? '').trim()
      const tacticEnResolved =
        stageEn || ICS_TACTIC_EN[tacticIdResolved] || derived.tacticEn
      const rawTitle = String(node.name_ar ?? node.nameAr ?? node.label_ar ?? 'تقنية')
      const cleanTitle = stripTrailingPhaseFromTitle(rawTitle, tacticEnResolved)
      steps.push({
        tacticId: tacticIdResolved,
        tacticAr: tacticArResolved,
        tacticEn: tacticEnResolved,
        stageOrder: stage.order,
        technique_id: tid,
        name_ar: cleanTitle,
        name_en: String(node.name_en ?? node.nameEn ?? ''),
        evidence_ar: String(node.evidence_ar ?? node.evidenceAr ?? node.detail_ar ?? ''),
        time: String(node.time ?? ''),
      })
    })
  })
  return steps
}

/** Client fallback when server map is missing or empty (matches backend _fallback_mitre_attack_map). */
function buildMapFromTimeline(timeline, summary) {
  const tl = Array.isArray(timeline) ? timeline : []
  if (!tl.length) {
    if (!summary || typeof summary !== 'object') {
      return null
    }
    const rate = typeof summary.malicious_rate === 'number' ? summary.malicious_rate * 100 : 0
    return {
      narrative_ar:
        'لم يُستخرج تسلسل زمني من الاستجابة؛ يُعرض مسار افتراضي بناءً على ملخص التحليل. أعد تشغيل الخادم أو أعد رفع الملف.',
      stages: [
        {
          order: 1,
          tactic_id: 'TA0102',
          tactic_ar: ICS_TACTIC_AR.TA0102,
          tactic_en: ICS_TACTIC_EN.TA0102,
          nodes: [
            {
              technique_id: 'T1046',
              name_ar: 'مراجعة السجلات والملخص الإحصائي بعد التحليل.',
              name_en: '',
              evidence_ar: `نسبة سلوك ضار تقريبية ${rate.toFixed(1)}% من النموذج.`,
              time: '',
            },
          ],
        },
      ],
    }
  }

  const stages = tl.slice(0, 12).map((step, i) => {
    const mitreRaw = String(step?.mitre ?? '')
    const tids = [...mitreRaw.matchAll(TID_RE)].map((m) => m[0].toUpperCase())
    const uniq = [...new Set(tids)]
    const primary = uniq.length ? uniq[0] : 'T1071'
    const extra = uniq.slice(1, 3)
    const labels = tacticLabelsForTechnique(primary)
    const detail = String(step?.detail ?? '')
    const evidence =
      extra.length > 0
        ? (detail ? `${detail} — ` : '') + `تقنيات مرتبطة: ${extra.join('، ')}`
        : detail
    return {
      order: i + 1,
      tactic_id: labels.tacticId,
      tactic_ar: labels.tacticAr,
      tactic_en: labels.tacticEn,
      nodes: [
        {
          technique_id: primary,
          name_ar: String(step?.title ?? 'حدث مشبوه'),
          name_en: '',
          evidence_ar: evidence,
          time: String(step?.time ?? ''),
        },
      ],
    }
  })

  const rate =
    typeof summary?.malicious_rate === 'number' ? summary.malicious_rate * 100 : null
  const narrative_ar =
    rate != null
      ? `مسار مُستخلص من التسلسل الزمني (نسبة خبث إجمالية تقريبية ${rate.toFixed(1)}%).`
      : 'مسار مُستخلص من التسلسل الزمني للتحليل.'

  return { narrative_ar, stages }
}

export function MitreAttackMap({ mapData, timeline, summary }) {
  const effectiveMap = useMemo(() => {
    const fromServer = mapData && typeof mapData === 'object' ? mapData : null
    const serverSteps = flattenStagesToSteps(fromServer?.stages)
    if (serverSteps.length > 0) {
      return fromServer
    }
    return buildMapFromTimeline(timeline, summary)
  }, [mapData, timeline, summary])

  const stages = effectiveMap?.stages
  const narrative = effectiveMap?.narrative_ar ?? mapData?.narrative_ar
  const mapMeta =
    effectiveMap && typeof effectiveMap === 'object' ? effectiveMap._meta : null

  const steps = useMemo(() => dedupeMitreFlowSteps(flattenStagesToSteps(stages)), [stages])

  const [activeIndex, setActiveIndex] = useState(0)
  const [expandedIndex, setExpandedIndex] = useState(null)
  const pauseRef = useRef(false)
  const nodeRefs = useRef([])

  useEffect(() => {
    if (steps.length === 0) {
      return
    }
    setActiveIndex(0)
    setExpandedIndex(null)
  }, [steps])

  useEffect(() => {
    if (steps.length <= 1) {
      return undefined
    }
    const id = setInterval(() => {
      if (pauseRef.current) {
        return
      }
      setActiveIndex((i) => (i + 1) % steps.length)
    }, 3200)
    return () => clearInterval(id)
  }, [steps.length])

  const scrollStepIntoView = useCallback((index) => {
    const el = nodeRefs.current[index]
    if (el && typeof el.scrollIntoView === 'function') {
      el.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' })
    }
  }, [])

  useEffect(() => {
    scrollStepIntoView(activeIndex)
  }, [activeIndex, scrollStepIntoView])

  const handleStepClick = (index) => {
    setActiveIndex(index)
    setExpandedIndex((prev) => (prev === index ? null : index))
    scrollStepIntoView(index)
  }

  if (!Array.isArray(stages) || stages.length === 0 || steps.length === 0) {
    return (
      <p className="mitre-map-empty">
        خريطة تسلسل الهجوم تظهر هنا بعد اكتمال التحليل من الخادم. إن استمرت فارغة، أعد رفع الملف
        وتأكد أن واجهة FastAPI محدّثة وتعمل.
      </p>
    )
  }

  return (
    <div className="mitre-map-panel mitre-map-panel--interactive">
      <div className="mitre-map-header">
        <Route className="mitre-map-header-icon" size={22} strokeWidth={1.75} />
        <div>
          <h3>تسلسل الهجوم (MITRE ATT&amp;CK)</h3>
          {narrative ? (
            <div className="mitre-map-narrative">
              <MarkdownBlock content={narrative} className="mitre-narrative-md" />
            </div>
          ) : null}
          {mapMeta && typeof mapMeta === 'object' ? (
            <p className="mitre-map-meta" lang="ar">
              <span className="mitre-map-meta-label">مصدر المسار:</span>{' '}
              {mapMeta.enrichment_source === 'gemini'
                ? 'Gemini ثم ضبط الخادم (MITRE ICS)'
                : 'قواعد الخادم والأدلة المقاسة (بدون خريطة كاملة من Gemini)'}
              {typeof mapMeta.distinct_tactic_stages === 'number'
                ? ` · تكتيكات مميّزة في العرض: ${mapMeta.distinct_tactic_stages}`
                : ''}
              {mapMeta.analysis_fingerprint
                ? ` · معرّف الجلسة: ${mapMeta.analysis_fingerprint}`
                : ''}
            </p>
          ) : null}
        </div>
      </div>

      <div
        className="mitre-flow-scroll"
        dir="rtl"
        onMouseEnter={() => {
          pauseRef.current = true
        }}
        onMouseLeave={() => {
          pauseRef.current = false
        }}
      >
        <div className="mitre-flow-rail" role="list" aria-label="خطوات تسلسل الهجوم">
          {steps.map((step, index) => {
            const url = mitreTechniqueUrl(step.technique_id)
            const isActive = index === activeIndex
            const isExpanded = expandedIndex === index

            return (
              <div className="mitre-flow-segment" key={`${step.technique_id}-${index}`} role="listitem">
                {index > 0 ? (
                  <div className="mitre-flow-arrow-wrap" aria-hidden="true">
                    <motion.div
                      className="mitre-flow-arrow"
                      initial={{ opacity: 0.35, scaleX: 0.6 }}
                      animate={{
                        opacity: index <= activeIndex ? 1 : 0.4,
                        scaleX: 1,
                      }}
                      transition={{ duration: 0.35 }}
                    >
                      <span className="mitre-flow-arrow-line" />
                      <span className="mitre-flow-arrow-head">◀</span>
                    </motion.div>
                  </div>
                ) : null}

                <motion.button
                  type="button"
                  ref={(el) => {
                    nodeRefs.current[index] = el
                  }}
                  className={`mitre-flow-node ${isActive ? 'is-active' : ''} ${isExpanded ? 'is-expanded' : ''}`}
                  onClick={() => handleStepClick(index)}
                  layout
                  initial={{ opacity: 0, y: 16 }}
                  animate={{
                    opacity: 1,
                    y: 0,
                    scale: isActive ? 1.02 : 1,
                  }}
                  transition={{ delay: index * 0.05, type: 'spring', stiffness: 420, damping: 28 }}
                  whileHover={{ scale: isActive ? 1.04 : 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <span className="mitre-flow-step-num">{index + 1}</span>
                  <span className="mitre-flow-tactic-pill" lang={step.tacticEn ? 'en' : 'ar'}>
                    {step.tacticEn || step.tacticAr}
                  </span>
                  <span className="mitre-tid mitre-tid--lg">{step.technique_id}</span>
                  <strong className="mitre-flow-title">{step.name_ar}</strong>
                  {step.time ? <time className="mitre-flow-time">{step.time}</time> : null}

                  <AnimatePresence>
                    {isExpanded && step.evidence_ar ? (
                      <motion.div
                        className="mitre-flow-evidence"
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.25 }}
                      >
                        <span className="mitre-flow-evidence-label">أدلة مرتبطة بالتحليل</span>
                        <MarkdownBlock content={step.evidence_ar} className="mitre-evidence-md" />
                      </motion.div>
                    ) : null}
                  </AnimatePresence>

                  {url ? (
                    <a
                      className="mitre-attack-link"
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <ExternalLink size={14} strokeWidth={2} />
                      صفحة MITRE الرسمية
                    </a>
                  ) : null}
                </motion.button>
              </div>
            )
          })}
        </div>
      </div>

      <div className="mitre-flow-progress" aria-hidden="true">
        <div className="mitre-flow-progress-track">
          <motion.div
            className="mitre-flow-progress-fill"
            initial={false}
            animate={{
              width: `${((activeIndex + 1) / steps.length) * 100}%`,
            }}
            transition={{ type: 'spring', stiffness: 200, damping: 24 }}
          />
        </div>
        <span className="mitre-flow-progress-label">
          الخطوة {activeIndex + 1} من {steps.length}
        </span>
      </div>
    </div>
  )
}
