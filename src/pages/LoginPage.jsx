import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Fingerprint, Loader2, Lock, LogIn, UserRound } from 'lucide-react'
import logoImg from '../../lastloggoooo.jpg'
import { useAuth } from '../auth/AuthContext'

const springTransition = { type: 'spring', stiffness: 380, damping: 28 }

export function LoginPage() {
  const reduceMotion = useReducedMotion()
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [nafathHint, setNafathHint] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')
    setNafathHint('')
    setIsSubmitting(true)
    try {
      await login(username, password)
    } catch (e) {
      setError(e?.message || 'تعذر تسجيل الدخول.')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleNafathPlaceholder = () => {
    setNafathHint('سيتم دعم تسجيل الدخول عبر نفاذ في إصدار لاحق — هذه الواجهة للعرض فقط.')
    setError('')
  }

  return (
    <div className="login-shell" dir="rtl">
      <motion.div
        className="login-backdrop"
        initial={reduceMotion ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: reduceMotion ? 0 : 0.35 }}
      />
      <motion.section
        className="login-card"
        initial={reduceMotion ? false : { opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={reduceMotion ? { duration: 0 } : { ...springTransition, delay: 0.06 }}
      >
        <div className="login-brand">
          <img className="login-logo" src={logoImg} alt="بينة" />
          <h1 className="login-title">تسجيل الدخول</h1>
          <p className="login-subtitle">منصة بَيْنة — التحقيق الجنائي الرقمي</p>
        </div>

        <form className="login-form" onSubmit={handleSubmit} noValidate>
          <label className="login-label" htmlFor="login-username">
            اسم المستخدم
          </label>
          <div className="login-input-wrap">
            <UserRound className="login-input-icon" size={18} aria-hidden />
            <input
              id="login-username"
              name="username"
              type="text"
              autoComplete="username"
              inputMode="text"
              className="login-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="أدخل اسم المستخدم"
              disabled={isSubmitting}
            />
          </div>

          <label className="login-label" htmlFor="login-password">
            كلمة المرور
          </label>
          <div className="login-input-wrap">
            <Lock className="login-input-icon" size={18} aria-hidden />
            <input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              className="login-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="أدخل كلمة المرور"
              spellCheck={false}
              disabled={isSubmitting}
            />
          </div>

          {error ? (
            <motion.p
              className="login-error"
              role="alert"
              initial={reduceMotion ? false : { opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {error}
            </motion.p>
          ) : null}

          {nafathHint ? (
            <motion.p
              className="login-info"
              initial={reduceMotion ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              {nafathHint}
            </motion.p>
          ) : null}

          <motion.button
            type="submit"
            className="primary login-submit"
            disabled={isSubmitting}
            whileHover={reduceMotion || isSubmitting ? undefined : { scale: 1.01 }}
            whileTap={reduceMotion || isSubmitting ? undefined : { scale: 0.98 }}
          >
            {isSubmitting ? (
              <>
                <Loader2 className="login-spin" size={20} aria-hidden />
                جاري التحقق…
              </>
            ) : (
              <>
                <LogIn size={20} aria-hidden />
                تسجيل الدخول
              </>
            )}
          </motion.button>
        </form>

        <div className="login-divider">
          <span>أو</span>
        </div>

        <motion.button
          type="button"
          className="login-nafath-btn"
          onClick={handleNafathPlaceholder}
          disabled={isSubmitting}
          whileHover={reduceMotion || isSubmitting ? undefined : { scale: 1.01 }}
          whileTap={reduceMotion || isSubmitting ? undefined : { scale: 0.98 }}
        >
          <Fingerprint size={20} aria-hidden />
          تسجيل الدخول عبر نفاذ
        </motion.button>
      </motion.section>
    </div>
  )
}
