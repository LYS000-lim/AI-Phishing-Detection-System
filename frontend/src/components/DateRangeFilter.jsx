import { useEffect, useRef, useState } from 'react'

// Dates are shown/typed as DD/MM/YYYY but stored and sent to the API as
// ISO YYYY-MM-DD. Native <input type="date"> follows the browser locale
// (often MM/DD/YYYY), so a text field is used with a calendar button that
// opens the native picker.

export const todayISO = () => {
  const d = new Date()
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

export const isoToDMY = (iso) => {
  if (!iso) return ''
  const [y, m, d] = iso.split('-')
  return `${d}/${m}/${y}`
}

// Returns { iso } for a valid date, { iso: '' } for empty, or { error }.
const parseDMY = (text, allowEmpty) => {
  if (!text) return allowEmpty ? { iso: '' } : { error: 'Date is required.' }
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(text)
  if (!m) return { error: 'Use the format DD/MM/YYYY.' }
  const [, dd, mm, yyyy] = m
  const d = Number(dd), mo = Number(mm), y = Number(yyyy)
  const date = new Date(y, mo - 1, d)
  if (y < 2000 || date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d) {
    return { error: `${text} is not a valid date.` }
  }
  return { iso: `${yyyy}-${mm}-${dd}` }
}

// Auto-insert slashes while typing: "01012026" -> "01/01/2026".
const maskDMY = (raw) => {
  const digits = raw.replace(/\D/g, '').slice(0, 8)
  if (digits.length <= 2) return digits
  if (digits.length <= 4) return `${digits.slice(0, 2)}/${digits.slice(2)}`
  return `${digits.slice(0, 2)}/${digits.slice(2, 4)}/${digits.slice(4)}`
}

function DateField({ label, text, onText, iso, min, max }) {
  const pickerRef = useRef(null)
  const openPicker = () => {
    try { pickerRef.current?.showPicker() } catch { pickerRef.current?.click() }
  }
  return (
    <label className="date-filter">
      {label}
      <span className="date-input-wrap">
        <input
          type="text"
          inputMode="numeric"
          placeholder="DD/MM/YYYY"
          maxLength={10}
          value={text}
          onChange={(e) => onText(maskDMY(e.target.value))}
        />
        <button type="button" className="date-picker-btn" onClick={openPicker} aria-label={`Pick ${label} date`}>📅</button>
        <input
          ref={pickerRef}
          type="date"
          className="date-picker-hidden"
          tabIndex={-1}
          value={iso || ''}
          min={min || undefined}
          max={max || undefined}
          onChange={(e) => onText(isoToDMY(e.target.value))}
        />
      </span>
    </label>
  )
}

/**
 * From/To date range with DD/MM/YYYY entry and validation:
 * - each date must be a real calendar date in DD/MM/YYYY form
 * - dates cannot be in the future
 * - From must be on or before To
 * onChange(from, to) fires only with a valid range (ISO strings);
 * onValidityChange(bool) lets the parent disable its Apply button.
 */
export default function DateRangeFilter({ from, to, onChange, onValidityChange, allowEmpty = false }) {
  const [fromText, setFromText] = useState(isoToDMY(from))
  const [toText, setToText] = useState(isoToDMY(to))
  const [error, setError] = useState('')
  const today = todayISO()

  // Keep text in sync if the parent resets the range.
  useEffect(() => { setFromText(isoToDMY(from)) }, [from])
  useEffect(() => { setToText(isoToDMY(to)) }, [to])

  const validate = (fText, tText) => {
    const f = parseDMY(fText, allowEmpty)
    const t = parseDMY(tText, allowEmpty)
    let msg = f.error ? `From: ${f.error}` : t.error ? `To: ${t.error}` : ''
    if (!msg && f.iso && f.iso > today) msg = 'From date cannot be in the future.'
    if (!msg && t.iso && t.iso > today) msg = 'To date cannot be in the future.'
    if (!msg && f.iso && t.iso && f.iso > t.iso) msg = 'From date must be on or before the To date.'
    return { msg, f: f.iso, t: t.iso }
  }

  const update = (fText, tText) => {
    setFromText(fText)
    setToText(tText)
    // Don't nag while a date is still being typed.
    const incomplete = [fText, tText].some((x) => x && x.length < 10)
    const { msg, f, t } = validate(fText, tText)
    setError(incomplete ? '' : msg)
    onValidityChange?.(!msg)
    if (!msg && (f !== from || t !== to)) onChange(f, t)
  }

  const fromISO = parseDMY(fromText, true).iso
  const toISO = parseDMY(toText, true).iso

  return (
    <>
      <DateField label="From" text={fromText} iso={fromISO} max={toISO || today}
        onText={(v) => update(v, toText)} />
      <DateField label="To" text={toText} iso={toISO} min={fromISO} max={today}
        onText={(v) => update(fromText, v)} />
      {error && <span className="date-error">{error}</span>}
    </>
  )
}
