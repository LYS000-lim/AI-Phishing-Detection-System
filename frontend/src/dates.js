// The backend stores timestamps as naive UTC ("2026-09-23T02:55:25", no
// "Z"), which the browser would otherwise read as LOCAL time - showing
// every time 8 hours early in Malaysia. Mark such strings as UTC first.
export const utcDate = (value) => {
  if (!value) return new Date(NaN)
  const s = String(value)
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`)
}
