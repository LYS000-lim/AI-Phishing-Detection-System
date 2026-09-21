const RULES = [
  { label: 'At least 8 characters', test: (v) => v.length >= 8 },
  { label: 'One uppercase letter', test: (v) => /[A-Z]/.test(v) },
  { label: 'One lowercase letter', test: (v) => /[a-z]/.test(v) },
  { label: 'One number', test: (v) => /\d/.test(v) },
  { label: 'One special character', test: (v) => /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(v) },
]

export const isPasswordValid = (v) => RULES.every((r) => r.test(v))

export default function PasswordRequirements({ password }) {
  return (
    <ul className="password-rules">
      {RULES.map((r) => {
        const ok = r.test(password)
        return (
          <li key={r.label} className={ok ? 'ok' : ''}>
            <span aria-hidden>{ok ? '\u2713' : '\u2717'}</span> {r.label}
          </li>
        )
      })}
    </ul>
  )
}
