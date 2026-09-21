export default function PasswordMatch({ password, confirm }) {
  if (!confirm) return null
  const match = password === confirm
  return (
    <p className={`password-match ${match ? 'ok' : 'bad'}`}>
      {match ? '✓ Passwords match' : '✗ Passwords do not match'}
    </p>
  )
}
