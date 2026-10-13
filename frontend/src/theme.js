// Day/night theme for the web portal. The choice is kept in localStorage
// and applied as <html data-theme="light|dark">; index.css swaps the colour
// variables for the light theme.
import { useEffect, useState } from 'react'

const KEY = 'pg_theme'
const EVENT = 'pg-theme-change'

export const getTheme = () => {
  try {
    return localStorage.getItem(KEY) === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

export const applyTheme = (theme = getTheme()) => {
  document.documentElement.dataset.theme = theme
}

export const setTheme = (theme) => {
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    // Private mode: the theme still applies for this visit.
  }
  applyTheme(theme)
  window.dispatchEvent(new Event(EVENT))
}

// Chart.js draws on a canvas and cannot read CSS variables, so charts read
// the resolved colours here and redraw when the theme changes.
export const themeColors = () => {
  const css = getComputedStyle(document.documentElement)
  const v = (name) => css.getPropertyValue(name).trim()
  return {
    bg: v('--bg'),
    panel: v('--panel'),
    panel2: v('--panel-2'),
    text: v('--text'),
    muted: v('--muted'),
    grid: v('--border-strong'),
    accent: v('--accent'),
    accent2: v('--accent-2'),
    good: v('--good'),
    bad: v('--bad'),
    warn: v('--warn'),
  }
}

export function useThemeColors() {
  const [colors, setColors] = useState(themeColors)
  useEffect(() => {
    const update = () => setColors(themeColors())
    window.addEventListener(EVENT, update)
    return () => window.removeEventListener(EVENT, update)
  }, [])
  return colors
}

export function useTheme() {
  const [theme, setThemeState] = useState(getTheme)
  useEffect(() => {
    const update = () => setThemeState(getTheme())
    window.addEventListener(EVENT, update)
    return () => window.removeEventListener(EVENT, update)
  }, [])
  return [theme, setTheme]
}
