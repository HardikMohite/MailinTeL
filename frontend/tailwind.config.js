/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Single Unified Theme Palette from Design.md
        navy: {
          sidebar: '#101C33',   // Primary Navigation Navy
          deep: '#172641',      // Deep Intelligence Navy
          elevated: '#20314D',  // Elevated Dark Surface
          border: '#2A3C5C',    // Dark surface border
        },
        workspace: {
          DEFAULT: '#F5F7FB',   // Soft Light Main Workspace
          card: '#FFFFFF',      // Primary Card Surface
          secondary: '#EEF2F7', // Secondary Information Surface
          header: '#F8FAFC',    // Quiet Header/Table Surface
          border: '#E2E8F0',    // Light surface border
        },
        brand: {
          DEFAULT: '#2563B8',   // Intelligence Blue
          hover: '#1D4E9E',     // Hover / Active Blue
          soft: '#EAF2FF',      // Soft Blue Surface
        },
        text: {
          primary: '#1C2B40',   // Primary text on light
          secondary: '#627086', // Secondary text
          muted: '#8793A5',     // Muted text
          dark: '#EAF0F8',      // Text on dark navy
        },
        severity: {
          critical: {
            DEFAULT: '#C73A32',
            soft: '#FDECEA',
          },
          high: {
            DEFAULT: '#D88916',
            soft: '#FFF4DD',
          },
          medium: {
            DEFAULT: '#7C62C8',
            soft: '#F0ECFB',
          },
          low: {
            DEFAULT: '#3478C7',
            soft: '#EAF3FD',
          },
          safe: {
            DEFAULT: '#2D8B68',
            soft: '#E8F6EF',
          },
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
    },
  },
  plugins: [],
}
