/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // High-End Executive Blue & White Palette
        navy: {
          sidebar: '#FFFFFF',   // Clean White Sidebar
          deep: '#F8FAFC',      // Crisp light surface
          elevated: '#F1F5F9',  // Elevated Light Surface
          border: '#E2E8F0',    // Clean slate border
        },
        workspace: {
          DEFAULT: '#F8FAFC',   // Luminous Slate-50 Workspace
          card: '#FFFFFF',      // Pure White Card Surface
          secondary: '#F1F5F9', // Soft structured secondary surface
          header: '#FFFFFF',    // Pristine Table/Header Surface
          border: '#E2E8F0',    // Refined subtle border
        },
        brand: {
          DEFAULT: '#2563EB',   // Executive Royal Cobalt Blue
          hover: '#1D4ED8',     // Deep Vibrant Blue
          active: '#1E40AF',    // Deep Navy-Blue Active
          soft: '#EFF6FF',      // Ice Blue Soft Surface
          accent: '#3B82F6',    // Electric Sky Accent
          border: '#BFDBFE',    // Subtle Blue Border
        },
        text: {
          primary: '#0F172A',   // High-contrast slate-900
          secondary: '#475569', // Clean slate-600
          muted: '#94A3B8',     // Soft slate-400
          dark: '#0F172A',      // Slate text
        },
        severity: {
          critical: {
            DEFAULT: '#DC2626',
            soft: '#FEF2F2',
          },
          high: {
            DEFAULT: '#D97706',
            soft: '#FFFBEB',
          },
          medium: {
            DEFAULT: '#2563EB',
            soft: '#EFF6FF',
          },
          low: {
            DEFAULT: '#0284C7',
            soft: '#F0F9FF',
          },
          safe: {
            DEFAULT: '#16A34A',
            soft: '#F0FDF4',
          },
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'xs': '0 1px 2px 0 rgba(15, 23, 42, 0.04)',
        'card': '0 1px 3px 0 rgba(15, 23, 42, 0.04), 0 1px 2px -1px rgba(15, 23, 42, 0.02)',
        'card-hover': '0 12px 24px -4px rgba(37, 99, 235, 0.08), 0 4px 8px -2px rgba(37, 99, 235, 0.03)',
        'blue-glow': '0 0 20px -2px rgba(37, 99, 235, 0.25)',
      },
    },
  },
  plugins: [],
}
