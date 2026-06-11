/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        sentinel: {
          50:  '#fdf2f2',
          100: '#fce4e4',
          500: '#dc2626',
          600: '#b91c1c',
          900: '#1a0a0a',
        },
      },
    },
  },
  plugins: [],
}
