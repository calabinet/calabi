// Logo.tsx — the calabi brand mark. Kept in sync with the marketing site
// (web/www/src/components/Logo.tsx): a dark navy tile (sits *in* the dark
// surface rather than popping off it) holding an indigo→cyan gradient "C" with
// a glowing cyan connection node, lit by a soft cyan halo — matching the site's
// luminous tech language while keeping the contrast low. The halo is a CSS
// drop-shadow on the rendered element so it spills outside the viewBox without
// clipping.
type Props = { size?: number };

export default function Logo({ size = 28 }: Props) {
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      style={{ filter: "drop-shadow(0 0 6px rgba(34,211,238,.6))" }}
      aria-hidden
    >
      <defs>
        <linearGradient
          id="calabiLogoGrad"
          x1="0"
          y1="0"
          x2="32"
          y2="32"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#5e7fff" />
          <stop offset="100%" stopColor="#22d3ee" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="7" fill="#0e1630" stroke="rgba(255,255,255,0.12)" />
      <path
        d="M9 10c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2v3h-3v-2H12v10h8v-2h3v3c0 1.1-.9 2-2 2H11c-1.1 0-2-.9-2-2V10z"
        fill="url(#calabiLogoGrad)"
      />
      <circle cx="22" cy="16" r="4" fill="#22d3ee" opacity="0.4" />
      <circle cx="22" cy="16" r="2.1" fill="#67e8f9" />
    </svg>
  );
}
