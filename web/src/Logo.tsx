import { useId } from "react";

/** The Meridian mark: a globe with one bold meridian ending at an exit (same drawing as public/favicon.svg). */
export function Logo({ className }: { className?: string }) {
  const g = useId();
  return (
    <svg className={className} viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={g} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#6366f1" />
          <stop offset="1" stopColor="#3730a3" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="14" fill={`url(#${g})`} />
      <circle cx="32" cy="32" r="18" fill="none" stroke="#fff" strokeOpacity=".35" strokeWidth="3" />
      <path d="M8 32h48" stroke="#fff" strokeOpacity=".35" strokeWidth="3" strokeLinecap="round" />
      <path d="M32 14c-9 5-9 31 0 36" fill="none" stroke="#fff" strokeWidth="5" strokeLinecap="round" />
      <circle cx="32" cy="14" r="4.5" fill="#fbbf24" />
    </svg>
  );
}
