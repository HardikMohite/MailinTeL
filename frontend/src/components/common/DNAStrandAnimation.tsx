import React from 'react';

interface DNAStrandAnimationProps {
  label?: string;
  subtext?: string;
}

export const DNAStrandAnimation: React.FC<DNAStrandAnimationProps> = ({
  label = 'Processing / In Progress',
  subtext = 'Extracting structural MIME hierarchies, header sequence hashes, and behavioral DNA patterns...',
}) => {
  const rungs = 18;

  return (
    <div className="rounded-2xl border border-blue-100 bg-white p-8 flex flex-col items-center justify-center text-center shadow-sm">
      {/* 3D Animated DNA Double Helix */}
      <div className="relative h-20 w-full max-w-sm flex items-center justify-between mb-5 select-none px-2">
        {Array.from({ length: rungs }).map((_, i) => {
          const delay = (i * 0.11).toFixed(2);
          return (
            <div
              key={i}
              className="relative flex flex-col items-center justify-center h-full w-3"
            >
              {/* Vertical connecting base-pair hydrogen bond */}
              <div
                className="absolute w-[2px] bg-gradient-to-b from-blue-500 via-cyan-300 to-indigo-500 rounded-full"
                style={{
                  animation: 'dnaRung 1.6s ease-in-out infinite',
                  animationDelay: `${delay}s`,
                }}
              />
              {/* Helical strand node A (Cyan with glowing drop-shadow) */}
              <div
                className="absolute w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.85)]"
                style={{
                  animation: 'dnaNodeA 1.6s ease-in-out infinite',
                  animationDelay: `${delay}s`,
                }}
              />
              {/* Helical strand node B (Blue with glowing drop-shadow) */}
              <div
                className="absolute w-2.5 h-2.5 rounded-full bg-blue-600 shadow-[0_0_8px_rgba(37,99,235,0.75)]"
                style={{
                  animation: 'dnaNodeB 1.6s ease-in-out infinite',
                  animationDelay: `${delay}s`,
                }}
              />
            </div>
          );
        })}
      </div>

      {/* Processing Badge */}
      <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-semibold shadow-2xs">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-600"></span>
        </span>
        <span className="tracking-wide uppercase text-[11px] font-mono">{label}</span>
      </div>

      {/* Subtext */}
      {subtext && (
        <p className="text-xs text-slate-500 mt-2.5 max-w-md leading-relaxed">
          {subtext}
        </p>
      )}
    </div>
  );
};
