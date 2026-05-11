"use client";

import React, { useMemo, useState } from "react";
import type { WebACL } from "@/lib/types";
import { scoreWebACL, type PostureReport, type FindingSeverity } from "@/engines/postureScorer";
import { ShieldCheck, ShieldAlert, AlertCircle, AlertTriangle, Info } from "lucide-react";

interface Props {
  webACL: WebACL | null | undefined;
  className?: string;
}

const VERDICT_STYLES: Record<
  PostureReport["verdict"],
  { label: string; className: string; icon: React.ReactNode }
> = {
  "No Protection": {
    label: "No Protection",
    className: "bg-red-900/40 text-red-300 border-red-800",
    icon: <ShieldAlert className="w-3.5 h-3.5" />,
  },
  Minimal: {
    label: "Minimal",
    className: "bg-orange-900/40 text-orange-300 border-orange-800",
    icon: <ShieldAlert className="w-3.5 h-3.5" />,
  },
  Basic: {
    label: "Basic",
    className: "bg-yellow-900/40 text-yellow-300 border-yellow-800",
    icon: <ShieldCheck className="w-3.5 h-3.5" />,
  },
  Solid: {
    label: "Solid",
    className: "bg-blue-900/40 text-blue-300 border-blue-800",
    icon: <ShieldCheck className="w-3.5 h-3.5" />,
  },
  Strong: {
    label: "Strong",
    className: "bg-green-900/40 text-green-300 border-green-800",
    icon: <ShieldCheck className="w-3.5 h-3.5" />,
  },
  "Defense in Depth": {
    label: "Defense in Depth",
    className: "bg-emerald-900/40 text-emerald-300 border-emerald-700",
    icon: <ShieldCheck className="w-3.5 h-3.5" />,
  },
};

const SEVERITY_ICONS: Record<FindingSeverity, React.ReactNode> = {
  error: <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />,
  warning: <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0 mt-0.5" />,
  info: <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />,
};

/**
 * A compact posture-score badge that expands into a full finding breakdown.
 * Self-contained — no store coupling, pass the WebACL in as a prop.
 */
export function PostureScoreBadge({ webACL, className = "" }: Props) {
  const [expanded, setExpanded] = useState(false);
  const report: PostureReport | null = useMemo(() => {
    if (!webACL) return null;
    try {
      return scoreWebACL(webACL);
    } catch {
      return null;
    }
  }, [webACL]);

  if (!webACL || !report) {
    return null;
  }

  const verdictStyle = VERDICT_STYLES[report.verdict];
  const topFindings = report.findings.slice(0, 5);

  return (
    <div className={`rounded-md border ${verdictStyle.className} ${className}`}>
      <button
        type="button"
        onClick={() => setExpanded((x) => !x)}
        className="w-full flex items-center gap-2 px-2.5 py-1.5 text-xs font-medium text-left"
        aria-expanded={expanded}
        aria-label="Toggle WebACL posture score details"
      >
        {verdictStyle.icon}
        <span className="truncate">{verdictStyle.label}</span>
        <span className="ml-auto tabular-nums font-semibold">
          {report.totalScore}/{report.maxScore}
        </span>
      </button>

      {expanded && (
        <div className="px-2.5 pb-2 space-y-2 text-[11px] text-gray-300">
          <div className="grid grid-cols-5 gap-1 border-t border-white/10 pt-2">
            {report.categories.map((c) => (
              <div key={c.category} className="text-center" title={`${c.category}: ${c.score}/${c.max}`}>
                <div className="font-mono tabular-nums">
                  {c.score}/{c.max}
                </div>
                <div className="text-[10px] text-gray-400 truncate">{c.category}</div>
              </div>
            ))}
          </div>

          {topFindings.length > 0 && (
            <ul className="space-y-1 border-t border-white/10 pt-2">
              {topFindings.map((f, idx) => (
                <li key={`${f.category}-${idx}`} className="flex gap-1.5">
                  {SEVERITY_ICONS[f.severity]}
                  <span className="flex-1">
                    <span className="font-medium text-gray-200">{f.title}</span>
                    {f.recommendation && (
                      <span className="block text-gray-400 mt-0.5">{f.recommendation}</span>
                    )}
                  </span>
                </li>
              ))}
              {report.findings.length > topFindings.length && (
                <li className="text-gray-500 italic pl-5">
                  +{report.findings.length - topFindings.length} more finding(s)…
                </li>
              )}
            </ul>
          )}

          <div className="border-t border-white/10 pt-1.5 text-gray-400 text-[10px]">
            {report.summary}
          </div>
        </div>
      )}
    </div>
  );
}
