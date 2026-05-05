"use client";

import React from "react";
import type { FloodSimulationResult } from "@/lib/types";
import { AlertTriangle, CheckCircle2, ShieldAlert, TrendingUp } from "lucide-react";

interface Props {
  result: FloodSimulationResult | null;
  className?: string;
}

/**
 * Compact flood-simulation timeline.
 * Shows: request count over time, when the rate-based rule tripped, and a
 * color-coded timeline of allowed vs blocked requests.
 * Inspired by ns-x's event-queue model — each request is an event ordered
 * by elapsed time.
 */
export function FloodTimelineChart({ result, className = "" }: Props) {
  if (!result || result.timeline.length === 0) {
    return null;
  }

  const totalDurationSec = Math.max(
    1,
    ...result.timeline.map((t) => t.elapsedSeconds)
  );

  // Downsample timeline to <= 120 bars for rendering sanity
  const maxBars = 120;
  const step = Math.max(1, Math.ceil(result.timeline.length / maxBars));
  const bars = [];
  for (let i = 0; i < result.timeline.length; i += step) {
    const slice = result.timeline.slice(i, i + step);
    const blocked = slice.filter((t) => t.action === "BLOCK").length;
    const allowed = slice.length - blocked;
    const elapsed = slice[slice.length - 1].elapsedSeconds;
    bars.push({
      allowed,
      blocked,
      total: slice.length,
      elapsed,
      // currentRate is smoothed over the window inside rateEngine
      currentRate: slice[slice.length - 1].currentRate,
    });
  }

  const maxTotal = Math.max(...bars.map((b) => b.total), 1);
  const maxRate = Math.max(...bars.map((b) => b.currentRate), 1);

  const triggered = result.triggersAtSeconds !== null;
  const blockedPct = ((result.blockedRequests / result.totalRequests) * 100).toFixed(1);

  return (
    <div className={`rounded-md border border-gray-700 bg-gray-900 text-gray-200 ${className}`}>
      <div className="flex items-center gap-3 px-3 py-2 border-b border-gray-800 text-xs">
        <TrendingUp className="w-3.5 h-3.5 text-blue-400" />
        <span className="font-semibold">Flood simulation</span>
        <span className="text-gray-500">·</span>
        <span className="text-gray-400">
          {result.totalRequests.toLocaleString()} requests over{" "}
          {totalDurationSec.toFixed(1)}s
        </span>
        <div className="ml-auto flex items-center gap-3">
          {triggered ? (
            <span className="inline-flex items-center gap-1 text-red-300">
              <ShieldAlert className="w-3.5 h-3.5" />
              Rate limit tripped at {result.triggersAtSeconds!.toFixed(1)}s ({result.triggerRequestCount} req)
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-yellow-300">
              <AlertTriangle className="w-3.5 h-3.5" />
              Rate threshold not hit — increase rate or add a rate-based rule
            </span>
          )}
        </div>
      </div>

      <div className="px-3 py-3">
        {/* Stacked bar chart: allowed (green) + blocked (red) per bucket */}
        <div className="flex items-end gap-[1px] h-16 mb-2">
          {bars.map((b, i) => {
            const height = (b.total / maxTotal) * 100;
            const blockedHeight = b.total === 0 ? 0 : (b.blocked / b.total) * height;
            const allowedHeight = height - blockedHeight;
            return (
              <div
                key={i}
                className="flex-1 flex flex-col justify-end min-w-[2px]"
                title={`t=${b.elapsed.toFixed(1)}s · ${b.allowed} allowed · ${b.blocked} blocked · rate ${b.currentRate.toFixed(0)}/min`}
              >
                {blockedHeight > 0 && (
                  <div
                    className="bg-red-500"
                    style={{ height: `${blockedHeight}%` }}
                  />
                )}
                {allowedHeight > 0 && (
                  <div
                    className="bg-emerald-500/70"
                    style={{ height: `${allowedHeight}%` }}
                  />
                )}
              </div>
            );
          })}
        </div>

        {/* Rate curve overlay as a separate line chart */}
        <div className="relative h-10 mb-2">
          <svg
            width="100%"
            height="100%"
            viewBox={`0 0 ${bars.length} 100`}
            preserveAspectRatio="none"
            className="absolute inset-0"
          >
            <polyline
              fill="none"
              stroke="rgb(96 165 250)"
              strokeWidth="1.5"
              vectorEffect="non-scaling-stroke"
              points={bars
                .map((b, i) => `${i},${100 - (b.currentRate / maxRate) * 90}`)
                .join(" ")}
            />
          </svg>
          <div className="absolute bottom-0 left-0 text-[10px] text-gray-500">
            0 req/min
          </div>
          <div className="absolute top-0 right-0 text-[10px] text-gray-500">
            peak {maxRate.toFixed(0)}/min
          </div>
        </div>

        {/* Footer stats */}
        <div className="grid grid-cols-4 gap-2 text-[11px] pt-2 border-t border-gray-800">
          <div>
            <div className="text-gray-500">Total</div>
            <div className="font-mono tabular-nums">
              {result.totalRequests.toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-gray-500 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" /> Allowed
            </div>
            <div className="font-mono tabular-nums text-emerald-300">
              {result.allowedRequests.toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-gray-500 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-red-400" /> Blocked
            </div>
            <div className="font-mono tabular-nums text-red-300">
              {result.blockedRequests.toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-gray-500">Block rate</div>
            <div className="font-mono tabular-nums">{blockedPct}%</div>
          </div>
        </div>
      </div>
    </div>
  );
}
