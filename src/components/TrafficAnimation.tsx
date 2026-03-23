"use client";

import React, { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { TrafficDot, EvaluationResult } from "@/lib/types";
import { Shield, X, Check, AlertTriangle } from "lucide-react";

interface TrafficAnimationProps {
  dots: TrafficDot[];
  onDotComplete?: (dotId: string) => void;
  edgePath?: string; // SVG path for the edge
}

export const TrafficAnimation: React.FC<TrafficAnimationProps> = ({
  dots,
  onDotComplete,
  edgePath = "M0,100 L300,100",
}) => {
  const [animatingDots, setAnimatingDots] = useState<Map<string, number>>(new Map());

  useEffect(() => {
    // Start animation for new dots
    dots.forEach((dot) => {
      if (!animatingDots.has(dot.id) && dot.status === "traveling") {
        setAnimatingDots((prev) => {
          const next = new Map(prev);
          next.set(dot.id, 0);
          return next;
        });
      }
    });
  }, [dots]);

  const getDotColor = (status: TrafficDot["status"]) => {
    switch (status) {
      case "blocked":
        return "#ef4444"; // red
      case "allowed":
        return "#22c55e"; // green
      case "counted":
        return "#eab308"; // yellow
      case "evaluating":
        return "#f97316"; // orange
      default:
        return "#3b82f6"; // blue
    }
  };

  const getAnimationDuration = (speed: TrafficDot["speed"]) => {
    switch (speed) {
      case "slow":
        return 4;
      case "fast":
        return 1;
      default:
        return 2;
    }
  };

  return (
    <div className="relative w-full h-full">
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 400 200">
        {/* Edge path */}
        <path
          d={edgePath}
          stroke="#374151"
          strokeWidth={2}
          fill="none"
          strokeDasharray="5,5"
        />

        {/* WAF Node indicator */}
        <g transform="translate(150, 80)">
          <rect
            x={-30}
            y={-15}
            width={60}
            height={30}
            rx={5}
            fill="#dc2626"
            className="waf-node"
          />
          <text x={0} y={5} textAnchor="middle" fill="white" fontSize={12}>
            WAF
          </text>
        </g>

        {/* Traffic dots */}
        <AnimatePresence>
          {dots.map((dot, index) => (
            <motion.circle
              key={dot.id}
              r={8}
              fill={getDotColor(dot.status)}
              initial={{ offsetDistance: "0%" }}
              animate={{ offsetDistance: "100%" }}
              transition={{
                duration: getAnimationDuration(dot.speed),
                ease: "linear",
              }}
              style={{
                offsetPath: `path("${edgePath}")`,
              }}
              onAnimationComplete={() => onDotComplete?.(dot.id)}
            >
              {/* Pulse effect for blocked */}
              {dot.status === "blocked" && (
                <animate
                  attributeName="r"
                  values="8;12;8"
                  dur="0.3s"
                  repeatCount="indefinite"
                />
              )}
            </motion.circle>
          ))}
        </AnimatePresence>
      </svg>

      {/* Status overlay */}
      <div className="absolute bottom-4 right-4 space-y-1">
        {dots.slice(-3).map((dot) => (
          <motion.div
            key={dot.id}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            className={`
              px-3 py-1.5 rounded-full text-xs flex items-center gap-2
              ${dot.status === "blocked" ? "bg-red-900/50 text-red-300" : ""}
              ${dot.status === "allowed" ? "bg-green-900/50 text-green-300" : ""}
              ${dot.status === "evaluating" ? "bg-orange-900/50 text-orange-300" : ""}
              ${dot.status === "traveling" ? "bg-blue-900/50 text-blue-300" : ""}
            `}
          >
            {dot.status === "blocked" && <X className="w-3 h-3" />}
            {dot.status === "allowed" && <Check className="w-3 h-3" />}
            {dot.status === "evaluating" && <Shield className="w-3 h-3 animate-pulse" />}
            {dot.status === "traveling" && <div className="w-3 h-3 rounded-full bg-blue-400" />}
            <span>
              {dot.request.method} {dot.request.uri.split("?")[0]}
            </span>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

// WAF Evaluation Animation Component
interface WAFAvaluationAnimationProps {
  result: EvaluationResult;
  isEvaluating: boolean;
}

export const WAFAvaluationAnimation: React.FC<WAFAvaluationAnimationProps> = ({
  result,
  isEvaluating,
}) => {
  const [currentRuleIndex, setCurrentRuleIndex] = useState(0);

  useEffect(() => {
    if (isEvaluating && result.ruleTrace.length > 0) {
      const timer = setInterval(() => {
        setCurrentRuleIndex((prev) => {
          if (prev >= result.ruleTrace.length - 1) {
            clearInterval(timer);
            return prev;
          }
          return prev + 1;
        });
      }, 200);

      return () => clearInterval(timer);
    }
  }, [isEvaluating, result.ruleTrace.length]);

  return (
    <div className="relative">
      {/* WAF Shield Icon */}
      <motion.div
        className="relative w-16 h-16 mx-auto"
        animate={{
          scale: isEvaluating ? [1, 1.1, 1] : 1,
        }}
        transition={{
          duration: 0.5,
          repeat: isEvaluating ? Infinity : 0,
        }}
      >
        <Shield
          className={`w-16 h-16 ${
            result.finalAction === "BLOCK"
              ? "text-red-500"
              : result.finalAction === "ALLOW"
              ? "text-green-500"
              : "text-gray-400"
          }`}
          fill={
            result.finalAction === "BLOCK"
              ? "#ef4444"
              : result.finalAction === "ALLOW"
              ? "#22c55e"
              : "transparent"
          }
        />

        {/* Evaluating pulse */}
        {isEvaluating && (
          <motion.div
            className="absolute inset-0 rounded-full border-2 border-orange-500"
            animate={{
              scale: [1, 1.5],
              opacity: [1, 0],
            }}
            transition={{
              duration: 1,
              repeat: Infinity,
            }}
          />
        )}
      </motion.div>

      {/* Rule evaluation animation */}
      <AnimatePresence>
        {isEvaluating && result.ruleTrace.slice(0, currentRuleIndex + 1).map((trace, idx) => (
          <motion.div
            key={trace.ruleName}
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`text-xs mt-1 ${
              trace.matched ? "text-yellow-400" : "text-gray-500"
            }`}
          >
            {idx + 1}. {trace.ruleName} {trace.matched ? "✓" : "✗"}
          </motion.div>
        ))}
      </AnimatePresence>

      {/* Final result */}
      {!isEvaluating && result.finalAction && (
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          className={`
            absolute -bottom-8 left-1/2 -translate-x-1/2
            px-3 py-1 rounded-full text-sm font-bold
            ${
              result.finalAction === "BLOCK"
                ? "bg-red-500 text-white"
                : "bg-green-500 text-white"
            }
          `}
        >
          {result.finalAction}
        </motion.div>
      )}
    </div>
  );
};

// Traffic Flow Visualization
interface TrafficFlowProps {
  requests: Array<{
    id: string;
    status: "pending" | "blocked" | "allowed";
  }>;
}

export const TrafficFlow: React.FC<TrafficFlowProps> = ({ requests }) => {
  const blockedCount = requests.filter((r) => r.status === "blocked").length;
  const allowedCount = requests.filter((r) => r.status === "allowed").length;

  return (
    <div className="flex items-center gap-2 p-2 bg-gray-800 rounded-lg">
      <div className="flex items-center gap-1">
        <div className="w-3 h-3 rounded-full bg-blue-500" />
        <span className="text-xs text-gray-400">
          {requests.filter((r) => r.status === "pending").length}
        </span>
      </div>
      <div className="flex items-center gap-1">
        <div className="w-3 h-3 rounded-full bg-green-500" />
        <span className="text-xs text-gray-400">{allowedCount}</span>
      </div>
      <div className="flex items-center gap-1">
        <div className="w-3 h-3 rounded-full bg-red-500" />
        <span className="text-xs text-gray-400">{blockedCount}</span>
      </div>
    </div>
  );
};

export default TrafficAnimation;
