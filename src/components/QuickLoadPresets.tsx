"use client";

import React from "react";
import { AttackPreset } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Database,
  Code,
  Terminal,
  Shield,
  AlertTriangle,
  Zap,
  Bot,
  Lock,
  Activity,
} from "lucide-react";

interface QuickLoadPresetsProps {
  presets: AttackPreset[];
  onSelect: (preset: AttackPreset) => void;
}

const getCategoryIcon = (category: AttackPreset["category"]) => {
  switch (category) {
    case "sqli":
      return <Database className="w-4 h-4" />;
    case "xss":
      return <Code className="w-4 h-4" />;
    case "rce":
      return <Terminal className="w-4 h-4" />;
    case "traversal":
      return <Shield className="w-4 h-4" />;
    case "auth":
      return <Lock className="w-4 h-4" />;
    case "flood":
      return <Activity className="w-4 h-4" />;
    case "bot":
      return <Bot className="w-4 h-4" />;
    default:
      return <AlertTriangle className="w-4 h-4" />;
  }
};

const getCategoryColor = (category: AttackPreset["category"]) => {
  switch (category) {
    case "sqli":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "xss":
      return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "rce":
      return "bg-purple-500/20 text-purple-400 border-purple-500/30";
    case "traversal":
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "auth":
      return "bg-pink-500/20 text-pink-400 border-pink-500/30";
    case "flood":
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case "bot":
      return "bg-gray-500/20 text-gray-400 border-gray-500/30";
    default:
      return "bg-green-500/20 text-green-400 border-green-500/30";
  }
};

export const QuickLoadPresets: React.FC<QuickLoadPresetsProps> = ({ presets, onSelect }) => {
  // Group presets by category
  const groupedPresets = presets.reduce(
    (acc, preset) => {
      const category = preset.category;
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(preset);
      return acc;
    },
    {} as Record<string, AttackPreset[]>
  );

  return (
    <div className="space-y-4">
      {Object.entries(groupedPresets).map(([category, categoryPresets]) => (
        <div key={category}>
          <h3 className="text-sm font-semibold text-gray-400 uppercase mb-2 flex items-center gap-2">
            {getCategoryIcon(category as AttackPreset["category"])}
            {category}
          </h3>
          <div className="space-y-2">
            {categoryPresets.map((preset) => (
              <div
                key={preset.id}
                className="p-3 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors cursor-pointer"
                onClick={() => onSelect(preset)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium">{preset.name}</span>
                      <Badge className={getCategoryColor(preset.category)} variant="outline">
                        {preset.category.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-sm text-gray-400">{preset.description}</p>
                    {preset.expectedBehavior && (
                      <p className="text-xs text-gray-500 mt-1 italic">
                        Expected: {preset.expectedBehavior}
                      </p>
                    )}
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-blue-400 hover:text-blue-300"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelect(preset);
                    }}
                  >
                    <Zap className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

export default QuickLoadPresets;
