"use client";

// WAFSim v3 rc.9.3 — Welcome overlay with starting templates.
//
// Rendered on first-load (or after a reset) when the workspace doesn't
// contain meaningful user work yet. Kills the "dropped into an editor
// with no explanation" UX.
//
// Shows templates, a brief value-prop hero, and a clear CTA.

import React from "react";
import { Shield, ArrowRight, Sparkles, Share2, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useWAFSimStore } from "@/store/wafsimStore";
import { WORKSPACE_TEMPLATES, templateToImportJson, type WorkspaceTemplate } from "@/lib/workspaceTemplates";
import { toast } from "sonner";

interface Props {
  onDismiss: () => void;
}

const DIFFICULTY_TONE: Record<WorkspaceTemplate["difficulty"], string> = {
  Starter: "bg-green-600",
  Intermediate: "bg-blue-600",
  Advanced: "bg-purple-600",
};

export function WelcomeOverlay({ onDismiss }: Props) {
  const { importState } = useWAFSimStore();

  const applyTemplate = (t: WorkspaceTemplate) => {
    importState(templateToImportJson(t));
    toast.success(`Loaded "${t.name}" template`, {
      description: `${t.nodes.length} nodes · ${t.edges.length} edges · ${t.wafs.length} WebACL${t.wafs.length === 1 ? "" : "s"}`,
    });
    onDismiss();
  };

  return (
    <div className="absolute inset-0 z-30 bg-gray-950/95 backdrop-blur-sm overflow-auto">
      <div className="max-w-5xl mx-auto px-6 py-10">
        {/* Hero */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-3">
            <Shield className="w-6 h-6 text-blue-400" />
            <span className="text-xs uppercase tracking-widest text-gray-400">
              WAFSim
            </span>
          </div>
          <h1 className="text-3xl font-semibold text-gray-50 mb-2">
            Design, test, and tune AWS WAF rules visually
          </h1>
          <p className="text-sm text-gray-400 max-w-2xl mx-auto leading-relaxed">
            Build a topology, attach WebACLs, run live traffic simulations,
            and generate false-positive exceptions — all without deploying
            a single rule to production.
          </p>
          <div className="flex items-center justify-center gap-4 mt-4 text-[11px] text-gray-500">
            <span className="flex items-center gap-1">
              <Sparkles className="w-3 h-3" /> 14 managed rule groups
            </span>
            <span className="text-gray-700">·</span>
            <span className="flex items-center gap-1">
              <Share2 className="w-3 h-3" /> Shareable state URLs
            </span>
            <span className="text-gray-700">·</span>
            <span className="flex items-center gap-1">
              <Download className="w-3 h-3" /> Export to CFN / Terraform
            </span>
          </div>
        </div>

        {/* Templates */}
        <div className="mb-3">
          <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-3">
            Start with a template
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {WORKSPACE_TEMPLATES.map((t) => (
              <button
                key={t.id}
                onClick={() => applyTemplate(t)}
                className="group text-left p-4 rounded-lg border border-gray-800 bg-gray-900/60 hover:border-blue-500/60 hover:bg-blue-500/5 transition-all"
              >
                <div className="flex items-start gap-3">
                  <div className="text-2xl shrink-0">{t.icon}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold text-gray-100">
                        {t.name}
                      </span>
                      <Badge className={cn("text-[9px] py-0", DIFFICULTY_TONE[t.difficulty])}>
                        {t.difficulty}
                      </Badge>
                    </div>
                    <div className="text-[12px] text-blue-400 mb-1">
                      {t.tagline}
                    </div>
                    <div className="text-[11px] text-gray-400 leading-relaxed">
                      {t.description}
                    </div>
                    <div className="flex items-center gap-3 mt-2 text-[10px] text-gray-600 font-mono">
                      <span>{t.nodes.length} nodes</span>
                      <span>·</span>
                      <span>{t.edges.length} edges</span>
                      <span>·</span>
                      <span>
                        {t.wafs.length} WebACL{t.wafs.length === 1 ? "" : "s"}
                      </span>
                      {t.wafs.reduce((acc, w) => acc + w.rules.length, 0) > 0 && (
                        <>
                          <span>·</span>
                          <span>
                            {t.wafs.reduce((acc, w) => acc + w.rules.length, 0)} rules
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-gray-700 group-hover:text-blue-400 group-hover:translate-x-1 transition-all" />
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Quick actions */}
        <div className="mt-6 flex items-center justify-center gap-3 text-[11px]">
          <Button
            onClick={onDismiss}
            variant="outline"
            size="sm"
            className="h-8 text-xs border-gray-700"
          >
            Skip to blank workspace
          </Button>
          <span className="text-gray-600">
            Or paste a shared URL into the address bar to load a workspace.
          </span>
        </div>
      </div>
    </div>
  );
}
