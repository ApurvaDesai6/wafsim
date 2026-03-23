"use client";

import React, { useState, useCallback, useEffect } from "react";
import { useWAFSimStore } from "@/store/wafsimStore";
import { TopologyCanvas } from "@/components/TopologyCanvas";
import { WAFConfigPanel } from "@/components/WAFConfigPanel";
import { TrafficSimulator } from "@/components/TrafficSimulator";
import { EvaluationTrace } from "@/components/EvaluationTrace";
import { RuleBuilder } from "@/components/RuleBuilder";
import { ResourceManager } from "@/components/ResourceManager";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Shield,
  Play,
  Download,
  Upload,
  Trash2,
  Network,
  Zap,
  FileJson,
  Code,
  Copy,
  Check,
  Settings,
  Info,
  AlertTriangle,
  Plus,
  X,
} from "lucide-react";
import { evaluateWebACL } from "@/engines/wafEngine";
import { exportAsWebACLJson, exportAsTerraformHCL, generateCLICommands } from "@/engines/exportEngine";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Rule } from "@/lib/types";

export default function WAFSimPage() {
  const {
    nodes,
    edges,
    wafs,
    ipSets,
    regexPatternSets,
    selectedEdgeId,
    selectedWAFId,
    evaluationResult,
    lastEvaluatedWAFId,
    setEvaluationResult,
    createWAFOnEdge,
    selectWAF,
    selectEdge,
    exportState,
    importState,
    resetState,
    activeTab,
    setActiveTab,
    showExportModal,
    setShowExportModal,
    addRuleToWAF,
    updateRuleInWAF,
    clearEvaluationResult,
  } = useWAFSimStore();

  const [copied, setCopied] = useState<string | null>(null);
  const [showResourcesPanel, setShowResourcesPanel] = useState(false);
  const [showEdgeDialog, setShowEdgeDialog] = useState(false);
  const [showInfoDialog, setShowInfoDialog] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [showRuleBuilder, setShowRuleBuilder] = useState(false);
  const [ruleBuilderMode, setRuleBuilderMode] = useState<"create" | "edit">("create");

  // Find selected edge and WAF
  const selectedEdge = edges.find((e) => e.id === selectedEdgeId);
  const selectedWAF = wafs.find((w) => w.id === selectedWAFId || w.id === selectedEdge?.wafId);

  // Check if WAF can be attached to selected edge
  const canAttachWAF = useCallback(() => {
    if (!selectedEdge) return false;
    if (selectedEdge.wafId) return false; // Already has WAF

    const targetNode = nodes.find((n) => n.id === selectedEdge.target);
    if (!targetNode?.wafAttachable) return false;

    return true;
  }, [selectedEdge, nodes]);

  // Handle WAF attachment
  const handleAttachWAF = () => {
    if (!canAttachWAF() || !selectedEdge) return;

    const targetNode = nodes.find((n) => n.id === selectedEdge.target);
    
    createWAFOnEdge(selectedEdge.id, {
      name: `WAF-${targetNode?.label || "WebACL"}`,
      description: `WAF protecting ${targetNode?.label}`,
      scope: targetNode?.scope || "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: "WAFMetric",
      },
      capacity: 0,
    });

    toast.success("WAF attached successfully! Configure it in the right panel.");
    setShowEdgeDialog(false);
  };

  // Handle edge click
  const handleEdgeClick = useCallback((edgeId: string) => {
    const edge = edges.find((e) => e.id === edgeId);
    if (edge?.wafId) {
      selectWAF(edge.wafId);
    } else {
      selectEdge(edgeId);
      setShowEdgeDialog(true);
    }
  }, [edges, selectWAF, selectEdge]);

  // Handle edit rule from WAFConfigPanel
  const handleEditRule = useCallback((rule: Rule) => {
    setEditingRule(rule);
    setRuleBuilderMode("edit");
    setShowRuleBuilder(true);
  }, []);

  // Handle create new rule
  const handleCreateRule = useCallback(() => {
    setEditingRule(null);
    setRuleBuilderMode("create");
    setShowRuleBuilder(true);
  }, []);

  // Handle save rule from RuleBuilder
  const handleSaveRule = useCallback((rule: Rule) => {
    if (!selectedWAF) return;

    if (ruleBuilderMode === "edit" && editingRule) {
      // Update existing rule
      updateRuleInWAF(selectedWAF.id, editingRule.name, rule);
      toast.success(`Rule "${rule.name}" updated successfully!`);
    } else {
      // Add new rule
      addRuleToWAF(selectedWAF.id, {
        ...rule,
        priority: selectedWAF.rules.length + 1,
      });
      toast.success(`Rule "${rule.name}" created successfully!`);
    }

    setShowRuleBuilder(false);
    setEditingRule(null);
  }, [selectedWAF, ruleBuilderMode, editingRule, addRuleToWAF, updateRuleInWAF]);

  // Handle export
  const handleExport = () => {
    setShowExportModal(true);
  };

  // Handle import
  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
          const content = e.target?.result as string;
          try {
            importState(content);
            toast.success("Configuration imported successfully!");
          } catch {
            toast.error("Failed to import configuration");
          }
        };
        reader.readAsText(file);
      }
    };
    input.click();
  };

  // Copy to clipboard
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
    toast.success("Copied to clipboard!");
  };

  // Get active WAF for simulation
  const activeWAF = wafs.length > 0 ? wafs[0] : null;

  // Automatically switch to simulate tab when evaluation result is available
  useEffect(() => {
    if (evaluationResult && activeTab === "topology") {
      // Keep topology tab active but show overlay results
    }
  }, [evaluationResult, activeTab]);

  return (
    <div className="h-screen flex flex-col bg-gray-950 text-white overflow-hidden">
      {/* Header */}
      <header className="h-14 border-b border-gray-800 flex items-center justify-between px-4 bg-gray-900 shrink-0">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-red-500" />
          <h1 className="text-xl font-bold">WAFSim</h1>
          <Badge variant="outline" className="text-xs bg-gray-800">
            AWS WAF Testing Dashboard
          </Badge>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowInfoDialog(true)}
            className="text-gray-400 hover:text-white"
          >
            <Info className="w-4 h-4 mr-1" />
            Help
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowResourcesPanel(true)}
            className="text-gray-400 hover:text-white"
          >
            <Settings className="w-4 h-4 mr-1" />
            Resources
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleImport}
            className="border-gray-700"
          >
            <Upload className="w-4 h-4 mr-1" />
            Import
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExport}
            className="border-gray-700"
          >
            <Download className="w-4 h-4 mr-1" />
            Export
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => {
              if (confirm("Are you sure you want to reset? This will clear all configuration.")) {
                resetState();
                toast.success("Configuration reset!");
              }
            }}
          >
            <Trash2 className="w-4 h-4 mr-1" />
            Reset
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        <ResizablePanelGroup direction="horizontal">
          {/* Left Panel - Topology Canvas */}
          <ResizablePanel defaultSize={activeTab === "simulate" ? 40 : 70} minSize={30}>
            <Tabs
              value={activeTab}
              onValueChange={(v) => setActiveTab(v as "topology" | "simulate" | "export")}
              className="h-full flex flex-col"
            >
              <TabsList className="mx-4 mt-2 bg-gray-800 shrink-0">
                <TabsTrigger value="topology" className="data-[state=active]:bg-gray-700">
                  <Network className="w-4 h-4 mr-1" />
                  Topology
                </TabsTrigger>
                <TabsTrigger value="simulate" className="data-[state=active]:bg-gray-700">
                  <Zap className="w-4 h-4 mr-1" />
                  Simulate
                </TabsTrigger>
              </TabsList>

              <TabsContent value="topology" className="flex-1 relative m-0">
                <TopologyCanvas
                  onEdgeClick={handleEdgeClick}
                  evaluationStatus={
                    evaluationResult?.finalAction === "BLOCK" ? "blocked" :
                    evaluationResult?.finalAction === "ALLOW" ? "allowed" :
                    evaluationResult?.finalAction === "COUNT" ? "counted" : null
                  }
                  evaluatedWAFId={lastEvaluatedWAFId}
                />
                
                {/* Evaluation Result Overlay - Shows in topology view */}
                {evaluationResult && (
                  <div className="absolute bottom-4 right-4 w-80 max-h-[60vh] bg-gray-900/95 border border-gray-700 rounded-lg shadow-xl overflow-hidden backdrop-blur-sm">
                    <div className="flex items-center justify-between p-3 border-b border-gray-700 bg-gray-800">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Zap className="w-4 h-4 text-yellow-400" />
                        Last Evaluation Result
                      </h3>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => clearEvaluationResult()}
                        className="h-6 w-6 p-0"
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                    <div className="max-h-[calc(60vh-48px)] overflow-y-auto">
                      <EvaluationTrace result={evaluationResult} />
                    </div>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="simulate" className="flex-1 flex m-0">
                <ResizablePanelGroup direction="horizontal">
                  <ResizablePanel defaultSize={50} minSize={30}>
                    <TrafficSimulator />
                  </ResizablePanel>
                  <ResizableHandle withHandle />
                  <ResizablePanel defaultSize={50} minSize={30}>
                    {evaluationResult ? (
                      <EvaluationTrace result={evaluationResult} />
                    ) : (
                      <div className="h-full flex items-center justify-center text-gray-500 bg-gray-900">
                        <div className="text-center p-8">
                          <Play className="w-16 h-16 mx-auto mb-4 opacity-50" />
                          <p className="text-lg font-medium">No Simulation Results</p>
                          <p className="text-sm mt-2">Run a simulation to see rule evaluation results</p>
                        </div>
                      </div>
                    )}
                  </ResizablePanel>
                </ResizablePanelGroup>
              </TabsContent>
            </Tabs>
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* Right Panel - WAF Configuration */}
          <ResizablePanel defaultSize={activeTab === "simulate" ? 20 : 30} minSize={20}>
            {selectedWAF ? (
              <WAFConfigPanel 
                wafId={selectedWAF.id} 
                onEditRule={handleEditRule}
                onCreateRule={handleCreateRule}
              />
            ) : (
              <div className="h-full flex items-center justify-center text-gray-500 bg-gray-900">
                <div className="text-center p-4">
                  <Shield className="w-16 h-16 mx-auto mb-4 opacity-50" />
                  <p className="font-medium text-lg">No WAF Selected</p>
                  <p className="text-sm mt-2 text-gray-400">
                    Click on an edge to attach a WAF, or drag a WAF onto the canvas
                  </p>
                  <div className="mt-4 text-xs text-gray-500">
                    <p>WAF-ready resources show a</p>
                    <p className="text-green-400 flex items-center justify-center gap-1 mt-1">
                      <Shield className="w-3 h-3" /> WAF Ready badge
                    </p>
                  </div>
                </div>
              </div>
            )}
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {/* Edge Action Dialog */}
      <Dialog open={showEdgeDialog} onOpenChange={setShowEdgeDialog}>
        <DialogContent className="bg-gray-900 border-gray-700 max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Network className="w-5 h-5" />
              Edge Configuration
            </DialogTitle>
            <DialogDescription className="text-gray-400">
              Configure the connection between resources
            </DialogDescription>
          </DialogHeader>

          <div className="mt-4 space-y-4">
            {selectedEdge && (
              <div className="p-3 bg-gray-800 rounded-lg">
                <div className="text-sm text-gray-400">Connection</div>
                <div className="flex items-center gap-2 mt-1">
                  <Badge variant="outline">
                    {nodes.find((n) => n.id === selectedEdge.source)?.label}
                  </Badge>
                  <span className="text-gray-500">→</span>
                  <Badge variant="outline">
                    {nodes.find((n) => n.id === selectedEdge.target)?.label}
                  </Badge>
                </div>
              </div>
            )}

            {canAttachWAF() ? (
              <div className="space-y-3">
                <div className="p-3 bg-green-900/20 border border-green-500/30 rounded-lg">
                  <div className="flex items-center gap-2 text-green-400">
                    <Shield className="w-4 h-4" />
                    <span className="font-medium">WAF Available</span>
                  </div>
                  <p className="text-xs text-gray-400 mt-1">
                    This edge connects to a WAF-compatible resource. Attach a WAF to inspect and filter traffic.
                  </p>
                </div>
                <Button
                  onClick={handleAttachWAF}
                  className="w-full bg-green-600 hover:bg-green-700"
                >
                  <Shield className="w-4 h-4 mr-2" />
                  Attach WAF WebACL
                </Button>
              </div>
            ) : selectedEdge?.wafId ? (
              <div className="p-3 bg-blue-900/20 border border-blue-500/30 rounded-lg">
                <div className="flex items-center gap-2 text-blue-400">
                  <Shield className="w-4 h-4" />
                  <span className="font-medium">WAF Already Attached</span>
                </div>
                <p className="text-xs text-gray-400 mt-1">
                  Click on the edge again to configure the WAF
                </p>
              </div>
            ) : (
              <div className="p-3 bg-yellow-900/20 border border-yellow-500/30 rounded-lg">
                <div className="flex items-center gap-2 text-yellow-400">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="font-medium">WAF Not Available</span>
                </div>
                <p className="text-xs text-gray-400 mt-1">
                  The target resource does not support WAF attachment. Valid targets: CloudFront, ALB, API Gateway, AppSync, Cognito.
                </p>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Rule Builder Dialog */}
      <Dialog open={showRuleBuilder} onOpenChange={setShowRuleBuilder}>
        <DialogContent className="bg-gray-900 border-gray-700 max-w-2xl max-h-[90vh] overflow-hidden">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              {ruleBuilderMode === "edit" ? "Edit Rule" : "Create New Rule"}
            </DialogTitle>
            <DialogDescription className="text-gray-400">
              {ruleBuilderMode === "edit" 
                ? "Modify the rule configuration below"
                : "Configure your new WAF rule below"}
            </DialogDescription>
          </DialogHeader>
          <div className="overflow-y-auto max-h-[calc(90vh-120px)]">
            <RuleBuilder
              rule={editingRule || undefined}
              onSave={handleSaveRule}
              onCancel={() => {
                setShowRuleBuilder(false);
                setEditingRule(null);
              }}
            />
          </div>
        </DialogContent>
      </Dialog>

      {/* Resources Panel */}
      <Sheet open={showResourcesPanel} onOpenChange={setShowResourcesPanel}>
        <SheetContent className="bg-gray-900 border-gray-700 w-[400px]">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Settings className="w-5 h-5" />
              Resources
            </SheetTitle>
          </SheetHeader>
          <div className="mt-4">
            <ResourceManager />
          </div>
        </SheetContent>
      </Sheet>

      {/* Help Dialog */}
      <Dialog open={showInfoDialog} onOpenChange={setShowInfoDialog}>
        <DialogContent className="bg-gray-900 border-gray-700 max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Info className="w-5 h-5" />
              How to Use WAFSim
            </DialogTitle>
          </DialogHeader>
          <div className="mt-4 space-y-4 text-sm">
            <Card className="bg-gray-800 border-gray-700">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Network className="w-4 h-4 text-blue-400" />
                  1. Build Topology
                </CardTitle>
              </CardHeader>
              <CardContent className="text-gray-400 text-xs">
                <ul className="list-disc list-inside space-y-1">
                  <li>Drag resources from the left palette onto the canvas</li>
                  <li>Connect nodes by dragging from handles (dots on sides)</li>
                  <li>Double-click nodes for options</li>
                  <li>Resources with green dashed borders support WAF</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-gray-800 border-gray-700">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="w-4 h-4 text-red-400" />
                  2. Attach WAF
                </CardTitle>
              </CardHeader>
              <CardContent className="text-gray-400 text-xs">
                <ul className="list-disc list-inside space-y-1">
                  <li>Click on an edge (connection line) between resources</li>
                  <li>Choose "Attach WAF" to add protection</li>
                  <li>Or drag a WAF WebACL from the palette</li>
                  <li>Configure rules in the right panel</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-gray-800 border-gray-700">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  3. Simulate Traffic
                </CardTitle>
              </CardHeader>
              <CardContent className="text-gray-400 text-xs">
                <ul className="list-disc list-inside space-y-1">
                  <li>Switch to the Simulate tab or stay in Topology</li>
                  <li>Configure your test request or use presets</li>
                  <li>Use natural language to generate attack patterns</li>
                  <li>Review the evaluation trace to see rule matches</li>
                  <li>Results appear as overlay in topology view</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-gray-800 border-gray-700">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Download className="w-4 h-4 text-green-400" />
                  4. Export Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="text-gray-400 text-xs">
                <ul className="list-disc list-inside space-y-1">
                  <li>Export as AWS WAF JSON for CLI deployment</li>
                  <li>Export as Terraform HCL</li>
                  <li>Save/Load full configuration</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </DialogContent>
      </Dialog>

      {/* Export Modal */}
      <Dialog open={showExportModal} onOpenChange={setShowExportModal}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden bg-gray-900 border-gray-700">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Download className="w-5 h-5" />
              Export Configuration
            </DialogTitle>
          </DialogHeader>

          <Tabs defaultValue="json" className="mt-4">
            <TabsList className="bg-gray-800">
              <TabsTrigger value="json" className="data-[state=active]:bg-gray-700">
                <FileJson className="w-4 h-4 mr-1" />
                AWS JSON
              </TabsTrigger>
              <TabsTrigger value="terraform" className="data-[state=active]:bg-gray-700">
                <Code className="w-4 h-4 mr-1" />
                Terraform
              </TabsTrigger>
              <TabsTrigger value="cli" className="data-[state=active]:bg-gray-700">
                <Code className="w-4 h-4 mr-1" />
                CLI Commands
              </TabsTrigger>
            </TabsList>

            <TabsContent value="json" className="mt-4">
              {wafs.length > 0 ? (
                <div className="relative">
                  <Button
                    size="sm"
                    variant="outline"
                    className="absolute top-2 right-2 z-10"
                    onClick={() =>
                      copyToClipboard(
                        JSON.stringify(exportAsWebACLJson(wafs[0]), null, 2),
                        "json"
                      )
                    }
                  >
                    {copied === "json" ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </Button>
                  <pre className="bg-gray-800 p-4 rounded-lg overflow-auto max-h-96 text-sm font-mono text-gray-300">
                    {JSON.stringify(exportAsWebACLJson(wafs[0]), null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No WAF configuration to export</p>
                  <p className="text-sm">Create a WAF first</p>
                </div>
              )}
            </TabsContent>

            <TabsContent value="terraform" className="mt-4">
              {wafs.length > 0 ? (
                <div className="relative">
                  <Button
                    size="sm"
                    variant="outline"
                    className="absolute top-2 right-2 z-10"
                    onClick={() =>
                      copyToClipboard(
                        exportAsTerraformHCL(wafs[0], ipSets, regexPatternSets),
                        "terraform"
                      )
                    }
                  >
                    {copied === "terraform" ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </Button>
                  <pre className="bg-gray-800 p-4 rounded-lg overflow-auto max-h-96 text-sm font-mono text-gray-300">
                    {exportAsTerraformHCL(wafs[0], ipSets, regexPatternSets)}
                  </pre>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No WAF configuration to export</p>
                </div>
              )}
            </TabsContent>

            <TabsContent value="cli" className="mt-4">
              {wafs.length > 0 ? (
                <div className="relative">
                  <Button
                    size="sm"
                    variant="outline"
                    className="absolute top-2 right-2 z-10"
                    onClick={() =>
                      copyToClipboard(
                        generateCLICommands(wafs[0], ipSets, regexPatternSets).join("\n\n"),
                        "cli"
                      )
                    }
                  >
                    {copied === "cli" ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </Button>
                  <pre className="bg-gray-800 p-4 rounded-lg overflow-auto max-h-96 text-sm font-mono text-gray-300">
                    {generateCLICommands(wafs[0], ipSets, regexPatternSets).join("\n\n")}
                  </pre>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No WAF configuration to export</p>
                </div>
              )}
            </TabsContent>
          </Tabs>

          {/* Save Configuration */}
          <div className="mt-4 pt-4 border-t border-gray-700">
            <Button
              onClick={() => {
                const state = exportState();
                const blob = new Blob([state], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "wafsim-config.json";
                a.click();
                URL.revokeObjectURL(url);
                toast.success("Configuration saved!");
              }}
              className="w-full"
            >
              <Download className="w-4 h-4 mr-2" />
              Save Full Configuration
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
