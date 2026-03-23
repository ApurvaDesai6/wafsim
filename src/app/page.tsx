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
  Plus,
  X,
  ChevronUp,
  ChevronDown,
  List,
} from "lucide-react";
import { evaluateWebACL } from "@/engines/wafEngine";
import { exportAsWebACLJson, exportAsTerraformHCL, generateCLICommands } from "@/engines/exportEngine";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Rule, HttpRequest, EvaluationResult } from "@/lib/types";

// Sampled request log entry
interface SampledRequest {
  timestamp: string;
  request: HttpRequest;
  result: EvaluationResult;
  action: string;
  terminatingRule: string | null;
}

export default function WAFSimPage() {
  const {
    nodes,
    edges,
    wafs,
    ipSets,
    regexPatternSets,
    selectedNodeId,
    selectedWAFId,
    evaluationResult,
    lastEvaluatedWAFId,
    currentRequest,
    setEvaluationResultWithWAF,
    clearEvaluationResult,
    createWAFOnEdge,
    selectWAF,
    selectNode,
    exportState,
    importState,
    resetState,
    addRuleToWAF,
    updateRuleInWAF,
    setCurrentRequest,
    setIsSimulating,
    isSimulating,
  } = useWAFSimStore();

  const [copied, setCopied] = useState<string | null>(null);
  const [showResourcesPanel, setShowResourcesPanel] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [showRuleBuilder, setShowRuleBuilder] = useState(false);
  const [ruleBuilderMode, setRuleBuilderMode] = useState<"create" | "edit">("create");
  const [bottomPanel, setBottomPanel] = useState<"closed" | "simulator" | "results" | "logs">("closed");
  const [sampledRequests, setSampledRequests] = useState<SampledRequest[]>([]);
  const [showExportModal, setShowExportModal] = useState(false);

  // Auto-select WAF when clicking a WAF-attachable node
  const selectedNode = nodes.find((n) => n.id === selectedNodeId);
  const selectedWAF = wafs.find((w) => w.id === selectedWAFId);

  // Find WAF attached to selected node (via edge)
  const wafForSelectedNode = useCallback(() => {
    if (!selectedNodeId) return null;
    const incomingEdge = edges.find((e) => e.target === selectedNodeId && e.wafId);
    if (incomingEdge?.wafId) return wafs.find((w) => w.id === incomingEdge.wafId) || null;
    // Also check if the node itself is a WAF
    const node = nodes.find((n) => n.id === selectedNodeId);
    if (node?.wafId) return wafs.find((w) => w.id === node.wafId) || null;
    return null;
  }, [selectedNodeId, edges, wafs, nodes]);

  // When a node is selected, auto-select its WAF
  useEffect(() => {
    const waf = wafForSelectedNode();
    if (waf) selectWAF(waf.id);
  }, [selectedNodeId]);

  // Handle attaching WAF to a node
  const handleAttachWAF = useCallback(() => {
    if (!selectedNodeId || !selectedNode?.wafAttachable) return;
    const incomingEdge = edges.find((e) => e.target === selectedNodeId);
    if (!incomingEdge || incomingEdge.wafId) return;

    createWAFOnEdge(incomingEdge.id, {
      name: `WAF-${selectedNode.label}`,
      description: `Protecting ${selectedNode.label}`,
      scope: selectedNode.scope || "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "WAFMetric" },
      capacity: 0,
    });
    toast.success(`WAF attached to ${selectedNode.label}`);
  }, [selectedNodeId, selectedNode, edges, createWAFOnEdge]);

  // Handle node click from canvas
  const handleNodeClick = useCallback((nodeId: string) => {
    selectNode(nodeId);
  }, [selectNode]);

  // Handle edge click - select the WAF on that edge
  const handleEdgeClick = useCallback((edgeId: string) => {
    const edge = edges.find((e) => e.id === edgeId);
    if (edge?.wafId) selectWAF(edge.wafId);
  }, [edges, selectWAF]);

  // Run simulation
  const handleSimulate = useCallback(() => {
    const activeWAF = selectedWAF || (wafs.length > 0 ? wafs[0] : null);
    if (!activeWAF) { toast.error("No WAF configured"); return; }

    setIsSimulating(true);
    const result = evaluateWebACL(currentRequest, activeWAF, { ipSets, regexPatternSets });
    setEvaluationResultWithWAF(result, activeWAF.id);
    setIsSimulating(false);

    // Add to sampled requests log
    setSampledRequests((prev) => [{
      timestamp: new Date().toISOString(),
      request: currentRequest,
      result,
      action: result.finalAction,
      terminatingRule: result.terminatingRule?.rule.name || null,
    }, ...prev].slice(0, 100));

    setBottomPanel("results");
  }, [selectedWAF, wafs, currentRequest, ipSets, regexPatternSets]);

  // Handle edit/create rule
  const handleEditRule = useCallback((rule: Rule) => {
    setEditingRule(rule);
    setRuleBuilderMode("edit");
    setShowRuleBuilder(true);
  }, []);

  const handleCreateRule = useCallback(() => {
    setEditingRule(null);
    setRuleBuilderMode("create");
    setShowRuleBuilder(true);
  }, []);

  const handleSaveRule = useCallback((rule: Rule) => {
    const waf = selectedWAF || (wafs.length > 0 ? wafs[0] : null);
    if (!waf) return;
    if (ruleBuilderMode === "edit" && editingRule) {
      updateRuleInWAF(waf.id, editingRule.name, rule);
      toast.success(`Rule "${rule.name}" updated`);
    } else {
      addRuleToWAF(waf.id, { ...rule, priority: waf.rules.length + 1 });
      toast.success(`Rule "${rule.name}" created`);
    }
    setShowRuleBuilder(false);
    setEditingRule(null);
  }, [selectedWAF, wafs, ruleBuilderMode, editingRule, addRuleToWAF, updateRuleInWAF]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
    toast.success("Copied!");
  };

  const activeWAF = selectedWAF || (wafs.length > 0 ? wafs[0] : null);
  const nodeHasWAF = selectedNode ? !!wafForSelectedNode() : false;
  const canAttachWAF = selectedNode?.wafAttachable && !nodeHasWAF && edges.some((e) => e.target === selectedNodeId && !e.wafId);

  return (
    <div className="h-screen flex flex-col bg-gray-950 text-white overflow-hidden select-none">
      {/* Header */}
      <header className="h-12 border-b border-gray-800 flex items-center justify-between px-4 bg-gray-900 shrink-0">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-red-500" />
          <h1 className="text-lg font-bold">WAFSim</h1>
          <Badge variant="outline" className="text-[10px] bg-gray-800">v2</Badge>
        </div>
        <div className="flex items-center gap-1.5">
          <Button variant="ghost" size="sm" onClick={() => setShowResourcesPanel(true)} className="text-gray-400 hover:text-white h-8 text-xs">
            <Settings className="w-3.5 h-3.5 mr-1" />IP Sets
          </Button>
          <Button variant="outline" size="sm" onClick={() => { const input = document.createElement("input"); input.type = "file"; input.accept = ".json"; input.onchange = (e) => { const file = (e.target as HTMLInputElement).files?.[0]; if (file) { const reader = new FileReader(); reader.onload = (e) => { try { importState(e.target?.result as string); toast.success("Imported!"); } catch { toast.error("Import failed"); } }; reader.readAsText(file); } }; input.click(); }} className="border-gray-700 h-8 text-xs">
            <Upload className="w-3.5 h-3.5 mr-1" />Import
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShowExportModal(true)} className="border-gray-700 h-8 text-xs">
            <Download className="w-3.5 h-3.5 mr-1" />Export
          </Button>
          <Button variant="destructive" size="sm" onClick={() => { if (confirm("Reset all?")) { resetState(); setSampledRequests([]); toast.success("Reset!"); } }} className="h-8 text-xs">
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </header>

      {/* Main Content: Topology + Right Panel */}
      <div className="flex-1 flex overflow-hidden">
        {/* Topology Canvas - always visible */}
        <div className="flex-1 relative">
          <TopologyCanvas
            onNodeClick={handleNodeClick}
            onEdgeClick={handleEdgeClick}
            evaluationStatus={
              evaluationResult?.finalAction === "BLOCK" ? "blocked" :
              evaluationResult?.finalAction === "ALLOW" ? "allowed" :
              evaluationResult?.finalAction === "COUNT" ? "counted" : null
            }
            evaluatedWAFId={lastEvaluatedWAFId}
          />

          {/* Bottom toolbar */}
          <div className="absolute bottom-0 left-0 right-0 bg-gray-900/95 border-t border-gray-700 backdrop-blur-sm">
            <div className="flex items-center gap-1 px-3 py-1.5">
              <Button size="sm" variant={bottomPanel === "simulator" ? "default" : "ghost"} onClick={() => setBottomPanel(bottomPanel === "simulator" ? "closed" : "simulator")} className="h-7 text-xs">
                <Zap className="w-3.5 h-3.5 mr-1" />Simulate
              </Button>
              <Button size="sm" variant={bottomPanel === "results" ? "default" : "ghost"} onClick={() => setBottomPanel(bottomPanel === "results" ? "closed" : "results")} className="h-7 text-xs">
                <Play className="w-3.5 h-3.5 mr-1" />Results
                {evaluationResult && (
                  <Badge className={`ml-1 text-[9px] px-1 ${evaluationResult.finalAction === "BLOCK" ? "bg-red-600" : evaluationResult.finalAction === "ALLOW" ? "bg-green-600" : "bg-yellow-600"}`}>
                    {evaluationResult.finalAction}
                  </Badge>
                )}
              </Button>
              <Button size="sm" variant={bottomPanel === "logs" ? "default" : "ghost"} onClick={() => setBottomPanel(bottomPanel === "logs" ? "closed" : "logs")} className="h-7 text-xs">
                <List className="w-3.5 h-3.5 mr-1" />Sampled Requests
                {sampledRequests.length > 0 && <Badge variant="outline" className="ml-1 text-[9px] px-1">{sampledRequests.length}</Badge>}
              </Button>

              <div className="flex-1" />

              {/* Quick simulate button */}
              {activeWAF && (
                <Button size="sm" onClick={handleSimulate} disabled={isSimulating} className="h-7 text-xs bg-green-700 hover:bg-green-600">
                  <Play className="w-3.5 h-3.5 mr-1" />{isSimulating ? "Running..." : "Run"}
                </Button>
              )}
            </div>

            {/* Bottom panel content */}
            {bottomPanel !== "closed" && (
              <div className="h-[280px] border-t border-gray-700 overflow-hidden flex">
                {bottomPanel === "simulator" && (
                  <TrafficSimulator onSimulate={() => handleSimulate()} />
                )}
                {bottomPanel === "results" && (
                  evaluationResult ? (
                    <div className="flex-1 overflow-y-auto">
                      <EvaluationTrace result={evaluationResult} />
                    </div>
                  ) : (
                    <div className="flex-1 flex items-center justify-center text-gray-500">
                      <div className="text-center">
                        <Play className="w-10 h-10 mx-auto mb-2 opacity-30" />
                        <p className="text-sm">Run a simulation to see results</p>
                      </div>
                    </div>
                  )
                )}
                {bottomPanel === "logs" && (
                  <div className="flex-1 overflow-y-auto">
                    {sampledRequests.length === 0 ? (
                      <div className="flex items-center justify-center h-full text-gray-500 text-sm">No sampled requests yet</div>
                    ) : (
                      <table className="w-full text-xs">
                        <thead className="sticky top-0 bg-gray-800">
                          <tr className="text-gray-400">
                            <th className="text-left p-2">Time</th>
                            <th className="text-left p-2">Method</th>
                            <th className="text-left p-2">URI</th>
                            <th className="text-left p-2">Source IP</th>
                            <th className="text-left p-2">Country</th>
                            <th className="text-left p-2">Action</th>
                            <th className="text-left p-2">Terminating Rule</th>
                            <th className="text-left p-2">Labels</th>
                          </tr>
                        </thead>
                        <tbody>
                          {sampledRequests.map((sr, i) => (
                            <tr key={i} className="border-t border-gray-800 hover:bg-gray-800/50 cursor-pointer" onClick={() => { setCurrentRequest(sr.request); setEvaluationResultWithWAF(sr.result, lastEvaluatedWAFId); setBottomPanel("results"); }}>
                              <td className="p-2 text-gray-400 font-mono">{new Date(sr.timestamp).toLocaleTimeString()}</td>
                              <td className="p-2"><Badge variant="outline" className="text-[10px]">{sr.request.method}</Badge></td>
                              <td className="p-2 font-mono max-w-[200px] truncate">{sr.request.uri}</td>
                              <td className="p-2 font-mono">{sr.request.sourceIP}</td>
                              <td className="p-2">{sr.request.country}</td>
                              <td className="p-2">
                                <Badge className={`text-[10px] ${sr.action === "BLOCK" ? "bg-red-600" : sr.action === "ALLOW" ? "bg-green-600" : "bg-yellow-600"}`}>
                                  {sr.action}
                                </Badge>
                              </td>
                              <td className="p-2 text-gray-300">{sr.terminatingRule || "Default"}</td>
                              <td className="p-2 text-gray-400">{sr.result.labelsApplied.join(", ") || "—"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Panel - WAF Config (always visible) */}
        <div className="w-[340px] border-l border-gray-700 flex flex-col shrink-0">
          {activeWAF ? (
            <WAFConfigPanel
              wafId={activeWAF.id}
              onEditRule={handleEditRule}
              onCreateRule={handleCreateRule}
            />
          ) : selectedNode?.wafAttachable ? (
            <div className="flex-1 flex flex-col items-center justify-center p-6 text-center">
              <Shield className="w-12 h-12 text-green-400 mb-3 opacity-60" />
              <p className="font-medium text-sm">{selectedNode.label}</p>
              <p className="text-xs text-gray-400 mt-1 mb-4">This resource supports WAF protection</p>
              {canAttachWAF ? (
                <Button onClick={handleAttachWAF} className="bg-green-600 hover:bg-green-700">
                  <Shield className="w-4 h-4 mr-2" />Attach WAF
                </Button>
              ) : (
                <p className="text-xs text-yellow-400">Connect a source to this node first</p>
              )}
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-6 text-center">
              <Shield className="w-12 h-12 text-gray-600 mb-3" />
              <p className="font-medium text-sm text-gray-400">Select a Resource</p>
              <p className="text-xs text-gray-500 mt-1">Click a WAF-ready node (green border) to configure protection</p>
            </div>
          )}
        </div>
      </div>

      {/* Rule Builder Dialog */}
      <Dialog open={showRuleBuilder} onOpenChange={setShowRuleBuilder}>
        <DialogContent className="bg-gray-900 border-gray-700 max-w-2xl max-h-[90vh] overflow-hidden">
          <DialogHeader>
            <DialogTitle>{ruleBuilderMode === "edit" ? "Edit Rule" : "Create Rule"}</DialogTitle>
          </DialogHeader>
          <div className="overflow-y-auto max-h-[calc(90vh-120px)]">
            <RuleBuilder rule={editingRule || undefined} onSave={handleSaveRule} onCancel={() => { setShowRuleBuilder(false); setEditingRule(null); }} />
          </div>
        </DialogContent>
      </Dialog>

      {/* Resources Panel */}
      <Sheet open={showResourcesPanel} onOpenChange={setShowResourcesPanel}>
        <SheetContent className="bg-gray-900 border-gray-700 w-[400px]">
          <SheetHeader><SheetTitle>IP Sets & Regex Pattern Sets</SheetTitle></SheetHeader>
          <div className="mt-4"><ResourceManager /></div>
        </SheetContent>
      </Sheet>

      {/* Export Modal */}
      <Dialog open={showExportModal} onOpenChange={setShowExportModal}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden bg-gray-900 border-gray-700">
          <DialogHeader><DialogTitle>Export Configuration</DialogTitle></DialogHeader>
          <Tabs defaultValue="json" className="mt-4">
            <TabsList className="bg-gray-800">
              <TabsTrigger value="json" className="data-[state=active]:bg-gray-700"><FileJson className="w-4 h-4 mr-1" />AWS JSON</TabsTrigger>
              <TabsTrigger value="terraform" className="data-[state=active]:bg-gray-700"><Code className="w-4 h-4 mr-1" />Terraform</TabsTrigger>
              <TabsTrigger value="cli" className="data-[state=active]:bg-gray-700"><Code className="w-4 h-4 mr-1" />CLI</TabsTrigger>
            </TabsList>
            {["json", "terraform", "cli"].map((tab) => (
              <TabsContent key={tab} value={tab} className="mt-4">
                {wafs.length > 0 ? (
                  <div className="relative">
                    <Button size="sm" variant="outline" className="absolute top-2 right-2 z-10" onClick={() => {
                      const content = tab === "json" ? JSON.stringify(exportAsWebACLJson(wafs[0]), null, 2) : tab === "terraform" ? exportAsTerraformHCL(wafs[0], ipSets, regexPatternSets) : generateCLICommands(wafs[0], ipSets, regexPatternSets).join("\n\n");
                      copyToClipboard(content, tab);
                    }}>
                      {copied === tab ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    </Button>
                    <pre className="bg-gray-800 p-4 rounded-lg overflow-auto max-h-96 text-sm font-mono text-gray-300">
                      {tab === "json" ? JSON.stringify(exportAsWebACLJson(wafs[0]), null, 2) : tab === "terraform" ? exportAsTerraformHCL(wafs[0], ipSets, regexPatternSets) : generateCLICommands(wafs[0], ipSets, regexPatternSets).join("\n\n")}
                    </pre>
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500"><Shield className="w-12 h-12 mx-auto mb-2 opacity-50" /><p>No WAF to export</p></div>
                )}
              </TabsContent>
            ))}
          </Tabs>
          <div className="mt-4 pt-4 border-t border-gray-700">
            <Button onClick={() => { const blob = new Blob([exportState()], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "wafsim-config.json"; a.click(); toast.success("Saved!"); }} className="w-full">
              <Download className="w-4 h-4 mr-2" />Save Full Configuration
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
