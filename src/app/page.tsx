"use client";

import React, { useState, useCallback, useEffect, useRef } from "react";
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
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from "@/components/ui/dialog";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import {
  Shield, Play, Download, Upload, Trash2, FileJson, Code, Copy, Check,
  Settings, X, List, Zap, ChevronDown, ChevronUp,
} from "lucide-react";
import { evaluateWebACL } from "@/engines/wafEngine";
import { exportAsWebACLJson, exportAsTerraformHCL, generateCLICommands } from "@/engines/exportEngine";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Rule, HttpRequest, EvaluationResult } from "@/lib/types";

interface SampledRequest {
  timestamp: string;
  request: HttpRequest;
  result: EvaluationResult;
  wafName: string;
  wafId: string;
  pathResults: Array<{ wafName: string; wafId: string; result: EvaluationResult }>;
}

export default function WAFSimPage() {
  const store = useWAFSimStore();
  const {
    nodes, edges, wafs, ipSets, regexPatternSets,
    selectedNodeId, selectedWAFId, evaluationResult, lastEvaluatedWAFId,
    currentRequest, setCurrentRequest,
    setEvaluationResultWithWAF, clearEvaluationResult,
    createWAFOnEdge, selectWAF, selectNode,
    exportState, importState, resetState,
    addRuleToWAF, updateRuleInWAF, setIsSimulating, isSimulating,
  } = store;

  const [copied, setCopied] = useState<string | null>(null);
  const [showResources, setShowResources] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [showRuleBuilder, setShowRuleBuilder] = useState(false);
  const [rightPanelOpen, setRightPanelOpen] = useState(true);
  const [ruleBuilderMode, setRuleBuilderMode] = useState<"create" | "edit">("create");
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [bottomTab, setBottomTab] = useState<string | null>(null);
  const [bottomHeight, setBottomHeight] = useState(300);
  const [sampledRequests, setSampledRequests] = useState<SampledRequest[]>([]);
  const [isAnimating, setIsAnimating] = useState(false);
  const [wafResults, setWafResults] = useState<Map<string, string>>(new Map()); // wafId -> action
  const [trafficEdges, setTrafficEdges] = useState<Map<string, "passed" | "blocked">>(new Map()); // edgeId -> status

  // Only show WAF config when a WAF is explicitly selected (not fallback)
  const activeWAF = wafs.find(w => w.id === selectedWAFId) || null;
  // For simulation, use all WAFs
  const hasAnyWAF = wafs.length > 0;

  // When node is clicked, auto-select its WAF if it has one
  useEffect(() => {
    if (!selectedNodeId) return;
    const node = nodes.find(n => n.id === selectedNodeId);
    if (node?.type === "WAF" && node.wafId) { selectWAF(node.wafId); setRightPanelOpen(true); return; }
    const wafEdge = edges.find(e => e.target === selectedNodeId && e.wafId);
    if (wafEdge?.wafId) { selectWAF(wafEdge.wafId); setRightPanelOpen(true); return; }
    // Non-WAF node clicked: clear WAF selection
    selectWAF(null as unknown as string);
  }, [selectedNodeId]);

  // Attach WAF to selected node - creates a visible WAF node and connects it
  const handleAttachWAF = useCallback(() => {
    if (!selectedNodeId) return;
    const node = nodes.find(n => n.id === selectedNodeId);
    if (!node?.wafAttachable) return;

    // Create the WAF
    const wafId = store.createWAF({
      name: `WAF-${node.label}`,
      description: `Protecting ${node.label}`,
      scope: (node.scope || "REGIONAL") as "CLOUDFRONT" | "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "WAFMetric" },
      capacity: 0,
    });

    // Create a WAF node positioned above the resource
    const wafNodeId = store.addNode({
      type: "WAF",
      label: "WAF WebACL",
      icon: "🛡️",
      wafAttachable: false,
      wafId,
      position: { x: node.position.x, y: node.position.y - 100 },
    });

    // Connect WAF node to resource
    store.addEdge({ source: wafNodeId, target: selectedNodeId, wafId });

    selectWAF(wafId);
    toast.success(`WAF created and attached to ${node.label}`);
  }, [selectedNodeId, nodes, store, selectWAF]);

  // Run simulation through ALL WAFs in the topology
  const handleSimulate = useCallback(() => {
    if (wafs.length === 0) { toast.error("No WAF configured"); return; }
    setIsSimulating(true);
    setIsAnimating(true);

    setTimeout(() => {
      const pathResults: Array<{ wafName: string; wafId: string; result: EvaluationResult }> = [];
      let finalResult: EvaluationResult | null = null;
      let terminatingWafId: string | null = null;

      for (const waf of wafs) {
        const result = evaluateWebACL(currentRequest, waf, { ipSets, regexPatternSets });
        pathResults.push({ wafName: waf.name, wafId: waf.id, result });
        finalResult = result;
        terminatingWafId = waf.id;
        if (result.finalAction === "BLOCK" || result.finalAction === "CAPTCHA" || result.finalAction === "CHALLENGE") {
          break;
        }
      }

      if (finalResult && terminatingWafId) {
        setEvaluationResultWithWAF(finalResult, terminatingWafId);
      }
      // Store per-WAF results for visual feedback on each edge
      const resultsMap = new Map<string, string>();
      pathResults.forEach(pr => resultsMap.set(pr.wafId, pr.result.finalAction));
      setWafResults(resultsMap);

      // Compute traffic flow: which edges did traffic pass through?
      const flowMap = new Map<string, "passed" | "blocked">();
      
      // Find which resources are directly protected by blocking WAFs
      const blockedAtNodes = new Set<string>();
      for (const pr of pathResults) {
        if (pr.result.finalAction === "BLOCK") {
          edges.filter(e => e.wafId === pr.wafId).forEach(e => blockedAtNodes.add(e.target));
        }
      }

      // Propagate: find ALL nodes downstream of blocked nodes (BFS)
      const allBlockedNodes = new Set<string>(blockedAtNodes);
      const queue = [...blockedAtNodes];
      while (queue.length > 0) {
        const nodeId = queue.shift()!;
        // Find all traffic edges going OUT of this node
        for (const edge of edges) {
          if (edge.wafId) continue; // skip WAF edges
          const srcNode = nodes.find(n => n.id === edge.source);
          if (srcNode?.type === "WAF") continue;
          if (edge.source === nodeId && !allBlockedNodes.has(edge.target)) {
            allBlockedNodes.add(edge.target);
            queue.push(edge.target);
          }
        }
      }

      // Mark all traffic edges
      for (const edge of edges) {
        if (edge.wafId) continue;
        const srcNode = nodes.find(n => n.id === edge.source);
        if (srcNode?.type === "WAF") continue;
        
        if (allBlockedNodes.has(edge.source)) {
          // Source is at or beyond the block point: no traffic flows
          flowMap.set(edge.id, "blocked");
        } else {
          // Traffic flows through this edge (even if target is the blocked node, traffic reached it)
          flowMap.set(edge.id, "passed");
        }
      }
      setTrafficEdges(flowMap);
      setIsSimulating(false);

      setSampledRequests(prev => [{
        timestamp: new Date().toISOString(),
        request: currentRequest,
        result: finalResult!,
        wafName: wafs.find(w => w.id === terminatingWafId)?.name || "",
        wafId: terminatingWafId!,
        pathResults,
      }, ...prev].slice(0, 100));

      if (!bottomTab) setBottomTab("results");
    }, 600);
  }, [wafs, currentRequest, ipSets, regexPatternSets, bottomTab]);

  const handleNodeClick = useCallback((nodeId: string) => selectNode(nodeId), [selectNode]);
  const handleEdgeClick = useCallback((edgeId: string) => {
    const edge = edges.find(e => e.id === edgeId);
    if (edge?.wafId) selectWAF(edge.wafId);
  }, [edges, selectWAF]);

  const handleEditRule = useCallback((rule: Rule) => {
    setEditingRule(rule); setRuleBuilderMode("edit"); setShowRuleBuilder(true);
  }, []);
  const handleCreateRule = useCallback(() => {
    setEditingRule(null); setRuleBuilderMode("create"); setShowRuleBuilder(true);
  }, []);
  const handleSaveRule = useCallback((rule: Rule) => {
    if (!activeWAF) return;
    if (ruleBuilderMode === "edit" && editingRule) {
      updateRuleInWAF(activeWAF.id, editingRule.name, rule);
    } else {
      addRuleToWAF(activeWAF.id, { ...rule, priority: activeWAF.rules.length + 1 });
    }
    toast.success(`Rule "${rule.name}" ${ruleBuilderMode === "edit" ? "updated" : "created"}`);
    setShowRuleBuilder(false); setEditingRule(null);
  }, [activeWAF, ruleBuilderMode, editingRule]);

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text); setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  // Determine right panel state
  const selectedNode = nodes.find(n => n.id === selectedNodeId);
  const nodeHasWAF = selectedNode ? edges.some(e => e.target === selectedNodeId && e.wafId) : false;
  const canAttach = selectedNode?.wafAttachable && !nodeHasWAF;

  return (
    <div className="h-screen flex flex-col bg-gray-950 text-white overflow-hidden">
      {/* Header */}
      <header className="h-11 border-b border-gray-800 flex items-center justify-between px-3 md:px-4 bg-gray-900 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-red-500" />
          <span className="text-base font-bold hidden sm:inline">AWS WAFSim</span>
          <span className="text-base font-bold sm:hidden">WAFSim</span>
          <Badge variant="outline" className="text-[10px] bg-gray-800 ml-1 hidden sm:inline-flex">v2</Badge>
        </div>
        <div className="flex items-center gap-0.5 md:gap-1">
          <a href="https://github.com/ApurvaDesai6/wafsim" target="_blank" rel="noopener noreferrer" className="inline-flex items-center justify-center h-7 px-2 text-xs text-gray-400 hover:text-white rounded-md hover:bg-gray-800 transition-colors">
            <svg viewBox="0 0 16 16" fill="currentColor" className="w-3.5 h-3.5"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
          </a>
          <Button variant="ghost" size="sm" onClick={() => setShowResources(true)} className="h-7 text-xs text-gray-400 hidden md:inline-flex"><Settings className="w-3 h-3 mr-1" />Resources</Button>
          <Button variant="ghost" size="sm" onClick={() => { const i = document.createElement("input"); i.type = "file"; i.accept = ".json"; i.onchange = (e) => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) { const r = new FileReader(); r.onload = (e) => { try { importState(e.target?.result as string); toast.success("Imported"); } catch { toast.error("Failed"); } }; r.readAsText(f); } }; i.click(); }} className="h-7 text-xs text-gray-400 hidden sm:inline-flex"><Upload className="w-3 h-3 mr-1" />Import</Button>
          <Button variant="ghost" size="sm" onClick={() => setShowExport(true)} className="h-7 text-xs text-gray-400 hidden sm:inline-flex"><Download className="w-3 h-3 mr-1" />Export</Button>
          <Button variant="ghost" size="sm" onClick={() => { if (confirm("Reset everything?")) { resetState(); setSampledRequests([]); toast.success("Reset"); } }} className="h-7 text-xs text-red-400"><Trash2 className="w-3 h-3" /></Button>
        </div>
      </header>

      {/* Main area */}
      <div className="flex-1 flex flex-col md:flex-row overflow-hidden min-h-0">
        {/* Left: Topology + Bottom Panel */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Topology Canvas */}
          <div className="flex-1 relative min-h-0">
            <TopologyCanvas
              onNodeClick={handleNodeClick}
              onEdgeClick={handleEdgeClick}
              evaluationStatus={evaluationResult ? (evaluationResult.finalAction === "BLOCK" ? "blocked" : evaluationResult.finalAction === "ALLOW" ? "allowed" : "counted") : null}
              evaluatedWAFId={lastEvaluatedWAFId}
              isAnimating={isAnimating}
              bottomPanelOpen={!!bottomTab}
              wafResults={wafResults}
              trafficEdges={trafficEdges}
            />
          </div>

          {/* Bottom Panel Bar */}
          <div className="border-t border-gray-700 bg-gray-900 shrink-0">
            <div className="flex items-center h-11 px-3 gap-2">
              {(["simulator", "results", "logs"] as const).map(tab => (
                <button key={tab} onClick={() => setBottomTab(bottomTab === tab ? null : tab)}
                  className={`px-3 py-1.5 text-sm font-medium rounded transition-colors ${bottomTab === tab ? "bg-gray-700 text-white" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"}`}>
                  {tab === "simulator" && "⚡ Simulate"}
                  {tab === "results" && <>Results {evaluationResult && <Badge className={`ml-1.5 text-[10px] px-1.5 py-0 ${evaluationResult.finalAction === "BLOCK" ? "bg-red-600" : evaluationResult.finalAction === "ALLOW" ? "bg-green-600" : "bg-yellow-600"}`}>{evaluationResult.finalAction}</Badge>}</>}
                  {tab === "logs" && <>Sampled Requests {sampledRequests.length > 0 && <Badge variant="outline" className="ml-1.5 text-[10px] px-1.5 py-0">{sampledRequests.length}</Badge>}</>}
                </button>
              ))}
              <button disabled className="px-3 py-1.5 text-sm rounded text-gray-600 cursor-not-allowed" title="Coming soon: guided false positive exception workflow">
                False Positive Exceptions <Badge variant="outline" className="text-[9px] px-1 text-gray-600 border-gray-700 ml-1">Soon</Badge>
              </button>
              {bottomTab && (
                <button onClick={() => setBottomTab(null)} className="text-gray-500 hover:text-gray-300 ml-1" title="Close panel">
                  <X className="w-4 h-4" />
                </button>
              )}
              <div className="flex-1" />
              {wafs.length > 0 && (
                <>
                  {isAnimating && (
                    <Button size="sm" onClick={() => setIsAnimating(false)} variant="outline" className="h-8 text-sm px-3 border-gray-600">
                      ⏹ Stop
                    </Button>
                  )}
                  <Button size="sm" onClick={handleSimulate} disabled={isSimulating} className="h-8 text-sm bg-green-700 hover:bg-green-600 px-5">
                    <Play className="w-4 h-4 mr-1.5" />{isSimulating ? "Running..." : "Run Test"}
                  </Button>
                </>
              )}
            </div>

            {/* Bottom panel content */}
            {bottomTab && (
              <div style={{ height: bottomHeight }} className="border-t border-gray-800 overflow-hidden">
                {bottomTab === "simulator" && (
                  <TrafficSimulator onSimulate={handleSimulate} />
                )}
                {bottomTab === "results" && (
                  evaluationResult ? (
                    <div className="h-full overflow-y-auto"><EvaluationTrace result={evaluationResult} /></div>
                  ) : (
                    <div className="h-full flex items-center justify-center text-gray-500 text-sm">Run a simulation to see results</div>
                  )
                )}
                {bottomTab === "logs" && (
                  <div className="h-full overflow-auto">
                    {sampledRequests.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-gray-500 text-sm">No requests yet</div>
                    ) : (
                      <table className="w-full text-[11px]">
                        <thead className="sticky top-0 bg-gray-800 z-10">
                          <tr className="text-gray-400 text-left">
                            <th className="p-1.5 pl-3">Time</th>
                            <th className="p-1.5">Method</th>
                            <th className="p-1.5">URI</th>
                            <th className="p-1.5">Source IP</th>
                            <th className="p-1.5">Action</th>
                            <th className="p-1.5">WAF</th>
                            <th className="p-1.5">Rule</th>
                            <th className="p-1.5">Path</th>
                          </tr>
                        </thead>
                        <tbody>
                          {sampledRequests.map((sr, i) => (
                            <tr key={i} className="border-t border-gray-800/50 hover:bg-gray-800/50 cursor-pointer"
                              onClick={() => { setCurrentRequest(sr.request); setEvaluationResultWithWAF(sr.result, lastEvaluatedWAFId); setBottomTab("results"); }}>
                              <td className="p-1.5 pl-3 text-gray-500 font-mono">{new Date(sr.timestamp).toLocaleTimeString()}</td>
                              <td className="p-1.5"><Badge variant="outline" className="text-[9px] px-1">{sr.request.method}</Badge></td>
                              <td className="p-1.5 font-mono max-w-[180px] truncate">{sr.request.uri}</td>
                              <td className="p-1.5 font-mono">{sr.request.sourceIP}</td>
                              <td className="p-1.5">
                                <Badge className={`text-[9px] px-1 ${sr.result.finalAction === "BLOCK" ? "bg-red-600" : sr.result.finalAction === "ALLOW" ? "bg-green-600" : "bg-yellow-600"}`}>
                                  {sr.result.finalAction}
                                </Badge>
                              </td>
                              <td className="p-1.5 text-gray-300 max-w-[100px] truncate">{sr.wafName}</td>
                              <td className="p-1.5 text-gray-300 max-w-[120px] truncate">{sr.result.terminatingRule?.rule.name || "Default"}</td>
                              <td className="p-1.5 text-gray-500">
                                {sr.pathResults.map((pr, j) => (
                                  <Badge key={j} variant="outline" className={`text-[8px] px-1 mr-0.5 ${pr.result.finalAction === "BLOCK" ? "border-red-600 text-red-400" : "border-green-600 text-green-400"}`}>
                                    {pr.wafName}: {pr.result.finalAction}
                                  </Badge>
                                ))}
                              </td>
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

        {/* Right Panel: WAF Config - collapsible */}
        {rightPanelOpen ? (
        <div className="w-full md:w-[380px] border-t md:border-t-0 md:border-l border-gray-700 flex flex-col shrink-0 overflow-hidden max-h-[40vh] md:max-h-none relative">
          <button onClick={() => setRightPanelOpen(false)} className="absolute top-2 right-2 z-10 text-gray-500 hover:text-gray-300" title="Hide panel">
            <X className="w-4 h-4" />
          </button>
          {activeWAF ? (
            <WAFConfigPanel wafId={activeWAF.id} onEditRule={handleEditRule} onCreateRule={handleCreateRule} />
          ) : selectedNode?.wafAttachable ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <Shield className="w-14 h-14 text-green-400/50 mb-4" />
              <p className="font-medium">{selectedNode.label}</p>
              <p className="text-xs text-gray-400 mt-1 mb-5">Supports WAF protection</p>
              {canAttach ? (
                <Button onClick={handleAttachWAF} className="bg-green-600 hover:bg-green-700">
                  <Shield className="w-4 h-4 mr-2" />Attach WAF WebACL
                </Button>
              ) : (
                <p className="text-xs text-yellow-400">Connect a source node first</p>
              )}
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <Shield className="w-14 h-14 text-gray-700 mb-4" />
              <p className="font-medium text-gray-400">AWS WAF Rule Simulator</p>
              <p className="text-xs text-gray-500 mt-2 leading-relaxed max-w-[280px]">
                Test and tune WAF rules against simulated traffic. Drag a WAF WebACL from the left palette and connect it to a resource to get started.
              </p>
            </div>
          )}
        </div>
        ) : (
          <button onClick={() => setRightPanelOpen(true)} className="w-8 border-l border-gray-700 bg-gray-900 flex items-center justify-center shrink-0 hover:bg-gray-800 text-gray-500 hover:text-gray-300" title="Show WAF config panel">
            <Shield className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Rule Builder */}
      <Dialog open={showRuleBuilder} onOpenChange={setShowRuleBuilder}>
        <DialogContent className="bg-gray-900 border-gray-700 max-w-2xl max-h-[85vh] overflow-hidden">
          <DialogHeader><DialogTitle>{ruleBuilderMode === "edit" ? "Edit Rule" : "Create Rule"}</DialogTitle></DialogHeader>
          <div className="overflow-y-auto max-h-[calc(85vh-80px)]">
            <RuleBuilder rule={editingRule || undefined} onSave={handleSaveRule} onCancel={() => { setShowRuleBuilder(false); setEditingRule(null); }} />
          </div>
        </DialogContent>
      </Dialog>

      {/* Resources */}
      <Sheet open={showResources} onOpenChange={setShowResources}>
        <SheetContent className="bg-gray-900 border-gray-700 w-[400px]">
          <SheetHeader><SheetTitle>IP Sets & Regex Patterns</SheetTitle></SheetHeader>
          <div className="mt-4"><ResourceManager /></div>
        </SheetContent>
      </Sheet>

      {/* Export */}
      <Dialog open={showExport} onOpenChange={setShowExport}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-hidden bg-gray-900 border-gray-700">
          <DialogHeader><DialogTitle>Export Configuration</DialogTitle></DialogHeader>
          <Tabs defaultValue="json" className="mt-2">
            <TabsList className="bg-gray-800">
              <TabsTrigger value="json"><FileJson className="w-3.5 h-3.5 mr-1" />JSON</TabsTrigger>
              <TabsTrigger value="terraform"><Code className="w-3.5 h-3.5 mr-1" />Terraform</TabsTrigger>
              <TabsTrigger value="cli"><Code className="w-3.5 h-3.5 mr-1" />CLI</TabsTrigger>
            </TabsList>
            {["json", "terraform", "cli"].map(tab => (
              <TabsContent key={tab} value={tab}>
                {wafs.length > 0 ? (
                  <div className="relative">
                    <Button size="sm" variant="outline" className="absolute top-2 right-2 z-10" onClick={() => {
                      const c = tab === "json" ? JSON.stringify(exportAsWebACLJson(wafs[0]), null, 2) : tab === "terraform" ? exportAsTerraformHCL(wafs[0], ipSets, regexPatternSets) : generateCLICommands(wafs[0], ipSets, regexPatternSets).join("\n\n");
                      copyText(c, tab); toast.success("Copied!");
                    }}>{copied === tab ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}</Button>
                    <pre className="bg-gray-800 p-3 rounded overflow-auto max-h-80 text-xs font-mono text-gray-300">
                      {tab === "json" ? JSON.stringify(exportAsWebACLJson(wafs[0]), null, 2) : tab === "terraform" ? exportAsTerraformHCL(wafs[0], ipSets, regexPatternSets) : generateCLICommands(wafs[0], ipSets, regexPatternSets).join("\n\n")}
                    </pre>
                  </div>
                ) : <div className="text-center py-8 text-gray-500">No WAF to export</div>}
              </TabsContent>
            ))}
          </Tabs>
          <Button onClick={() => { const b = new Blob([exportState()], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = "wafsim-config.json"; a.click(); toast.success("Saved!"); }} className="w-full mt-3">
            <Download className="w-4 h-4 mr-2" />Save Full Config
          </Button>
        </DialogContent>
      </Dialog>
    </div>
  );
}
