// WAFSim - Global State Store
// Zustand store for application state management

import { create } from "zustand";
import { persist } from "zustand/middleware";
import { importWebACLJson } from "@/engines/importEngine";
import {
  WebACL,
  IPSet,
  RegexPatternSet,
  HttpRequest,
  EvaluationResult,
  TrafficDot,
  FloodSimulationResult,
  AWSResourceNode,
  TopologyEdge,
  Rule,
  Statement,
  WAFAction,
} from "@/lib/types";
import { v4 as uuidv4 } from "uuid";

interface WAFSimState {
  // Topology
  nodes: AWSResourceNode[];
  edges: TopologyEdge[];
  wafs: WebACL[];

  // Selected items
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  selectedWAFId: string | null;

  // Resources
  ipSets: IPSet[];
  regexPatternSets: RegexPatternSet[];

  // Simulation
  currentRequest: HttpRequest;
  evaluationResult: EvaluationResult | null;
  lastEvaluatedWAFId: string | null; // Track which WAF was last evaluated for visual feedback
  trafficDots: TrafficDot[];
  floodSimulationResult: FloodSimulationResult | null;

  // UI State
  isSimulating: boolean;
  animationSpeed: "slow" | "normal" | "fast";
  showRuleBuilder: boolean;
  showExportModal: boolean;
  showImportModal: boolean;
  activeTab: "topology" | "simulate" | "export";

  // Actions - Topology
  addNode: (node: Omit<AWSResourceNode, "id">) => string;
  updateNode: (id: string, updates: Partial<AWSResourceNode>) => void;
  removeNode: (id: string) => void;
  setNodes: (nodes: AWSResourceNode[]) => void;

  addEdge: (edge: Omit<TopologyEdge, "id">) => string;
  removeEdge: (id: string) => void;
  setEdges: (edges: TopologyEdge[]) => void;

  attachWAFToEdge: (edgeId: string, waf: WebACL) => void;
  removeWAFFromEdge: (edgeId: string) => void;

  // Actions - Selection
  selectNode: (id: string | null) => void;
  selectEdge: (id: string | null) => void;
  selectWAF: (id: string | null) => void;

  // Actions - WAF
  createWAF: (waf: Omit<WebACL, "id">) => string;
  createWAFOnEdge: (edgeId: string, waf: Omit<WebACL, "id">) => string;
  updateWAF: (id: string, updates: Partial<WebACL>) => void;
  deleteWAF: (id: string) => void;

  addRuleToWAF: (wafId: string, rule: Rule) => void;
  updateRuleInWAF: (wafId: string, ruleName: string, updates: Partial<Rule>) => void;
  removeRuleFromWAF: (wafId: string, ruleName: string) => void;
  reorderRules: (wafId: string, ruleNames: string[]) => void;

  // Actions - Resources
  createIPSet: (ipSet: Omit<IPSet, "id" | "arn">) => string;
  updateIPSet: (id: string, updates: Partial<IPSet>) => void;
  deleteIPSet: (id: string) => void;

  createRegexPatternSet: (set: Omit<RegexPatternSet, "id" | "arn">) => string;
  updateRegexPatternSet: (id: string, updates: Partial<RegexPatternSet>) => void;
  deleteRegexPatternSet: (id: string) => void;

  // Actions - Simulation
  setCurrentRequest: (request: HttpRequest) => void;
  setEvaluationResult: (result: EvaluationResult | null) => void;
  setEvaluationResultWithWAF: (result: EvaluationResult | null, wafId: string | null) => void;
  clearEvaluationResult: () => void;
  addTrafficDot: (dot: TrafficDot) => void;
  updateTrafficDot: (id: string, updates: Partial<TrafficDot>) => void;
  removeTrafficDot: (id: string) => void;
  clearTrafficDots: () => void;
  setFloodSimulationResult: (result: FloodSimulationResult | null) => void;
  setIsSimulating: (simulating: boolean) => void;

  // Actions - UI
  setAnimationSpeed: (speed: "slow" | "normal" | "fast") => void;
  setShowRuleBuilder: (show: boolean) => void;
  setShowExportModal: (show: boolean) => void;
  setShowImportModal: (show: boolean) => void;
  setActiveTab: (tab: "topology" | "simulate" | "export") => void;

  // Actions - Import/Export
  exportState: () => string;
  importState: (json: string) => void;
  importWebACL: (json: string) => { success: boolean; errors: string[]; warnings: string[] };
  resetState: () => void;
}

// Default request template
const defaultRequest: HttpRequest = {
  protocol: "HTTP/1.1",
  method: "GET",
  uri: "/api/users",
  queryParams: {},
  headers: [
    { name: "Host", value: "example.com" },
    { name: "User-Agent", value: "Mozilla/5.0" },
    { name: "Accept", value: "application/json" },
  ],
  body: "",
  bodyEncoding: "none",
  contentType: "application/json",
  sourceIP: "192.168.1.100",
  country: "US",
};

// Initial topology
const initialNodes: AWSResourceNode[] = [
  { id: "internet-1", type: "INTERNET", label: "Internet", icon: "🌐", wafAttachable: false, position: { x: 50, y: 220 } },
  { id: "cloudfront-1", type: "CLOUDFRONT", label: "CloudFront CDN", icon: "☁️", wafAttachable: true, scope: "CLOUDFRONT", position: { x: 250, y: 220 } },
  { id: "alb-1", type: "ALB", label: "Application Load Balancer", icon: "⚖️", wafAttachable: true, scope: "REGIONAL", position: { x: 480, y: 220 } },
  { id: "ecs-1", type: "ECS", label: "Web App (ECS)", icon: "🐳", wafAttachable: false, position: { x: 720, y: 120 } },
  { id: "lambda-1", type: "LAMBDA", label: "API Lambda", icon: "⚡", wafAttachable: false, position: { x: 720, y: 220 } },
  { id: "ecs-2", type: "ECS", label: "Auth Service (ECS)", icon: "🐳", wafAttachable: false, position: { x: 720, y: 320 } },
  { id: "apigw-1", type: "API_GATEWAY", label: "API Gateway", icon: "🔌", wafAttachable: true, scope: "REGIONAL", position: { x: 480, y: 420 } },
  { id: "lambda-2", type: "LAMBDA", label: "Webhook Handler", icon: "⚡", wafAttachable: false, position: { x: 720, y: 420 } },
];

const initialEdges: TopologyEdge[] = [
  { id: "edge-1", source: "internet-1", target: "cloudfront-1" },
  { id: "edge-2", source: "cloudfront-1", target: "alb-1" },
  { id: "edge-3", source: "alb-1", target: "ecs-1" },
  { id: "edge-4", source: "alb-1", target: "lambda-1" },
  { id: "edge-5", source: "alb-1", target: "ecs-2" },
  { id: "edge-6", source: "internet-1", target: "apigw-1" },
  { id: "edge-7", source: "apigw-1", target: "lambda-2" },
];

// Default WAF template
const defaultWAF: WebACL = {
  id: "waf-default",
  name: "MyWebACL",
  description: "Default WebACL configuration",
  scope: "REGIONAL",
  defaultAction: "ALLOW",
  rules: [],
  visibilityConfig: {
    sampledRequestsEnabled: true,
    cloudWatchMetricsEnabled: true,
    metricName: "MyWebACL",
  },
  capacity: 0,
};

export const useWAFSimStore = create<WAFSimState>()(
  persist(
    (set, get) => ({
      // Initial state
      nodes: initialNodes,
      edges: initialEdges,
      wafs: [],
      selectedNodeId: null,
      selectedEdgeId: null,
      selectedWAFId: null,
      ipSets: [],
      regexPatternSets: [],
      currentRequest: defaultRequest,
      evaluationResult: null,
      lastEvaluatedWAFId: null,
      trafficDots: [],
      floodSimulationResult: null,
      isSimulating: false,
      animationSpeed: "normal",
      showRuleBuilder: false,
      showExportModal: false,
      showImportModal: false,
      activeTab: "topology",

      // Topology actions
      addNode: (node) => {
        const id = uuidv4();
        set((state) => ({
          nodes: [...state.nodes, { ...node, id }],
        }));
        return id;
      },

      updateNode: (id, updates) => {
        set((state) => ({
          nodes: state.nodes.map((n) => (n.id === id ? { ...n, ...updates } : n)),
        }));
      },

      removeNode: (id) => {
        set((state) => ({
          nodes: state.nodes.filter((n) => n.id !== id),
          edges: state.edges.filter((e) => e.source !== id && e.target !== id),
        }));
      },

      setNodes: (nodes) => set({ nodes }),

      addEdge: (edge) => {
        const id = uuidv4();
        set((state) => ({
          edges: [...state.edges, { ...edge, id }],
        }));
        return id;
      },

      removeEdge: (id) => {
        set((state) => ({
          edges: state.edges.filter((e) => e.id !== id),
        }));
      },

      setEdges: (edges) => set({ edges }),

      attachWAFToEdge: (edgeId, waf) => {
        const wafId = uuidv4();
        set((state) => ({
          wafs: [...state.wafs, { ...waf, id: wafId }],
          edges: state.edges.map((e) =>
            e.id === edgeId ? { ...e, wafId } : e
          ),
        }));
      },

      removeWAFFromEdge: (edgeId) => {
        const edge = get().edges.find((e) => e.id === edgeId);
        if (edge?.wafId) {
          set((state) => ({
            wafs: state.wafs.filter((w) => w.id !== edge.wafId),
            edges: state.edges.map((e) =>
              e.id === edgeId ? { ...e, wafId: undefined } : e
            ),
          }));
        }
      },

      // Selection actions
      selectNode: (id) => set({ selectedNodeId: id, selectedEdgeId: null, selectedWAFId: null }),
      selectEdge: (id) => set({ selectedEdgeId: id, selectedNodeId: null, selectedWAFId: null }),
      selectWAF: (id) => set({ selectedWAFId: id, selectedNodeId: null, selectedEdgeId: null }),

      // WAF actions
      createWAF: (waf) => {
        const id = uuidv4();
        set((state) => ({
          wafs: [...state.wafs, { ...waf, id }],
        }));
        return id;
      },

      createWAFOnEdge: (edgeId, waf) => {
        const wafId = uuidv4();
        set((state) => {
          // Check if target node supports WAF
          const edge = state.edges.find(e => e.id === edgeId);
          if (!edge) return state;
          
          const targetNode = state.nodes.find(n => n.id === edge.target);
          if (!targetNode?.wafAttachable) {
            console.warn("WAF cannot be attached to this resource type");
            return state;
          }
          
          return {
            wafs: [...state.wafs, { ...waf, id: wafId }],
            edges: state.edges.map((e) =>
              e.id === edgeId ? { ...e, wafId } : e
            ),
          };
        });
        return wafId;
      },

      updateWAF: (id, updates) => {
        set((state) => ({
          wafs: state.wafs.map((w) => (w.id === id ? { ...w, ...updates } : w)),
        }));
      },

      deleteWAF: (id) => {
        set((state) => ({
          wafs: state.wafs.filter((w) => w.id !== id),
          edges: state.edges.map((e) =>
            e.wafId === id ? { ...e, wafId: undefined } : e
          ),
        }));
      },

      addRuleToWAF: (wafId, rule) => {
        set((state) => ({
          wafs: state.wafs.map((w) =>
            w.id === wafId
              ? { ...w, rules: [...w.rules, rule] }
              : w
          ),
        }));
      },

      updateRuleInWAF: (wafId, ruleName, updates) => {
        set((state) => ({
          wafs: state.wafs.map((w) =>
            w.id === wafId
              ? {
                  ...w,
                  rules: w.rules.map((r) =>
                    r.name === ruleName ? { ...r, ...updates } : r
                  ),
                }
              : w
          ),
        }));
      },

      removeRuleFromWAF: (wafId, ruleName) => {
        set((state) => ({
          wafs: state.wafs.map((w) =>
            w.id === wafId
              ? { ...w, rules: w.rules.filter((r) => r.name !== ruleName) }
              : w
          ),
        }));
      },

      reorderRules: (wafId, ruleNames) => {
        set((state) => ({
          wafs: state.wafs.map((w) => {
            if (w.id !== wafId) return w;
            const ruleMap = new Map(w.rules.map((r) => [r.name, r]));
            const reorderedRules = ruleNames
              .map((name, index) => {
                const rule = ruleMap.get(name);
                return rule ? { ...rule, priority: index + 1 } : null;
              })
              .filter(Boolean) as Rule[];
            return { ...w, rules: reorderedRules };
          }),
        }));
      },

      // Resource actions
      createIPSet: (ipSet) => {
        const id = uuidv4();
        const arn = `arn:aws:wafv2:us-east-1:123456789012:regional/ipset/${ipSet.name}/${id}`;
        set((state) => ({
          ipSets: [...state.ipSets, { ...ipSet, id, arn }],
        }));
        return id;
      },

      updateIPSet: (id, updates) => {
        set((state) => ({
          ipSets: state.ipSets.map((s) => (s.id === id ? { ...s, ...updates } : s)),
        }));
      },

      deleteIPSet: (id) => {
        set((state) => ({
          ipSets: state.ipSets.filter((s) => s.id !== id),
        }));
      },

      createRegexPatternSet: (regexSet) => {
        const id = uuidv4();
        const arn = `arn:aws:wafv2:us-east-1:123456789012:regional/regexpatternset/${regexSet.name}/${id}`;
        set((state) => ({
          regexPatternSets: [...state.regexPatternSets, { ...regexSet, id, arn }],
        }));
        return id;
      },

      updateRegexPatternSet: (id, updates) => {
        set((state) => ({
          regexPatternSets: state.regexPatternSets.map((s) =>
            s.id === id ? { ...s, ...updates } : s
          ),
        }));
      },

      deleteRegexPatternSet: (id) => {
        set((state) => ({
          regexPatternSets: state.regexPatternSets.filter((s) => s.id !== id),
        }));
      },

      // Simulation actions
      setCurrentRequest: (request) => set({ currentRequest: request }),
      setEvaluationResult: (result) => set({ evaluationResult: result }),
      setEvaluationResultWithWAF: (result, wafId) => set({ 
        evaluationResult: result, 
        lastEvaluatedWAFId: wafId 
      }),
      clearEvaluationResult: () => set({ 
        evaluationResult: null, 
        lastEvaluatedWAFId: null 
      }),

      addTrafficDot: (dot) => {
        set((state) => ({
          trafficDots: [...state.trafficDots, dot],
        }));
      },

      updateTrafficDot: (id, updates) => {
        set((state) => ({
          trafficDots: state.trafficDots.map((d) =>
            d.id === id ? { ...d, ...updates } : d
          ),
        }));
      },

      removeTrafficDot: (id) => {
        set((state) => ({
          trafficDots: state.trafficDots.filter((d) => d.id !== id),
        }));
      },

      clearTrafficDots: () => set({ trafficDots: [] }),

      setFloodSimulationResult: (result) => set({ floodSimulationResult: result }),

      setIsSimulating: (simulating) => set({ isSimulating: simulating }),

      // UI actions
      setAnimationSpeed: (speed) => set({ animationSpeed: speed }),
      setShowRuleBuilder: (show) => set({ showRuleBuilder: show }),
      setShowExportModal: (show) => set({ showExportModal: show }),
      setShowImportModal: (show) => set({ showImportModal: show }),
      setActiveTab: (tab) => set({ activeTab: tab }),

      // Import/Export
      exportState: () => {
        const state = get();
        return JSON.stringify({
          nodes: state.nodes,
          edges: state.edges,
          wafs: state.wafs,
          ipSets: state.ipSets,
          regexPatternSets: state.regexPatternSets,
        });
      },

      importState: (json) => {
        try {
          const data = JSON.parse(json);
          set({
            nodes: data.nodes || initialNodes,
            edges: data.edges || initialEdges,
            wafs: data.wafs || [],
            ipSets: data.ipSets || [],
            regexPatternSets: data.regexPatternSets || [],
          });
        } catch (e) {
          console.error("Failed to import state:", e);
        }
      },

      importWebACL: (json) => {
        const result = importWebACLJson(json);
        if (result.webACL) {
          set((state) => ({
            wafs: [...state.wafs, result.webACL!],
          }));
        }
        return { success: result.success, errors: result.errors, warnings: result.warnings };
      },

      resetState: () => {
        set({
          nodes: initialNodes,
          edges: initialEdges,
          wafs: [],
          ipSets: [],
          regexPatternSets: [],
          currentRequest: defaultRequest,
          evaluationResult: null,
          lastEvaluatedWAFId: null,
          trafficDots: [],
          floodSimulationResult: null,
          selectedNodeId: null,
          selectedEdgeId: null,
          selectedWAFId: null,
        });
      },
    }),
    {
      name: "wafsim-storage",
      partialize: (state) => ({
        nodes: state.nodes,
        edges: state.edges,
        wafs: state.wafs,
        ipSets: state.ipSets,
        regexPatternSets: state.regexPatternSets,
      }),
    }
  )
);

// Selector hooks for performance
export const useTopology = () =>
  useWAFSimStore((state) => ({
    nodes: state.nodes,
    edges: state.edges,
    wafs: state.wafs,
  }));

export const useSelection = () =>
  useWAFSimStore((state) => ({
    selectedNodeId: state.selectedNodeId,
    selectedEdgeId: state.selectedEdgeId,
    selectedWAFId: state.selectedWAFId,
  }));

export const useSimulation = () =>
  useWAFSimStore((state) => ({
    currentRequest: state.currentRequest,
    evaluationResult: state.evaluationResult,
    trafficDots: state.trafficDots,
    floodSimulationResult: state.floodSimulationResult,
    isSimulating: state.isSimulating,
  }));

export const useResources = () =>
  useWAFSimStore((state) => ({
    ipSets: state.ipSets,
    regexPatternSets: state.regexPatternSets,
  }));

export const useUI = () =>
  useWAFSimStore((state) => ({
    animationSpeed: state.animationSpeed,
    showRuleBuilder: state.showRuleBuilder,
    showExportModal: state.showExportModal,
    showImportModal: state.showImportModal,
    activeTab: state.activeTab,
  }));
