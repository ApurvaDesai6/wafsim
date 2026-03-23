"use client";

import React, { useCallback, useMemo, useState, useRef } from "react";
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Connection,
  MarkerType,
  NodeTypes,
  Handle,
  Position,
  ReactFlowProvider,
  useReactFlow,
} from "reactflow";
import "reactflow/dist/style.css";
import { useWAFSimStore } from "@/store/wafsimStore";
import { AWSResourceNode as AWSNodeType, TopologyEdge } from "@/lib/types";
import { Shield, Globe, Cloud, Server, Database, Network, Lock, Cpu, Trash2, Settings, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";

// AWS Resource Node Component
const AWSResourceNodeComponent: React.FC<{
  data: AWSNodeType & { 
    selected?: boolean; 
    hasWAF?: boolean;
    onDoubleClick?: () => void;
    evaluationStatus?: 'blocked' | 'allowed' | 'counted' | null;
  };
}> = ({ data }) => {
  const isSelected = data.selected;
  const hasWAF = data.hasWAF;
  const evalStatus = data.evaluationStatus;

  const getIcon = () => {
    switch (data.type) {
      case "INTERNET":
        return <Globe className="w-5 h-5" />;
      case "CLOUDFRONT":
        return <Cloud className="w-5 h-5" />;
      case "ALB":
        return <Network className="w-5 h-5" />;
      case "API_GATEWAY":
        return <Server className="w-5 h-5" />;
      case "APPSYNC":
        return <Cpu className="w-5 h-5" />;
      case "COGNITO":
        return <Lock className="w-5 h-5" />;
      case "EC2":
      case "ECS":
        return <Server className="w-5 h-5" />;
      case "LAMBDA":
        return <Cpu className="w-5 h-5" />;
      case "S3":
        return <Database className="w-5 h-5" />;
      case "WAF":
        return <Shield className="w-5 h-5" />;
      default:
        return <Server className="w-5 h-5" />;
    }
  };

  const getNodeColor = () => {
    switch (data.type) {
      case "INTERNET":
        return "bg-blue-500";
      case "CLOUDFRONT":
        return "bg-orange-500";
      case "ALB":
        return "bg-green-500";
      case "API_GATEWAY":
        return "bg-purple-500";
      case "APPSYNC":
        return "bg-pink-500";
      case "COGNITO":
        return "bg-yellow-600";
      case "WAF":
        return "bg-red-500";
      default:
        return "bg-gray-500";
    }
  };

  const getStatusBorder = () => {
    if (evalStatus === 'blocked') return "border-2 border-red-500 shadow-lg shadow-red-500/50";
    if (evalStatus === 'allowed') return "border-2 border-green-500 shadow-lg shadow-green-500/50";
    if (evalStatus === 'counted') return "border-2 border-yellow-500 shadow-lg shadow-yellow-500/50";
    return "";
  };

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            className={`
              px-3 py-2 rounded-lg shadow-lg min-w-[120px] relative cursor-pointer
              transition-all duration-200 hover:scale-105
              ${isSelected ? "ring-2 ring-yellow-400 ring-offset-2 ring-offset-gray-900" : ""}
              ${getStatusBorder()}
              ${data.wafAttachable ? "border-2 border-dashed border-green-400" : "border border-gray-600"}
              bg-gray-800 text-white
            `}
            onDoubleClick={data.onDoubleClick}
          >
            {data.type !== "INTERNET" && (
              <Handle
                type="target"
                position={Position.Left}
                className="w-3 h-3 !bg-gray-400 hover:!bg-blue-400 transition-colors"
              />
            )}

            <div className="flex items-center gap-2">
              <div className={`${getNodeColor()} p-1.5 rounded`}>{getIcon()}</div>
              <div>
                <div className="font-semibold text-xs">{data.label}</div>
                {data.wafAttachable && (
                  <div className="text-[10px] text-green-400 flex items-center gap-1">
                    <Shield className="w-2.5 h-2.5" />
                    WAF Ready
                  </div>
                )}
              </div>
            </div>

            {hasWAF && (
              <div className="absolute -top-2 -right-2">
                <Shield className="w-5 h-5 text-red-500 fill-red-500" />
              </div>
            )}

            {/* Evaluation status indicator */}
            {evalStatus && (
              <div className={`absolute -bottom-2 left-1/2 transform -translate-x-1/2 px-2 py-0.5 rounded text-[10px] font-bold
                ${evalStatus === 'blocked' ? 'bg-red-500 text-white' : ''}
                ${evalStatus === 'allowed' ? 'bg-green-500 text-white' : ''}
                ${evalStatus === 'counted' ? 'bg-yellow-500 text-black' : ''}
              `}>
                {evalStatus.toUpperCase()}
              </div>
            )}

            {data.type !== "ECS" && data.type !== "EC2" && data.type !== "LAMBDA" && data.type !== "S3" && (
              <Handle
                type="source"
                position={Position.Right}
                className="w-3 h-3 !bg-gray-400 hover:!bg-blue-400 transition-colors"
              />
            )}
          </div>
        </TooltipTrigger>
        <TooltipContent side="top" className="bg-gray-800 border-gray-700">
          <div className="text-xs">
            <div className="font-semibold">{data.label}</div>
            <div className="text-gray-400">Type: {data.type}</div>
            {data.wafAttachable && (
              <div className="text-green-400">WAF can be attached</div>
            )}
            <div className="mt-1 text-blue-400">Double-click for options</div>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
};

// WAF Node Component
const WAFNodeComponent: React.FC<{ 
  data: { 
    wafName: string; 
    selected?: boolean;
    rulesCount?: number;
    onDoubleClick?: () => void;
  } 
}> = ({ data }) => {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            className={`
              px-3 py-2 rounded-lg shadow-lg cursor-pointer
              transition-all duration-200 hover:scale-105
              ${data.selected ? "ring-2 ring-yellow-400 ring-offset-2 ring-offset-gray-900" : ""}
              bg-red-900 text-white border-2 border-red-500
            `}
            onDoubleClick={data.onDoubleClick}
          >
            <Handle type="target" position={Position.Left} className="w-3 h-3 !bg-red-400" />

            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-red-300" />
              <div>
                <div className="text-sm font-semibold">{data.wafName}</div>
                <div className="text-[10px] text-red-300">
                  {data.rulesCount || 0} rules
                </div>
              </div>
            </div>

            <Handle type="source" position={Position.Right} className="w-3 h-3 !bg-red-400" />
          </div>
        </TooltipTrigger>
        <TooltipContent side="top" className="bg-gray-800 border-gray-700">
          <div className="text-xs">
            <div className="font-semibold">{data.wafName}</div>
            <div className="text-gray-400">Rules: {data.rulesCount || 0}</div>
            <div className="mt-1 text-blue-400">Double-click to configure</div>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
};

// Node types definition
const nodeTypes: NodeTypes = {
  awsResource: AWSResourceNodeComponent,
  waf: WAFNodeComponent,
};

// AWS resource palette items - including WAF
const AWS_RESOURCES = [
  { type: "CLOUDFRONT", label: "CloudFront", icon: <Cloud className="w-4 h-4" />, wafAttachable: true, scope: "CLOUDFRONT" },
  { type: "ALB", label: "ALB", icon: <Network className="w-4 h-4" />, wafAttachable: true, scope: "REGIONAL" },
  { type: "API_GATEWAY", label: "API Gateway", icon: <Server className="w-4 h-4" />, wafAttachable: true, scope: "REGIONAL" },
  { type: "APPSYNC", label: "AppSync", icon: <Cpu className="w-4 h-4" />, wafAttachable: true, scope: "REGIONAL" },
  { type: "COGNITO", label: "Cognito", icon: <Lock className="w-4 h-4" />, wafAttachable: true, scope: "REGIONAL" },
  { type: "EC2", label: "EC2", icon: <Server className="w-4 h-4" />, wafAttachable: false },
  { type: "ECS", label: "ECS", icon: <Server className="w-4 h-4" />, wafAttachable: false },
  { type: "LAMBDA", label: "Lambda", icon: <Cpu className="w-4 h-4" />, wafAttachable: false },
  { type: "S3", label: "S3", icon: <Database className="w-4 h-4" />, wafAttachable: false },
] as const;

// WAF item for palette
const WAF_RESOURCE = { type: "WAF", label: "WAF WebACL", icon: <Shield className="w-4 h-4" /> };

interface TopologyCanvasInnerProps {
  onEdgeClick?: (edgeId: string) => void;
  onNodeClick?: (nodeId: string) => void;
  onWAFClick?: (wafId: string) => void;
  evaluationStatus?: 'blocked' | 'allowed' | 'counted' | null;
  evaluatedWAFId?: string | null;
}

const TopologyCanvasInner: React.FC<TopologyCanvasInnerProps> = ({
  onEdgeClick,
  onNodeClick,
  onWAFClick,
  evaluationStatus,
  evaluatedWAFId,
}) => {
  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const { screenToFlowPosition } = useReactFlow();

  const {
    nodes: storeNodes,
    edges: storeEdges,
    wafs,
    selectedNodeId,
    selectedEdgeId,
    selectNode,
    selectEdge,
    addNode,
    addEdge,
    removeNode,
    setNodes,
    attachWAFToEdge,
    createWAF,
  } = useWAFSimStore();

  const [nodeConfigOpen, setNodeConfigOpen] = useState(false);
  const [selectedNodeForConfig, setSelectedNodeForConfig] = useState<string | null>(null);

  // Convert store nodes to React Flow nodes
  const reactFlowNodes: Node[] = useMemo(() => {
    return storeNodes.map((node) => {
      const isWAFNode = node.type === "WAF";
      const waf = isWAFNode ? wafs.find(w => w.id === node.wafId) : null;
      
      // Determine if this node should show evaluation status
      // Show status on WAF nodes that were just evaluated
      const showEvalStatus = isWAFNode && node.wafId === evaluatedWAFId ? evaluationStatus : null;
      
      return {
        id: node.id,
        type: isWAFNode ? "waf" : "awsResource",
        position: node.position,
        data: {
          ...node,
          selected: selectedNodeId === node.id,
          hasWAF: storeEdges.some((e) => e.source === node.id && e.wafId),
          wafName: waf?.name || "WAF",
          rulesCount: waf?.rules?.length || 0,
          evaluationStatus: showEvalStatus,
          onDoubleClick: () => {
            setSelectedNodeForConfig(node.id);
            setNodeConfigOpen(true);
          },
        },
      };
    });
  }, [storeNodes, selectedNodeId, storeEdges, wafs, evaluationStatus, evaluatedWAFId]);

  // Convert store edges to React Flow edges
  const reactFlowEdges: Edge[] = useMemo(() => {
    return storeEdges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: "smoothstep",
      animated: false,
      style: {
        strokeWidth: selectedEdgeId === edge.id ? 3 : 2,
        stroke: edge.wafId ? "#ef4444" : selectedEdgeId === edge.id ? "#fbbf24" : "#6b7280",
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: edge.wafId ? "#ef4444" : "#6b7280" },
    }));
  }, [storeEdges, selectedEdgeId]);

  const [nodes, setLocalNodes, onNodesChange] = useNodesState(reactFlowNodes);
  const [edges, setLocalEdges, onEdgesChange] = useEdgesState(reactFlowEdges);

  // Sync local nodes with store nodes when they change
  React.useEffect(() => {
    setLocalNodes(reactFlowNodes);
  }, [reactFlowNodes, setLocalNodes]);

  React.useEffect(() => {
    setLocalEdges(reactFlowEdges);
  }, [reactFlowEdges, setLocalEdges]);

  // Sync node positions back to store when dragged
  const onNodeDragStop = useCallback(
    (event: React.MouseEvent, node: Node) => {
      setNodes(storeNodes.map((n) => (n.id === node.id ? { ...n, position: node.position } : n)));
    },
    [storeNodes, setNodes]
  );

  // Handle new connections
  const onConnect = useCallback(
    (params: Connection) => {
      addEdge({
        source: params.source!,
        target: params.target!,
      });
      toast.success("Connection created!");
    },
    [addEdge]
  );

  // Handle node click
  const handleNodeClick = useCallback(
    (event: React.MouseEvent, node: Node) => {
      selectNode(node.id);
      onNodeClick?.(node.id);
    },
    [selectNode, onNodeClick]
  );

  // Handle edge click
  const handleEdgeClick = useCallback(
    (event: React.MouseEvent, edge: Edge) => {
      selectEdge(edge.id);
      onEdgeClick?.(edge.id);
    },
    [selectEdge, onEdgeClick]
  );

  // Handle drop from palette
  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();

      const resourceType = event.dataTransfer.getData("application/reactflow");
      if (!resourceType) return;

      // Get the position relative to the React Flow canvas
      const position = screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      if (resourceType === "WAF") {
        // Create a WAF node
        const wafId = createWAF({
          name: "New WebACL",
          description: "Click to configure",
          scope: "REGIONAL",
          defaultAction: "ALLOW",
          rules: [],
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: "NewWebACL",
          },
          capacity: 0,
        });

        // Add WAF node to canvas
        addNode({
          type: "WAF",
          label: "WAF WebACL",
          icon: "🛡️",
          wafAttachable: false,
          wafId,
          position,
        });

        toast.success("WAF WebACL created! Connect it to your resources.");
      } else {
        const resource = AWS_RESOURCES.find((r) => r.type === resourceType);
        if (!resource) return;

        addNode({
          type: resource.type as AWSNodeType["type"],
          label: resource.label,
          icon: resource.type,
          wafAttachable: resource.wafAttachable,
          scope: 'scope' in resource ? resource.scope as "CLOUDFRONT" | "REGIONAL" : undefined,
          position,
        });

        toast.success(`${resource.label} added to canvas`);
      }
    },
    [addNode, createWAF, screenToFlowPosition]
  );

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
  }, []);

  // Delete node
  const handleDeleteNode = useCallback(() => {
    if (selectedNodeForConfig) {
      removeNode(selectedNodeForConfig);
      setNodeConfigOpen(false);
      setSelectedNodeForConfig(null);
      toast.success("Node deleted");
    }
  }, [selectedNodeForConfig, removeNode]);

  return (
    <div ref={reactFlowWrapper} className="h-full w-full relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={handleNodeClick}
        onEdgeClick={handleEdgeClick}
        onNodeDragStop={onNodeDragStop}
        onDrop={onDrop}
        onDragOver={onDragOver}
        nodeTypes={nodeTypes}
        fitView
        snapToGrid
        snapGrid={[20, 20]}
        deleteKeyCode="Delete"
        className="bg-gray-950"
      >
        <Background color="#374151" gap={20} />
        <Controls className="!bg-gray-800 !text-white rounded !border-gray-700" />
        <MiniMap
          className="!bg-gray-800 rounded !border-gray-700"
          nodeColor={(node) => {
            switch (node.data?.type) {
              case "INTERNET":
                return "#3b82f6";
              case "CLOUDFRONT":
                return "#f97316";
              case "ALB":
                return "#22c55e";
              case "WAF":
                return "#dc2626";
              default:
                return "#6b7280";
            }
          }}
        />
      </ReactFlow>

      {/* Resource Palette */}
      <div className="absolute top-4 left-4 bg-gray-900/95 rounded-lg shadow-xl p-3 border border-gray-700 backdrop-blur-sm max-w-[160px]">
        <div className="text-xs font-semibold text-gray-400 mb-2 flex items-center gap-1">
          <Plus className="w-3 h-3" />
          Drag to Canvas
        </div>
        
        {/* WAF Section */}
        <div className="mb-2 pb-2 border-b border-gray-700">
          <div className="text-[10px] text-gray-500 uppercase mb-1">Security</div>
          <div
            className="flex items-center gap-2 px-2 py-2 rounded cursor-grab hover:bg-red-900/30 text-sm text-white border border-red-500/30 bg-red-900/20 active:cursor-grabbing transition-colors"
            draggable
            onDragStart={(e) => {
              e.dataTransfer.setData("application/reactflow", "WAF");
              e.dataTransfer.effectAllowed = "move";
            }}
          >
            <Shield className="w-4 h-4 text-red-400" />
            <span>WAF WebACL</span>
          </div>
        </div>

        {/* AWS Resources */}
        <div className="text-[10px] text-gray-500 uppercase mb-1">Resources</div>
        <div className="space-y-0.5 max-h-[300px] overflow-y-auto">
          {AWS_RESOURCES.map((resource) => (
            <TooltipProvider key={resource.type}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div
                    className={`
                      flex items-center gap-2 px-2 py-1.5 rounded cursor-grab 
                      hover:bg-gray-800 text-xs text-white active:cursor-grabbing transition-colors
                      ${resource.wafAttachable ? "border-l-2 border-green-500" : ""}
                    `}
                    draggable
                    onDragStart={(e) => {
                      e.dataTransfer.setData("application/reactflow", resource.type);
                      e.dataTransfer.effectAllowed = "move";
                    }}
                  >
                    {resource.icon}
                    <span>{resource.label}</span>
                    {resource.wafAttachable && (
                      <Shield className="w-3 h-3 text-green-400 ml-auto" />
                    )}
                  </div>
                </TooltipTrigger>
                <TooltipContent side="right" className="bg-gray-800 border-gray-700">
                  <div className="text-xs">
                    {resource.wafAttachable 
                      ? "WAF can protect this resource" 
                      : "WAF cannot be attached"}
                  </div>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          ))}
        </div>
      </div>

      {/* Instructions Panel */}
      <div className="absolute bottom-4 left-4 bg-gray-900/95 rounded-lg shadow-xl p-3 border border-gray-700 backdrop-blur-sm text-xs max-w-[200px]">
        <div className="font-semibold text-gray-300 mb-1">Quick Tips</div>
        <ul className="text-gray-400 space-y-0.5">
          <li>• Drag resources onto canvas</li>
          <li>• Connect nodes by dragging handles</li>
          <li>• Double-click nodes for options</li>
          <li>• Click edges to attach WAF</li>
          <li>• Press Delete to remove selection</li>
        </ul>
      </div>

      {/* Node Configuration Dialog */}
      <Dialog open={nodeConfigOpen} onOpenChange={setNodeConfigOpen}>
        <DialogContent className="bg-gray-900 border-gray-700">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Settings className="w-5 h-5" />
              Node Options
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 mt-4">
            <p className="text-sm text-gray-400">
              Configure this node or perform actions.
            </p>
            <div className="flex gap-2">
              <Button
                variant="destructive"
                onClick={handleDeleteNode}
                className="flex-1"
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Delete Node
              </Button>
              <Button
                variant="outline"
                onClick={() => setNodeConfigOpen(false)}
                className="flex-1 border-gray-700"
              >
                Cancel
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

// Main export with ReactFlowProvider wrapper
interface TopologyCanvasProps {
  onEdgeClick?: (edgeId: string) => void;
  onNodeClick?: (nodeId: string) => void;
  onWAFClick?: (wafId: string) => void;
  evaluationStatus?: 'blocked' | 'allowed' | 'counted' | null;
  evaluatedWAFId?: string | null;
}

export const TopologyCanvas: React.FC<TopologyCanvasProps> = (props) => {
  return (
    <ReactFlowProvider>
      <TopologyCanvasInner {...props} />
    </ReactFlowProvider>
  );
};

export default TopologyCanvas;
