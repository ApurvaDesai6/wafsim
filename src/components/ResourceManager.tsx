"use client";

import React, { useState } from "react";
import { useWAFSimStore } from "@/store/wafsimStore";
import { IPSet, RegexPatternSet } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Plus,
  Trash2,
  Edit,
  Globe,
  Code,
  Check,
  X,
  AlertTriangle,
} from "lucide-react";

interface ResourceManagerProps {
  onSelectIPSet?: (ipSet: IPSet) => void;
  onSelectRegexSet?: (regexSet: RegexPatternSet) => void;
}

export const ResourceManager: React.FC<ResourceManagerProps> = ({
  onSelectIPSet,
  onSelectRegexSet,
}) => {
  const {
    ipSets,
    regexPatternSets,
    createIPSet,
    updateIPSet,
    deleteIPSet,
    createRegexPatternSet,
    updateRegexPatternSet,
    deleteRegexPatternSet,
  } = useWAFSimStore();

  const [showIPSetDialog, setShowIPSetDialog] = useState(false);
  const [showRegexDialog, setShowRegexDialog] = useState(false);
  const [editingIPSet, setEditingIPSet] = useState<IPSet | null>(null);
  const [editingRegexSet, setEditingRegexSet] = useState<RegexPatternSet | null>(null);

  // IP Set form state
  const [ipSetName, setIPSetName] = useState("");
  const [ipSetDescription, setIPSetDescription] = useState("");
  const [ipSetScope, setIPSetScope] = useState<"CLOUDFRONT" | "REGIONAL">("REGIONAL");
  const [ipSetVersion, setIPSetVersion] = useState<"IPV4" | "IPV6">("IPV4");
  const [ipSetAddresses, setIPSetAddresses] = useState("");

  // Regex Pattern Set form state
  const [regexName, setRegexName] = useState("");
  const [regexDescription, setRegexDescription] = useState("");
  const [regexScope, setRegexScope] = useState<"CLOUDFRONT" | "REGIONAL">("REGIONAL");
  const [regexPatterns, setRegexPatterns] = useState("");

  const resetIPSetForm = () => {
    setIPSetName("");
    setIPSetDescription("");
    setIPSetScope("REGIONAL");
    setIPSetVersion("IPV4");
    setIPSetAddresses("");
    setEditingIPSet(null);
  };

  const resetRegexForm = () => {
    setRegexName("");
    setRegexDescription("");
    setRegexScope("REGIONAL");
    setRegexPatterns("");
    setEditingRegexSet(null);
  };

  const handleSaveIPSet = () => {
    const addresses = ipSetAddresses
      .split(/[\n,]+/)
      .map((a) => a.trim())
      .filter(Boolean);

    if (!ipSetName.trim()) {
      alert("Name is required");
      return;
    }

    if (editingIPSet) {
      updateIPSet(editingIPSet.id, {
        name: ipSetName,
        description: ipSetDescription,
        scope: ipSetScope,
        ipAddressVersion: ipSetVersion,
        addresses,
      });
    } else {
      createIPSet({
        name: ipSetName,
        description: ipSetDescription,
        scope: ipSetScope,
        ipAddressVersion: ipSetVersion,
        addresses,
      });
    }

    resetIPSetForm();
    setShowIPSetDialog(false);
  };

  const handleSaveRegexSet = () => {
    const patterns = regexPatterns
      .split("\n")
      .map((p) => p.trim())
      .filter(Boolean);

    if (!regexName.trim()) {
      alert("Name is required");
      return;
    }

    if (editingRegexSet) {
      updateRegexPatternSet(editingRegexSet.id, {
        name: regexName,
        description: regexDescription,
        scope: regexScope,
        regularExpressionList: patterns,
      });
    } else {
      createRegexPatternSet({
        name: regexName,
        description: regexDescription,
        scope: regexScope,
        regularExpressionList: patterns,
      });
    }

    resetRegexForm();
    setShowRegexDialog(false);
  };

  const handleEditIPSet = (ipSet: IPSet) => {
    setEditingIPSet(ipSet);
    setIPSetName(ipSet.name);
    setIPSetDescription(ipSet.description || "");
    setIPSetScope(ipSet.scope);
    setIPSetVersion(ipSet.ipAddressVersion);
    setIPSetAddresses(ipSet.addresses.join("\n"));
    setShowIPSetDialog(true);
  };

  const handleEditRegexSet = (regexSet: RegexPatternSet) => {
    setEditingRegexSet(regexSet);
    setRegexName(regexSet.name);
    setRegexDescription(regexSet.description || "");
    setRegexScope(regexSet.scope);
    setRegexPatterns(regexSet.regularExpressionList.join("\n"));
    setShowRegexDialog(true);
  };

  return (
    <div className="h-full flex flex-col bg-gray-900 text-white">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <h2 className="text-lg font-semibold">Resources</h2>
        <p className="text-sm text-gray-400">
          IP Sets and Regex Pattern Sets for WAF rules
        </p>
      </div>

      <Tabs defaultValue="ipsets" className="flex-1 flex flex-col">
        <TabsList className="mx-4 mt-2 bg-gray-800">
          <TabsTrigger value="ipsets" className="data-[state=active]:bg-gray-700">
            <Globe className="w-4 h-4 mr-1" />
            IP Sets ({ipSets.length})
          </TabsTrigger>
          <TabsTrigger value="regex" className="data-[state=active]:bg-gray-700">
            <Code className="w-4 h-4 mr-1" />
            Regex Patterns ({regexPatternSets.length})
          </TabsTrigger>
        </TabsList>

        {/* IP Sets Tab */}
        <TabsContent value="ipsets" className="flex-1 overflow-y-auto p-4">
          <div className="flex justify-between items-center mb-4">
            <h3 className="font-semibold">IP Sets</h3>
            <Button
              size="sm"
              onClick={() => {
                resetIPSetForm();
                setShowIPSetDialog(true);
              }}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Plus className="w-4 h-4 mr-1" />
              Create IP Set
            </Button>
          </div>

          <div className="space-y-2">
            {ipSets.map((ipSet) => (
              <Card
                key={ipSet.id}
                className="bg-gray-800 border-gray-700 cursor-pointer hover:border-gray-600"
                onClick={() => onSelectIPSet?.(ipSet)}
              >
                <CardHeader className="p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-sm">{ipSet.name}</CardTitle>
                      <div className="flex gap-2 mt-1">
                        <Badge variant="outline">{ipSet.scope}</Badge>
                        <Badge variant="secondary">{ipSet.ipAddressVersion}</Badge>
                        <Badge variant="outline">{ipSet.addresses.length} IPs</Badge>
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleEditIPSet(ipSet);
                        }}
                      >
                        <Edit className="w-4 h-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-red-400"
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteIPSet(ipSet.id);
                        }}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                {ipSet.description && (
                  <CardContent className="px-3 pb-3 pt-0">
                    <p className="text-xs text-gray-400">{ipSet.description}</p>
                    <div className="mt-2 text-xs font-mono bg-gray-700 p-2 rounded max-h-20 overflow-y-auto">
                      {ipSet.addresses.slice(0, 5).join(", ")}
                      {ipSet.addresses.length > 5 && `... +${ipSet.addresses.length - 5} more`}
                    </div>
                  </CardContent>
                )}
              </Card>
            ))}

            {ipSets.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Globe className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No IP Sets configured</p>
                <p className="text-sm">Create an IP Set to use in WAF rules</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* Regex Pattern Sets Tab */}
        <TabsContent value="regex" className="flex-1 overflow-y-auto p-4">
          <div className="flex justify-between items-center mb-4">
            <h3 className="font-semibold">Regex Pattern Sets</h3>
            <Button
              size="sm"
              onClick={() => {
                resetRegexForm();
                setShowRegexDialog(true);
              }}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Plus className="w-4 h-4 mr-1" />
              Create Pattern Set
            </Button>
          </div>

          <div className="space-y-2">
            {regexPatternSets.map((regexSet) => (
              <Card
                key={regexSet.id}
                className="bg-gray-800 border-gray-700 cursor-pointer hover:border-gray-600"
                onClick={() => onSelectRegexSet?.(regexSet)}
              >
                <CardHeader className="p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-sm">{regexSet.name}</CardTitle>
                      <div className="flex gap-2 mt-1">
                        <Badge variant="outline">{regexSet.scope}</Badge>
                        <Badge variant="secondary">{regexSet.regularExpressionList.length} patterns</Badge>
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleEditRegexSet(regexSet);
                        }}
                      >
                        <Edit className="w-4 h-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-red-400"
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteRegexPatternSet(regexSet.id);
                        }}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                {regexSet.description && (
                  <CardContent className="px-3 pb-3 pt-0">
                    <p className="text-xs text-gray-400">{regexSet.description}</p>
                    <div className="mt-2 text-xs font-mono bg-gray-700 p-2 rounded max-h-20 overflow-y-auto">
                      {regexSet.regularExpressionList.slice(0, 3).map((p, i) => (
                        <div key={i}>{p}</div>
                      ))}
                      {regexSet.regularExpressionList.length > 3 && (
                        <div className="text-gray-500">
                          ... +{regexSet.regularExpressionList.length - 3} more
                        </div>
                      )}
                    </div>
                  </CardContent>
                )}
              </Card>
            ))}

            {regexPatternSets.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Code className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No Regex Pattern Sets configured</p>
                <p className="text-sm">Create a Pattern Set to use in WAF rules</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* IP Set Dialog */}
      <Dialog open={showIPSetDialog} onOpenChange={setShowIPSetDialog}>
        <DialogContent className="bg-gray-900 border-gray-700">
          <DialogHeader>
            <DialogTitle>
              {editingIPSet ? "Edit IP Set" : "Create IP Set"}
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4 mt-4">
            <div>
              <Label className="text-sm text-gray-400">Name</Label>
              <Input
                value={ipSetName}
                onChange={(e) => setIPSetName(e.target.value)}
                placeholder="BlockedIPs"
                className="bg-gray-800 border-gray-700"
              />
            </div>

            <div>
              <Label className="text-sm text-gray-400">Description</Label>
              <Input
                value={ipSetDescription}
                onChange={(e) => setIPSetDescription(e.target.value)}
                placeholder="Known malicious IPs"
                className="bg-gray-800 border-gray-700"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-sm text-gray-400">Scope</Label>
                <Select value={ipSetScope} onValueChange={(v) => setIPSetScope(v as "CLOUDFRONT" | "REGIONAL")}>
                  <SelectTrigger className="bg-gray-800 border-gray-700">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="REGIONAL">Regional</SelectItem>
                    <SelectItem value="CLOUDFRONT">CloudFront</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-sm text-gray-400">IP Version</Label>
                <Select value={ipSetVersion} onValueChange={(v) => setIPSetVersion(v as "IPV4" | "IPV6")}>
                  <SelectTrigger className="bg-gray-800 border-gray-700">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="IPV4">IPv4</SelectItem>
                    <SelectItem value="IPV6">IPv6</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label className="text-sm text-gray-400">IP Addresses (CIDR notation, one per line or comma-separated)</Label>
              <Textarea
                value={ipSetAddresses}
                onChange={(e) => setIPSetAddresses(e.target.value)}
                placeholder="192.168.1.0/24&#10;10.0.0.0/8&#10;203.0.113.0/24"
                className="bg-gray-800 border-gray-700 font-mono text-sm min-h-[100px]"
              />
            </div>

            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={() => setShowIPSetDialog(false)}>
                Cancel
              </Button>
              <Button onClick={handleSaveIPSet} className="bg-green-600 hover:bg-green-700">
                <Check className="w-4 h-4 mr-1" />
                {editingIPSet ? "Update" : "Create"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Regex Pattern Set Dialog */}
      <Dialog open={showRegexDialog} onOpenChange={setShowRegexDialog}>
        <DialogContent className="bg-gray-900 border-gray-700">
          <DialogHeader>
            <DialogTitle>
              {editingRegexSet ? "Edit Regex Pattern Set" : "Create Regex Pattern Set"}
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4 mt-4">
            <div>
              <Label className="text-sm text-gray-400">Name</Label>
              <Input
                value={regexName}
                onChange={(e) => setRegexName(e.target.value)}
                placeholder="MaliciousPatterns"
                className="bg-gray-800 border-gray-700"
              />
            </div>

            <div>
              <Label className="text-sm text-gray-400">Description</Label>
              <Input
                value={regexDescription}
                onChange={(e) => setRegexDescription(e.target.value)}
                placeholder="Patterns for known attacks"
                className="bg-gray-800 border-gray-700"
              />
            </div>

            <div>
              <Label className="text-sm text-gray-400">Scope</Label>
              <Select value={regexScope} onValueChange={(v) => setRegexScope(v as "CLOUDFRONT" | "REGIONAL")}>
                <SelectTrigger className="bg-gray-800 border-gray-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="REGIONAL">Regional</SelectItem>
                  <SelectItem value="CLOUDFRONT">CloudFront</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-sm text-gray-400">Regex Patterns (one per line)</Label>
              <Textarea
                value={regexPatterns}
                onChange={(e) => setRegexPatterns(e.target.value)}
                placeholder=".*\.sql$&#10;.*\.bak$&#10;.*\.\./.*"
                className="bg-gray-800 border-gray-700 font-mono text-sm min-h-[100px]"
              />
            </div>

            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={() => setShowRegexDialog(false)}>
                Cancel
              </Button>
              <Button onClick={handleSaveRegexSet} className="bg-green-600 hover:bg-green-700">
                <Check className="w-4 h-4 mr-1" />
                {editingRegexSet ? "Update" : "Create"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default ResourceManager;
