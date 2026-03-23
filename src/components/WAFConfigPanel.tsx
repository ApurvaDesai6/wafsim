"use client";

import React, { useState } from "react";
import { useWAFSimStore } from "@/store/wafsimStore";
import { WebACL, Rule, WAFAction, Statement, OverrideAction } from "@/lib/types";
import {
  Shield,
  Plus,
  Trash2,
  GripVertical,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Check,
  X,
  Edit,
  Settings,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { WCUBudgetMeter } from "./WCUBudgetMeter";
import { calculateRuleWCU } from "@/engines/wcuCalculator";

interface WAFConfigPanelProps {
  wafId: string;
  onEditRule?: (rule: Rule) => void;
  onCreateRule?: () => void;
}

export const WAFConfigPanel: React.FC<WAFConfigPanelProps> = ({ wafId, onEditRule, onCreateRule }) => {
  const { wafs, updateWAF, addRuleToWAF, removeRuleFromWAF, updateRuleInWAF, reorderRules } =
    useWAFSimStore();

  const waf = wafs.find((w) => w.id === wafId);
  const [isAddingRule, setIsAddingRule] = useState(false);
  const [newRuleName, setNewRuleName] = useState("");
  const [draggedRule, setDraggedRule] = useState<string | null>(null);

  if (!waf) {
    return (
      <div className="p-4 text-gray-400 text-center">
        <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
        <p>No WAF selected</p>
      </div>
    );
  }

  const handleAddRule = () => {
    if (!newRuleName.trim()) return;

    const newRule: Rule = {
      name: newRuleName,
      priority: waf.rules.length + 1,
      statement: {
        type: "ByteMatchStatement",
        searchString: "",
        fieldToMatch: { type: "URI_PATH" },
        textTransformations: [{ type: "NONE", priority: 1 }],
        positionalConstraint: "EXACTLY",
      } as Statement,
      action: "BLOCK",
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: newRuleName.replace(/[^a-zA-Z0-9]/g, ""),
      },
    };

    addRuleToWAF(wafId, newRule);
    setNewRuleName("");
    setIsAddingRule(false);
  };

  const handleDragStart = (ruleName: string) => {
    setDraggedRule(ruleName);
  };

  const handleDragOver = (e: React.DragEvent, targetRuleName: string) => {
    e.preventDefault();
    if (draggedRule === targetRuleName) return;

    const ruleNames = waf.rules.map((r) => r.name);
    const draggedIndex = ruleNames.indexOf(draggedRule!);
    const targetIndex = ruleNames.indexOf(targetRuleName);

    if (draggedIndex !== -1 && targetIndex !== -1) {
      const newOrder = [...ruleNames];
      newOrder.splice(draggedIndex, 1);
      newOrder.splice(targetIndex, 0, draggedRule!);
      reorderRules(wafId, newOrder);
    }
  };

  const handleDragEnd = () => {
    setDraggedRule(null);
  };

  const getRuleTypeLabel = (statement: Statement): string => {
    switch (statement.type) {
      case "ByteMatchStatement":
        return "Byte Match";
      case "GeoMatchStatement":
        return "Geo Match";
      case "IPSetReferenceStatement":
        return "IP Set";
      case "ManagedRuleGroupStatement":
        return "Managed Rule Group";
      case "RateBasedStatement":
        return "Rate Based";
      case "RegexMatchStatement":
        return "Regex Match";
      case "SqliMatchStatement":
        return "SQL Injection";
      case "XssMatchStatement":
        return "XSS";
      case "AndStatement":
        return "AND";
      case "OrStatement":
        return "OR";
      case "NotStatement":
        return "NOT";
      case "SizeConstraintStatement":
        return "Size Constraint";
      case "RegexPatternSetReferenceStatement":
        return "Regex Pattern Set";
      case "LabelMatchStatement":
        return "Label Match";
      case "RuleGroupReferenceStatement":
        return "Rule Group";
      default:
        return "Custom";
    }
  };

  const getActionColor = (action: WAFAction): string => {
    switch (action) {
      case "BLOCK":
        return "bg-red-500";
      case "ALLOW":
        return "bg-green-500";
      case "COUNT":
        return "bg-yellow-500";
      case "CAPTCHA":
        return "bg-purple-500";
      case "CHALLENGE":
        return "bg-blue-500";
      default:
        return "bg-gray-500";
    }
  };

  const handleEditClick = (rule: Rule) => {
    if (onEditRule) {
      onEditRule(rule);
    }
  };

  const handleCreateCustomRule = () => {
    if (onCreateRule) {
      onCreateRule();
    } else {
      setIsAddingRule(true);
    }
  };

  return (
    <div className="h-full flex flex-col bg-gray-900 text-white">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="w-5 h-5 text-red-400" />
          <h2 className="text-lg font-semibold">{waf.name}</h2>
        </div>

        {/* WAF Settings */}
        <div className="space-y-3">
          <div>
            <Label className="text-sm text-gray-400">Description</Label>
            <Input
              value={waf.description || ""}
              onChange={(e) =>
                updateWAF(wafId, { description: e.target.value })
              }
              placeholder="WebACL description..."
              className="bg-gray-800 border-gray-700"
            />
          </div>

          <div className="flex items-center justify-between">
            <Label className="text-sm text-gray-400">Default Action</Label>
            <Select
              value={waf.defaultAction}
              onValueChange={(value: WAFAction) =>
                updateWAF(wafId, { defaultAction: value })
              }
            >
              <SelectTrigger className="w-32 bg-gray-800 border-gray-700">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALLOW">Allow</SelectItem>
                <SelectItem value="BLOCK">Block</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center justify-between">
            <Label className="text-sm text-gray-400">Scope</Label>
            <Badge variant="outline">{waf.scope}</Badge>
          </div>
        </div>
      </div>

      {/* WCU Budget */}
      <div className="px-4 py-3 border-b border-gray-700">
        <WCUBudgetMeter rules={waf.rules} />
      </div>

      {/* Quick Start Presets */}
      {waf.rules.length === 0 && (
        <div className="px-4 py-3 border-b border-gray-700 space-y-2">
          <Label className="text-xs text-gray-400 uppercase tracking-wide">Quick Start</Label>
          <div className="grid grid-cols-1 gap-1.5">
            {[
              { name: "OWASP Core", desc: "SQLi + XSS + path traversal", rules: [
                { name: "BlockSQLi", statement: { type: "SqliMatchStatement" as const, fieldToMatch: { type: "ALL_QUERY_ARGUMENTS" as const }, textTransformations: [{ type: "URL_DECODE" as const, priority: 1 }, { type: "LOWERCASE" as const, priority: 2 }], sensitivityLevel: "HIGH" as const }, action: "BLOCK" as const },
                { name: "BlockXSS", statement: { type: "XssMatchStatement" as const, fieldToMatch: { type: "BODY" as const, oversizeHandling: "CONTINUE" as const }, textTransformations: [{ type: "HTML_ENTITY_DECODE" as const, priority: 1 }], sensitivityLevel: "HIGH" as const }, action: "BLOCK" as const },
                { name: "BlockPathTraversal", statement: { type: "ByteMatchStatement" as const, searchString: "../", fieldToMatch: { type: "URI_PATH" as const }, textTransformations: [{ type: "URL_DECODE" as const, priority: 1 }, { type: "NORMALIZE_PATH" as const, priority: 2 }], positionalConstraint: "CONTAINS" as const }, action: "BLOCK" as const },
              ]},
              { name: "Geo Block", desc: "Block high-risk countries", rules: [
                { name: "GeoBlock", statement: { type: "GeoMatchStatement" as const, countryCodes: ["RU", "CN", "KP", "IR"] }, action: "BLOCK" as const },
              ]},
              { name: "Rate Limit", desc: "100 req/5min per IP", rules: [
                { name: "RateLimit", statement: { type: "RateBasedStatement" as const, rateLimit: 100, evaluationWindowSec: 300, aggregateKeyType: "IP" as const }, action: "BLOCK" as const },
              ]},
            ].map((preset) => (
              <Button
                key={preset.name}
                size="sm"
                variant="outline"
                className="justify-start text-xs border-gray-700 hover:bg-gray-800 h-auto py-1.5"
                onClick={() => {
                  preset.rules.forEach((r, i) => {
                    addRuleToWAF(wafId, {
                      name: r.name,
                      priority: waf.rules.length + i + 1,
                      statement: r.statement as Statement,
                      action: r.action,
                      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: r.name },
                    });
                  });
                }}
              >
                <div className="text-left">
                  <div className="font-medium">{preset.name}</div>
                  <div className="text-gray-500 text-[10px]">{preset.desc}</div>
                </div>
              </Button>
            ))}
          </div>
        </div>
      )}

      {/* Rules List */}
      <div className="flex-1 overflow-y-auto">
        <div className="p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold">Rules ({waf.rules.length})</h3>
            <Button
              size="sm"
              onClick={handleCreateCustomRule}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Plus className="w-4 h-4 mr-1" />
              Add Rule
            </Button>
          </div>

          {/* Add Rule Form */}
          {isAddingRule && (
            <div className="mb-3 p-3 bg-gray-800 rounded-lg border border-gray-700">
              <div className="flex gap-2">
                <Input
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  placeholder="Rule name..."
                  className="bg-gray-700 border-gray-600"
                  onKeyDown={(e) => e.key === "Enter" && handleAddRule()}
                />
                <Button size="sm" onClick={handleAddRule} className="bg-green-600 hover:bg-green-700">
                  <Check className="w-4 h-4" />
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setIsAddingRule(false)}
                  className="border-gray-600"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}

          {/* Rules */}
          <Accordion type="multiple" className="space-y-2">
            {waf.rules
              .sort((a, b) => a.priority - b.priority)
              .map((rule) => {
                const wcuCost = calculateRuleWCU(rule);
                return (
                  <AccordionItem
                    key={rule.name}
                    value={rule.name}
                    className="bg-gray-800 rounded-lg border border-gray-700"
                    draggable
                    onDragStart={() => handleDragStart(rule.name)}
                    onDragOver={(e) => handleDragOver(e, rule.name)}
                    onDragEnd={handleDragEnd}
                  >
                    <AccordionTrigger className="px-3 py-2 hover:no-underline">
                      <div className="flex items-center gap-2 flex-1">
                        <GripVertical className="w-4 h-4 text-gray-500 cursor-grab" />
                        <Badge variant="outline" className="text-xs">
                          {rule.priority}
                        </Badge>
                        <span className="font-medium">{rule.name}</span>
                        <Badge className={`${getActionColor(rule.action)} text-white text-xs`}>
                          {rule.action}
                        </Badge>
                        <Badge variant="secondary" className="text-xs">
                          {getRuleTypeLabel(rule.statement)}
                        </Badge>
                        <span className="text-xs text-gray-400 ml-auto">
                          {wcuCost.total} WCU
                        </span>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="px-3 pb-3">
                      <div className="space-y-3">
                        {/* Action Selector */}
                        <div className="flex items-center justify-between">
                          <Label className="text-sm">Action</Label>
                          <Select
                            value={rule.action}
                            onValueChange={(value: WAFAction) =>
                              updateRuleInWAF(wafId, rule.name, { action: value })
                            }
                          >
                            <SelectTrigger className="w-32 bg-gray-700 border-gray-600">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="BLOCK">Block</SelectItem>
                              <SelectItem value="ALLOW">Allow</SelectItem>
                              <SelectItem value="COUNT">Count</SelectItem>
                              <SelectItem value="CAPTCHA">CAPTCHA</SelectItem>
                              <SelectItem value="CHALLENGE">Challenge</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        {/* Rule Type Info */}
                        <div className="p-2 bg-gray-700 rounded text-sm">
                          <div className="text-gray-400 mb-1">Statement Type</div>
                          <div className="font-mono text-xs max-h-24 overflow-y-auto">
                            {JSON.stringify(rule.statement, null, 2)}
                          </div>
                        </div>

                        {/* Rule Labels */}
                        <div className="flex items-center justify-between">
                          <Label className="text-sm">Custom Labels</Label>
                          <div className="flex items-center gap-2">
                            {(rule.ruleLabels || []).map((label) => (
                              <Badge key={label} variant="outline" className="text-xs">
                                {label}
                              </Badge>
                            ))}
                            {(!rule.ruleLabels || rule.ruleLabels.length === 0) && (
                              <span className="text-gray-500 text-sm">None</span>
                            )}
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-2 pt-2 border-t border-gray-700">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleEditClick(rule)}
                            className="border-blue-600 text-blue-400 hover:bg-blue-600 hover:text-white"
                          >
                            <Edit className="w-4 h-4 mr-1" />
                            Edit Statement
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => removeRuleFromWAF(wafId, rule.name)}
                          >
                            <Trash2 className="w-4 h-4 mr-1" />
                            Delete
                          </Button>
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                );
              })}
          </Accordion>

          {waf.rules.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
              <p>No rules configured</p>
              <p className="text-sm">Click "Add Rule" to create your first rule</p>
            </div>
          )}
        </div>
      </div>

      {/* Managed Rule Groups Quick Add */}
      <div className="p-4 border-t border-gray-700">
        <h4 className="text-sm font-semibold mb-2 text-gray-400">Quick Add Managed Rules</h4>
        <div className="flex flex-wrap gap-2">
          {[
            { name: "AWSManagedRulesCommonRuleSet", label: "Common" },
            { name: "AWSManagedRulesSQLiRuleSet", label: "SQLi" },
            { name: "AWSManagedRulesKnownBadInputsRuleSet", label: "Bad Inputs" },
            { name: "AWSManagedRulesLinuxRuleSet", label: "Linux" },
            { name: "AWSManagedRulesUnixRuleSet", label: "Unix" },
          ].map((ruleSet) => (
            <Button
              key={ruleSet.name}
              size="sm"
              variant="outline"
              onClick={() => {
                const newRule: Rule = {
                  name: ruleSet.label,
                  priority: waf.rules.length + 1,
                  statement: {
                    type: "ManagedRuleGroupStatement",
                    vendorName: "AWS",
                    name: ruleSet.name,
                  } as Statement,
                  action: "BLOCK",
                  overrideAction: "NONE" as OverrideAction,
                  visibilityConfig: {
                    sampledRequestsEnabled: true,
                    cloudWatchMetricsEnabled: true,
                    metricName: ruleSet.name.replace(/[^a-zA-Z0-9]/g, ""),
                  },
                };
                addRuleToWAF(wafId, newRule);
              }}
              className="text-xs border-gray-600"
            >
              + {ruleSet.label}
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default WAFConfigPanel;
