"use client";

import React, { useState } from "react";
import {
  Rule,
  Statement,
  WAFAction,
  TextTransformation,
  FieldToMatch,
  PositionalConstraint,
  TextTransformationType,
} from "@/lib/types";
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
  Plus,
  Trash2,
  ChevronDown,
  ChevronRight,
  GripVertical,
  Save,
  X,
  AlertCircle,
  Info,
} from "lucide-react";
import { getAvailableTransformations, getTransformationDescription } from "@/engines/textTransformations";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface RuleBuilderProps {
  rule?: Rule;
  onSave: (rule: Rule) => void;
  onCancel: () => void;
}

const STATEMENT_TYPES = [
  { value: "ByteMatchStatement", label: "Byte Match", description: "Match strings in request components" },
  { value: "GeoMatchStatement", label: "Geo Match", description: "Match by country/region" },
  { value: "IPSetReferenceStatement", label: "IP Set", description: "Match IPs from a set" },
  { value: "LabelMatchStatement", label: "Label Match", description: "Match labels from other rules" },
  { value: "RateBasedStatement", label: "Rate Based", description: "Rate limiting rules" },
  { value: "RegexMatchStatement", label: "Regex Match", description: "Match regex patterns" },
  { value: "SizeConstraintStatement", label: "Size Constraint", description: "Check request component size" },
  { value: "SqliMatchStatement", label: "SQL Injection", description: "Detect SQL injection attacks" },
  { value: "XssMatchStatement", label: "XSS Match", description: "Detect cross-site scripting" },
  { value: "AndStatement", label: "AND", description: "All conditions must match" },
  { value: "OrStatement", label: "OR", description: "Any condition must match" },
  { value: "NotStatement", label: "NOT", description: "Negate a condition" },
] as const;

const FIELD_TO_MATCH_OPTIONS = [
  { value: "URI_PATH", label: "URI Path" },
  { value: "QUERY_STRING", label: "Query String" },
  { value: "BODY", label: "Body" },
  { value: "METHOD", label: "HTTP Method" },
  { value: "SINGLE_HEADER", label: "Single Header" },
  { value: "ALL_HEADERS", label: "All Headers" },
  { value: "SINGLE_QUERY_ARGUMENT", label: "Single Query Argument" },
  { value: "ALL_QUERY_ARGUMENTS", label: "All Query Arguments" },
  { value: "COOKIES", label: "Cookies" },
  { value: "JSON_BODY", label: "JSON Body" },
];

const POSITIONAL_CONSTRAINTS = [
  { value: "EXACTLY", label: "Exactly" },
  { value: "STARTS_WITH", label: "Starts With" },
  { value: "ENDS_WITH", label: "Ends With" },
  { value: "CONTAINS", label: "Contains" },
  { value: "CONTAINS_WORD", label: "Contains Word" },
];

const SIZE_OPERATORS = [
  { value: "EQ", label: "Equal To" },
  { value: "NE", label: "Not Equal To" },
  { value: "LE", label: "Less Than or Equal" },
  { value: "LT", label: "Less Than" },
  { value: "GE", label: "Greater Than or Equal" },
  { value: "GT", label: "Greater Than" },
];

const AGGREGATE_KEY_TYPES = [
  { value: "IP", label: "Source IP" },
  { value: "FORWARDED_IP", label: "Forwarded IP" },
  { value: "CUSTOM_KEYS", label: "Custom Keys" },
  { value: "CONSTANT", label: "Constant (All Requests)" },
];

const EVALUATION_WINDOWS = [
  { value: 60, label: "1 minute" },
  { value: 120, label: "2 minutes" },
  { value: 300, label: "5 minutes" },
  { value: 600, label: "10 minutes" },
];

export const RuleBuilder: React.FC<RuleBuilderProps> = ({ rule, onSave, onCancel }) => {
  const [name, setName] = useState(rule?.name || "");
  const [action, setAction] = useState<WAFAction>(rule?.action || "BLOCK");
  const [statementType, setStatementType] = useState<string>(
    rule?.statement?.type || "ByteMatchStatement"
  );
  const [expanded, setExpanded] = useState(true);

  // Byte Match state
  const [searchString, setSearchString] = useState(
    rule?.statement?.type === "ByteMatchStatement" ? (rule.statement as { searchString?: string }).searchString || "" : ""
  );
  const [fieldToMatch, setFieldToMatch] = useState<FieldToMatch>(
    rule?.statement?.type === "ByteMatchStatement"
      ? (rule.statement as { fieldToMatch?: FieldToMatch }).fieldToMatch || { type: "URI_PATH" }
      : { type: "URI_PATH" }
  );
  const [headerName, setHeaderName] = useState(
    rule?.statement?.type === "ByteMatchStatement" && (rule.statement as { fieldToMatch?: FieldToMatch }).fieldToMatch?.name
      ? (rule.statement as { fieldToMatch?: FieldToMatch }).fieldToMatch?.name || ""
      : ""
  );
  const [positionalConstraint, setPositionalConstraint] = useState<PositionalConstraint>(
    rule?.statement?.type === "ByteMatchStatement"
      ? (rule.statement as { positionalConstraint?: PositionalConstraint }).positionalConstraint || "CONTAINS"
      : "CONTAINS"
  );
  const [textTransformations, setTextTransformations] = useState<TextTransformation[]>(
    rule?.statement?.type === "ByteMatchStatement"
      ? (rule.statement as { textTransformations?: TextTransformation[] }).textTransformations || []
      : []
  );

  // Geo Match state
  const [countryCodes, setCountryCodes] = useState<string[]>(
    rule?.statement?.type === "GeoMatchStatement"
      ? (rule.statement as { countryCodes?: string[] }).countryCodes || []
      : []
  );

  // Rate Based state
  const [rateLimit, setRateLimit] = useState<number>(
    rule?.statement?.type === "RateBasedStatement"
      ? (rule.statement as { rateLimit?: number }).rateLimit || 100
      : 100
  );
  const [evaluationWindow, setEvaluationWindow] = useState<number>(
    rule?.statement?.type === "RateBasedStatement"
      ? (rule.statement as { evaluationWindowSec?: number }).evaluationWindowSec || 60
      : 60
  );
  const [aggregateKeyType, setAggregateKeyType] = useState<string>(
    rule?.statement?.type === "RateBasedStatement"
      ? (rule.statement as { aggregateKeyType?: string }).aggregateKeyType || "IP"
      : "IP"
  );

  // Regex Match state
  const [regexString, setRegexString] = useState(
    rule?.statement?.type === "RegexMatchStatement"
      ? (rule.statement as { regexString?: string }).regexString || ""
      : ""
  );

  // Size Constraint state
  const [size, setSize] = useState<number>(
    rule?.statement?.type === "SizeConstraintStatement"
      ? (rule.statement as { size?: number }).size || 1024
      : 1024
  );
  const [comparisonOperator, setComparisonOperator] = useState<string>(
    rule?.statement?.type === "SizeConstraintStatement"
      ? (rule.statement as { comparisonOperator?: string }).comparisonOperator || "GT"
      : "GT"
  );

  // Label Match state
  const [labelKey, setLabelKey] = useState(
    rule?.statement?.type === "LabelMatchStatement"
      ? (rule.statement as { key?: string }).key || ""
      : ""
  );
  const [labelScope, setLabelScope] = useState<"LABEL" | "NAMESPACE">(
    rule?.statement?.type === "LabelMatchStatement"
      ? (rule.statement as { scope?: "LABEL" | "NAMESPACE" }).scope || "LABEL"
      : "LABEL"
  );

  // IP Set state
  const [ipSetArn, setIpSetArn] = useState(
    rule?.statement?.type === "IPSetReferenceStatement"
      ? (rule.statement as { arn?: string }).arn || ""
      : ""
  );

  // Compound statement state (AND/OR/NOT)
  const [nestedStatements, setNestedStatements] = useState<Statement[]>(
    rule?.statement?.type === "AndStatement" || rule?.statement?.type === "OrStatement"
      ? (rule.statement as { statements?: Statement[] }).statements || []
      : []
  );
  const [notStatement, setNotStatement] = useState<Statement | null>(
    rule?.statement?.type === "NotStatement"
      ? (rule.statement as { statement?: Statement }).statement || null
      : null
  );

  // Custom labels
  const [ruleLabels, setRuleLabels] = useState<string[]>(rule?.ruleLabels || []);

  const availableTransformations = getAvailableTransformations();

  const addTransformation = () => {
    setTextTransformations([
      ...textTransformations,
      { type: "NONE", priority: textTransformations.length + 1 },
    ]);
  };

  const updateTransformation = (index: number, type: TextTransformationType) => {
    const newTransforms = [...textTransformations];
    newTransforms[index] = { ...newTransforms[index], type };
    setTextTransformations(newTransforms);
  };

  const removeTransformation = (index: number) => {
    setTextTransformations(textTransformations.filter((_, i) => i !== index));
  };

  const buildFieldToMatch = (): FieldToMatch => {
    const base: FieldToMatch = { type: fieldToMatch.type };
    
    if (fieldToMatch.type === "SINGLE_HEADER" && headerName) {
      base.name = headerName;
    }
    if (fieldToMatch.type === "SINGLE_QUERY_ARGUMENT" && headerName) {
      base.name = headerName;
    }
    
    return base;
  };

  const buildStatement = (): Statement => {
    const baseStatement: Record<string, unknown> = {
      type: statementType,
    };

    switch (statementType) {
      case "ByteMatchStatement":
        return {
          type: statementType,
          searchString,
          fieldToMatch: buildFieldToMatch(),
          positionalConstraint,
          textTransformations,
        } as Statement;

      case "GeoMatchStatement":
        return {
          type: statementType,
          countryCodes,
        } as Statement;

      case "IPSetReferenceStatement":
        return {
          type: statementType,
          arn: ipSetArn,
          ipSetReference: { arn: ipSetArn },
        } as Statement;

      case "LabelMatchStatement":
        return {
          type: statementType,
          key: labelKey,
          scope: labelScope,
        } as Statement;

      case "RateBasedStatement":
        return {
          type: statementType,
          rateLimit,
          evaluationWindowSec: evaluationWindow,
          aggregateKeyType,
        } as Statement;

      case "RegexMatchStatement":
        return {
          type: statementType,
          regexString,
          fieldToMatch: buildFieldToMatch(),
          textTransformations,
        } as Statement;

      case "SizeConstraintStatement":
        return {
          type: statementType,
          fieldToMatch: buildFieldToMatch(),
          comparisonOperator,
          size,
          textTransformations,
        } as Statement;

      case "SqliMatchStatement":
        return {
          type: statementType,
          fieldToMatch: buildFieldToMatch(),
          textTransformations,
          sensitivityLevel: "HIGH",
        } as Statement;

      case "XssMatchStatement":
        return {
          type: statementType,
          fieldToMatch: buildFieldToMatch(),
          textTransformations,
          sensitivityLevel: "HIGH",
        } as Statement;

      case "AndStatement":
        return {
          type: statementType,
          statements: nestedStatements,
        } as Statement;

      case "OrStatement":
        return {
          type: statementType,
          statements: nestedStatements,
        } as Statement;

      case "NotStatement":
        return {
          type: statementType,
          statement: notStatement,
        } as Statement;

      default:
        return { type: statementType } as unknown as Statement;
    }
  };

  const handleSave = () => {
    if (!name.trim()) {
      alert("Rule name is required");
      return;
    }

    const newRule: Rule = {
      name,
      priority: rule?.priority || 1,
      statement: buildStatement(),
      action,
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: name.replace(/[^a-zA-Z0-9]/g, ""),
      },
      ruleLabels,
    };

    onSave(newRule);
  };

  const renderFieldToMatchSelector = () => (
    <div className="space-y-2">
      <Label className="text-sm text-gray-400">Field to Match</Label>
      <Select
        value={fieldToMatch.type}
        onValueChange={(v) => setFieldToMatch({ ...fieldToMatch, type: v as FieldToMatch["type"] })}
      >
        <SelectTrigger className="bg-gray-800 border-gray-700">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {FIELD_TO_MATCH_OPTIONS.map((opt) => (
            <SelectItem key={opt.value} value={opt.value}>
              {opt.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      
      {(fieldToMatch.type === "SINGLE_HEADER" || fieldToMatch.type === "SINGLE_QUERY_ARGUMENT") && (
        <Input
          value={headerName}
          onChange={(e) => setHeaderName(e.target.value)}
          placeholder={fieldToMatch.type === "SINGLE_HEADER" ? "Header name (e.g., User-Agent)" : "Query argument name"}
          className="bg-gray-800 border-gray-700 mt-2"
        />
      )}
    </div>
  );

  const renderTextTransformations = () => (
    <div>
      <div className="flex items-center justify-between mb-2">
        <Label className="text-sm text-gray-400">Text Transformations</Label>
        <Button size="sm" variant="outline" onClick={addTransformation} className="h-7 text-xs">
          <Plus className="w-3 h-3 mr-1" />
          Add
        </Button>
      </div>
      <div className="space-y-2">
        {textTransformations.map((transform, index) => (
          <div key={index} className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              {index + 1}
            </Badge>
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Select
                    value={transform.type}
                    onValueChange={(v) => updateTransformation(index, v as TextTransformationType)}
                  >
                    <SelectTrigger className="bg-gray-800 border-gray-700 flex-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {availableTransformations.map((t) => (
                        <SelectItem key={t} value={t}>
                          {t}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="text-xs">{getTransformationDescription(transform.type)}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => removeTransformation(index)}
              className="text-red-400"
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        ))}
        {textTransformations.length === 0 && (
          <p className="text-xs text-gray-500 italic">No transformations applied</p>
        )}
      </div>
    </div>
  );

  const renderStatementBuilder = () => {
    switch (statementType) {
      case "ByteMatchStatement":
        return (
          <div className="space-y-4">
            <div>
              <Label className="text-sm text-gray-400">Search String</Label>
              <Input
                value={searchString}
                onChange={(e) => setSearchString(e.target.value)}
                placeholder="String to search for..."
                className="bg-gray-800 border-gray-700"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              {renderFieldToMatchSelector()}
              <div>
                <Label className="text-sm text-gray-400">Positional Constraint</Label>
                <Select
                  value={positionalConstraint}
                  onValueChange={(v) => setPositionalConstraint(v as PositionalConstraint)}
                >
                  <SelectTrigger className="bg-gray-800 border-gray-700">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {POSITIONAL_CONSTRAINTS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {renderTextTransformations()}
          </div>
        );

      case "GeoMatchStatement":
        return (
          <div className="space-y-4">
            <div>
              <Label className="text-sm text-gray-400">Country Codes (comma-separated)</Label>
              <Input
                value={countryCodes.join(", ")}
                onChange={(e) =>
                  setCountryCodes(
                    e.target.value.split(",").map((c) => c.trim().toUpperCase()).filter(Boolean)
                  )
                }
                placeholder="US, RU, CN, KP..."
                className="bg-gray-800 border-gray-700"
              />
              <p className="text-xs text-gray-500 mt-1">Use ISO 3166-1 alpha-2 country codes</p>
            </div>
            
            <div className="p-3 bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 text-blue-400 text-sm">
                <Info className="w-4 h-4" />
                <span>Matches requests originating from specified countries</span>
              </div>
            </div>
          </div>
        );

      case "RateBasedStatement":
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-sm text-gray-400">Rate Limit (requests)</Label>
                <Input
                  type="number"
                  value={rateLimit}
                  onChange={(e) => setRateLimit(parseInt(e.target.value) || 100)}
                  className="bg-gray-800 border-gray-700"
                  min={10}
                  max={2000000000}
                />
                <p className="text-xs text-gray-500 mt-1">Max requests per evaluation window</p>
              </div>
              <div>
                <Label className="text-sm text-gray-400">Evaluation Window</Label>
                <Select
                  value={evaluationWindow.toString()}
                  onValueChange={(v) => setEvaluationWindow(parseInt(v))}
                >
                  <SelectTrigger className="bg-gray-800 border-gray-700">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {EVALUATION_WINDOWS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value.toString()}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label className="text-sm text-gray-400">Aggregate Key Type</Label>
              <Select
                value={aggregateKeyType}
                onValueChange={setAggregateKeyType}
              >
                <SelectTrigger className="bg-gray-800 border-gray-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {AGGREGATE_KEY_TYPES.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-gray-500 mt-1">
                {aggregateKeyType === "IP" && "Rate limit per source IP address"}
                {aggregateKeyType === "FORWARDED_IP" && "Rate limit per forwarded IP (from X-Forwarded-For)"}
                {aggregateKeyType === "CUSTOM_KEYS" && "Rate limit by custom combination of attributes"}
                {aggregateKeyType === "CONSTANT" && "Rate limit across all requests (global)"}
              </p>
            </div>

            <div className="p-3 bg-yellow-900/20 border border-yellow-500/30 rounded-lg">
              <div className="flex items-center gap-2 text-yellow-400 text-sm">
                <AlertCircle className="w-4 h-4" />
                <span>Rate limits are simulated in flood test mode</span>
              </div>
            </div>
          </div>
        );

      case "RegexMatchStatement":
        return (
          <div className="space-y-4">
            <div>
              <Label className="text-sm text-gray-400">Regex Pattern</Label>
              <Input
                value={regexString}
                onChange={(e) => setRegexString(e.target.value)}
                placeholder=".*\.(sql|bak)$"
                className="bg-gray-800 border-gray-700 font-mono"
              />
              <p className="text-xs text-gray-500 mt-1">Enter a valid regular expression pattern</p>
            </div>
            
            {renderFieldToMatchSelector()}
            {renderTextTransformations()}
          </div>
        );

      case "SizeConstraintStatement":
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              {renderFieldToMatchSelector()}
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-sm text-gray-400">Operator</Label>
                <Select
                  value={comparisonOperator}
                  onValueChange={setComparisonOperator}
                >
                  <SelectTrigger className="bg-gray-800 border-gray-700">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SIZE_OPERATORS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-sm text-gray-400">Size (bytes)</Label>
                <Input
                  type="number"
                  value={size}
                  onChange={(e) => setSize(parseInt(e.target.value) || 0)}
                  className="bg-gray-800 border-gray-700"
                  min={0}
                  max={1073741824}
                />
              </div>
            </div>
            
            {renderTextTransformations()}
          </div>
        );

      case "SqliMatchStatement":
      case "XssMatchStatement":
        return (
          <div className="space-y-4">
            {renderFieldToMatchSelector()}
            {renderTextTransformations()}
            
            <div className="p-3 bg-gray-800 rounded-lg">
              <div className="flex items-center gap-2 text-green-400 text-sm">
                <AlertCircle className="w-4 h-4" />
                <span>
                  {statementType === "SqliMatchStatement" 
                    ? "Uses AWS built-in SQL injection detection patterns (HIGH sensitivity)"
                    : "Uses AWS built-in XSS detection patterns (HIGH sensitivity)"}
                </span>
              </div>
            </div>
          </div>
        );

      case "LabelMatchStatement":
        return (
          <div className="space-y-4">
            <div>
              <Label className="text-sm text-gray-400">Label Key</Label>
              <Input
                value={labelKey}
                onChange={(e) => setLabelKey(e.target.value)}
                placeholder="awswaf:managed:aws:sql injection:SQLInjectionQueryArguments"
                className="bg-gray-800 border-gray-700"
              />
              <p className="text-xs text-gray-500 mt-1">Full label namespace or specific label to match</p>
            </div>
            
            <div>
              <Label className="text-sm text-gray-400">Match Scope</Label>
              <Select
                value={labelScope}
                onValueChange={(v) => setLabelScope(v as "LABEL" | "NAMESPACE")}
              >
                <SelectTrigger className="bg-gray-800 border-gray-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="LABEL">Exact Label Match</SelectItem>
                  <SelectItem value="NAMESPACE">Namespace Prefix Match</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="p-3 bg-blue-900/20 border border-blue-500/30 rounded-lg">
              <div className="flex items-center gap-2 text-blue-400 text-sm">
                <Info className="w-4 h-4" />
                <span>Labels must be added by earlier rules in the same WebACL</span>
              </div>
            </div>
          </div>
        );

      case "IPSetReferenceStatement":
        return (
          <div className="space-y-4">
            <div>
              <Label className="text-sm text-gray-400">IP Set ARN</Label>
              <Input
                value={ipSetArn}
                onChange={(e) => setIpSetArn(e.target.value)}
                placeholder="arn:aws:wafv2:us-east-1:123456789012:regional/ipset/MyIPSet/..."
                className="bg-gray-800 border-gray-700"
              />
              <p className="text-xs text-gray-500 mt-1">
                Create IP Sets in the Resources panel or use existing AWS ARN
              </p>
            </div>
          </div>
        );

      case "AndStatement":
      case "OrStatement":
        return (
          <div className="space-y-4">
            <div className="p-3 bg-gray-800 rounded-lg">
              <p className="text-sm text-gray-400">
                {statementType === "AndStatement" 
                  ? "All statements must match for the rule to trigger"
                  : "Any statement must match for the rule to trigger"}
              </p>
            </div>
            
            <div className="text-center py-4 text-gray-500 border border-dashed border-gray-600 rounded-lg">
              <p className="text-sm">Nested statement configuration</p>
              <p className="text-xs mt-1">Add statements from the WAF panel after saving this rule</p>
            </div>
          </div>
        );

      case "NotStatement":
        return (
          <div className="space-y-4">
            <div className="p-3 bg-gray-800 rounded-lg">
              <p className="text-sm text-gray-400">
                The rule matches when the inner statement does NOT match
              </p>
            </div>
            
            <div className="text-center py-4 text-gray-500 border border-dashed border-gray-600 rounded-lg">
              <p className="text-sm">Negated statement configuration</p>
              <p className="text-xs mt-1">Configure the statement to negate after saving this rule</p>
            </div>
          </div>
        );

      default:
        return (
          <div className="text-center py-8 text-gray-500">
            <p>Statement type configuration coming soon</p>
          </div>
        );
    }
  };

  return (
    <div className="flex flex-col bg-gray-900 text-white">
      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Basic Info */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Basic Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-sm text-gray-400">Rule Name</Label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="MyRule"
                className="bg-gray-700 border-gray-600"
              />
            </div>

            <div>
              <Label className="text-sm text-gray-400">Action</Label>
              <Select value={action} onValueChange={(v) => setAction(v as WAFAction)}>
                <SelectTrigger className="bg-gray-700 border-gray-600">
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
              <p className="text-xs text-gray-500 mt-1">
                {action === "BLOCK" && "Terminate evaluation and block the request"}
                {action === "ALLOW" && "Terminate evaluation and allow the request"}
                {action === "COUNT" && "Count the match but continue evaluating rules"}
                {action === "CAPTCHA" && "Present CAPTCHA challenge to the client"}
                {action === "CHALLENGE" && "Present silent browser challenge"}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Statement Configuration */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Statement Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-sm text-gray-400">Statement Type</Label>
              <Select value={statementType} onValueChange={setStatementType}>
                <SelectTrigger className="bg-gray-700 border-gray-600">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="max-h-64">
                  {STATEMENT_TYPES.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      <div>
                        <span className="font-medium">{opt.label}</span>
                        <span className="text-gray-400 text-xs ml-2">{opt.description}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {renderStatementBuilder()}
          </CardContent>
        </Card>

        {/* Custom Labels */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Custom Labels</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {ruleLabels.map((label, index) => (
                <Badge key={index} variant="secondary" className="flex items-center gap-1">
                  {label}
                  <X
                    className="w-3 h-3 cursor-pointer"
                    onClick={() => setRuleLabels(ruleLabels.filter((_, i) => i !== index))}
                  />
                </Badge>
              ))}
              <Input
                placeholder="Add label..."
                className="bg-gray-700 border-gray-600 w-40"
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    const value = (e.target as HTMLInputElement).value.trim();
                    if (value && !ruleLabels.includes(value)) {
                      setRuleLabels([...ruleLabels, value]);
                      (e.target as HTMLInputElement).value = "";
                    }
                  }
                }}
              />
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Labels can be used by other rules with LabelMatchStatement
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Footer Actions */}
      <div className="p-4 border-t border-gray-700 flex gap-2 justify-end bg-gray-800">
        <Button variant="outline" onClick={onCancel} className="border-gray-600">
          <X className="w-4 h-4 mr-1" />
          Cancel
        </Button>
        <Button onClick={handleSave} className="bg-green-600 hover:bg-green-700">
          <Save className="w-4 h-4 mr-1" />
          Save Rule
        </Button>
      </div>
    </div>
  );
};

export default RuleBuilder;
