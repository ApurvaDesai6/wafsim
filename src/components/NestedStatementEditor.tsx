"use client";

import React from "react";
import type { Statement, FieldToMatch } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, X } from "lucide-react";

// Up to 3 levels of nesting as per v3 spec. Beyond that the console UX
// becomes unreadable. Raise if needed but keep a cap so users don't build
// unreadable trees.
const MAX_DEPTH = 3;

const SIMPLE_TYPES = [
  { value: "ByteMatchStatement", label: "Byte Match" },
  { value: "GeoMatchStatement", label: "Geo Match" },
  { value: "IPSetReferenceStatement", label: "IP Set" },
  { value: "LabelMatchStatement", label: "Label Match" },
  { value: "SizeConstraintStatement", label: "Size Constraint" },
  { value: "RegexMatchStatement", label: "Regex Match" },
];

const COMPOUND_TYPES = [
  { value: "AndStatement", label: "AND (all must match)" },
  { value: "OrStatement", label: "OR (any must match)" },
  { value: "NotStatement", label: "NOT (negate)" },
];

const ALL_TYPES = [...SIMPLE_TYPES, ...COMPOUND_TYPES];

const FIELD_TO_MATCH_OPTIONS: Array<{ value: FieldToMatch["type"]; label: string }> = [
  { value: "URI_PATH", label: "URI Path" },
  { value: "QUERY_STRING", label: "Query String" },
  { value: "BODY", label: "Body" },
  { value: "METHOD", label: "HTTP Method" },
  { value: "SINGLE_HEADER", label: "Single Header" },
  { value: "ALL_QUERY_ARGUMENTS", label: "All Query Arguments" },
];

const POSITIONAL_CONSTRAINTS = [
  { value: "EXACTLY", label: "Exactly" },
  { value: "STARTS_WITH", label: "Starts With" },
  { value: "ENDS_WITH", label: "Ends With" },
  { value: "CONTAINS", label: "Contains" },
  { value: "CONTAINS_WORD", label: "Contains Word" },
];

const SIZE_OPERATORS = ["EQ", "NE", "LE", "LT", "GE", "GT"];

interface Props {
  statement: Statement | null;
  onChange: (s: Statement | null) => void;
  depth?: number;
}

function defaultStatementOfType(type: string): Statement {
  switch (type) {
    case "GeoMatchStatement":
      return { type: "GeoMatchStatement", countryCodes: ["US"] } as Statement;
    case "IPSetReferenceStatement":
      return {
        type: "IPSetReferenceStatement",
        arn: "",
        ipSetReference: { arn: "" },
      } as Statement;
    case "LabelMatchStatement":
      return { type: "LabelMatchStatement", scope: "LABEL", key: "" } as Statement;
    case "SizeConstraintStatement":
      return {
        type: "SizeConstraintStatement",
        fieldToMatch: { type: "BODY", oversizeHandling: "CONTINUE" },
        comparisonOperator: "GT",
        size: 1024,
        textTransformations: [{ type: "NONE", priority: 0 }],
      } as Statement;
    case "RegexMatchStatement":
      return {
        type: "RegexMatchStatement",
        regexString: "",
        fieldToMatch: { type: "URI_PATH" },
        textTransformations: [{ type: "NONE", priority: 0 }],
      } as Statement;
    case "AndStatement":
      return { type: "AndStatement", statements: [] } as Statement;
    case "OrStatement":
      return { type: "OrStatement", statements: [] } as Statement;
    case "NotStatement":
      return {
        type: "NotStatement",
        statement: { type: "GeoMatchStatement", countryCodes: [] } as Statement,
      } as Statement;
    case "ByteMatchStatement":
    default:
      return {
        type: "ByteMatchStatement",
        searchString: "",
        fieldToMatch: { type: "URI_PATH" },
        textTransformations: [{ type: "NONE", priority: 0 }],
        positionalConstraint: "CONTAINS",
      } as Statement;
  }
}

const DEPTH_BORDER: Record<number, string> = {
  0: "border-l-blue-500",
  1: "border-l-emerald-500",
  2: "border-l-amber-500",
  3: "border-l-pink-500",
};

const COMPOUND_BORDER: Record<string, string> = {
  AndStatement: "border-l-blue-500",
  OrStatement: "border-l-emerald-500",
  NotStatement: "border-l-red-500",
};

/**
 * Recursive editor for WAF Statements. Handles simple types inline and
 * recurses into itself for compound AND/OR/NOT up to MAX_DEPTH levels.
 *
 * Design notes:
 *   - Simple types render a compact inline editor (enough to author the
 *     common case; full power still available in the main RuleBuilder for
 *     top-level statements).
 *   - Compound types render a colored-border card with + / X controls.
 *   - Null statement renders a single "Choose statement type" dropdown.
 */
export function NestedStatementEditor({ statement, onChange, depth = 0 }: Props) {
  if (!statement) {
    return (
      <div className="border border-dashed border-gray-600 rounded-md p-2 bg-gray-800/40">
        <Select onValueChange={(v) => onChange(defaultStatementOfType(v))}>
          <SelectTrigger className="bg-gray-900 border-gray-700 h-7 text-xs">
            <SelectValue placeholder="Choose a statement type…" />
          </SelectTrigger>
          <SelectContent>
            {ALL_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value} disabled={isCompound(t.value) && depth >= MAX_DEPTH}>
                {t.label}{isCompound(t.value) && depth >= MAX_DEPTH ? " (max depth reached)" : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    );
  }

  const borderColor =
    isCompound(statement.type) ? COMPOUND_BORDER[statement.type] : DEPTH_BORDER[depth % 4];

  return (
    <div className={`border-l-2 ${borderColor} border-t border-r border-b border-gray-700 rounded-md bg-gray-900 p-2 space-y-1.5`}>
      <div className="flex items-center gap-2">
        <Select
          value={statement.type}
          onValueChange={(v) => {
            // Switching types creates a fresh default; inner state is lost
            onChange(defaultStatementOfType(v));
          }}
        >
          <SelectTrigger className="bg-gray-800 border-gray-700 h-6 text-[11px] flex-1">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ALL_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value} disabled={isCompound(t.value) && depth >= MAX_DEPTH}>
                {t.label}{isCompound(t.value) && depth >= MAX_DEPTH ? " (max depth)" : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <button
          type="button"
          onClick={() => onChange(null)}
          className="text-gray-500 hover:text-red-400 shrink-0"
          aria-label="Remove statement"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
      <div className="pl-1">
        {renderStatementBody(statement, onChange, depth)}
      </div>
    </div>
  );
}

function isCompound(type: string): boolean {
  return type === "AndStatement" || type === "OrStatement" || type === "NotStatement";
}

function renderStatementBody(
  statement: Statement,
  onChange: (s: Statement | null) => void,
  depth: number
): React.ReactNode {
  switch (statement.type) {
    case "AndStatement":
    case "OrStatement": {
      const s = statement as Statement & { statements: Statement[] };
      return (
        <div className="space-y-1.5">
          {s.statements.length === 0 && (
            <p className="text-[10px] text-gray-500 italic py-1">
              No child statements — add one below.
            </p>
          )}
          {s.statements.map((child, i) => (
            <NestedStatementEditor
              key={i}
              statement={child}
              depth={depth + 1}
              onChange={(newChild) => {
                const next = [...s.statements];
                if (newChild === null) {
                  next.splice(i, 1);
                } else {
                  next[i] = newChild;
                }
                onChange({ ...s, statements: next });
              }}
            />
          ))}
          {depth < MAX_DEPTH && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-6 text-[10px] border-gray-700 hover:bg-gray-800"
              onClick={() =>
                onChange({
                  ...s,
                  statements: [...s.statements, defaultStatementOfType("ByteMatchStatement")],
                })
              }
            >
              <Plus className="w-3 h-3 mr-1" />
              Add child statement
            </Button>
          )}
          {depth >= MAX_DEPTH && (
            <p className="text-[10px] text-gray-500 italic">Max nesting depth ({MAX_DEPTH}) reached.</p>
          )}
        </div>
      );
    }
    case "NotStatement": {
      const s = statement as Statement & { statement: Statement };
      return (
        <div>
          <NestedStatementEditor
            statement={s.statement}
            depth={depth + 1}
            onChange={(newInner) => {
              if (newInner === null) {
                onChange(null);
              } else {
                onChange({ ...s, statement: newInner });
              }
            }}
          />
        </div>
      );
    }
    case "GeoMatchStatement": {
      const s = statement as Statement & { countryCodes: string[] };
      return (
        <div>
          <Label className="text-[10px] text-gray-500">Country codes (comma-separated)</Label>
          <Input
            value={s.countryCodes.join(",")}
            onChange={(e) =>
              onChange({
                ...s,
                countryCodes: e.target.value
                  .split(",")
                  .map((c) => c.trim().toUpperCase())
                  .filter(Boolean),
              })
            }
            placeholder="US,CA,GB"
            className="bg-gray-800 border-gray-700 h-6 text-[11px] font-mono"
          />
        </div>
      );
    }
    case "IPSetReferenceStatement": {
      const s = statement as Statement & { arn: string };
      return (
        <div>
          <Label className="text-[10px] text-gray-500">IP Set ARN</Label>
          <Input
            value={s.arn}
            onChange={(e) =>
              onChange({
                ...s,
                arn: e.target.value,
                ipSetReference: { arn: e.target.value },
              } as Statement)
            }
            placeholder="arn:aws:wafv2:…/ipset/…"
            className="bg-gray-800 border-gray-700 h-6 text-[11px] font-mono"
          />
        </div>
      );
    }
    case "LabelMatchStatement": {
      const s = statement as Statement & { key: string; scope: "LABEL" | "NAMESPACE" };
      return (
        <div className="grid grid-cols-[1fr_auto] gap-2">
          <div>
            <Label className="text-[10px] text-gray-500">Label key</Label>
            <Input
              value={s.key}
              onChange={(e) => onChange({ ...s, key: e.target.value })}
              placeholder="awswaf:managed:…"
              className="bg-gray-800 border-gray-700 h-6 text-[11px] font-mono"
            />
          </div>
          <div>
            <Label className="text-[10px] text-gray-500">Scope</Label>
            <Select
              value={s.scope}
              onValueChange={(v) => onChange({ ...s, scope: v as "LABEL" | "NAMESPACE" })}
            >
              <SelectTrigger className="bg-gray-800 border-gray-700 h-6 text-[11px] w-24">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="LABEL">Label</SelectItem>
                <SelectItem value="NAMESPACE">Namespace</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      );
    }
    case "SizeConstraintStatement": {
      const s = statement as Statement & {
        fieldToMatch: FieldToMatch;
        comparisonOperator: string;
        size: number;
      };
      return (
        <div className="grid grid-cols-3 gap-2">
          <div>
            <Label className="text-[10px] text-gray-500">Field</Label>
            <Select
              value={s.fieldToMatch.type}
              onValueChange={(v) =>
                onChange({ ...s, fieldToMatch: { ...s.fieldToMatch, type: v as FieldToMatch["type"] } })
              }
            >
              <SelectTrigger className="bg-gray-800 border-gray-700 h-6 text-[11px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FIELD_TO_MATCH_OPTIONS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-[10px] text-gray-500">Op</Label>
            <Select
              value={s.comparisonOperator}
              onValueChange={(v) => onChange({ ...s, comparisonOperator: v })}
            >
              <SelectTrigger className="bg-gray-800 border-gray-700 h-6 text-[11px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SIZE_OPERATORS.map((o) => (
                  <SelectItem key={o} value={o}>
                    {o}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-[10px] text-gray-500">Size (bytes)</Label>
            <Input
              type="number"
              value={s.size}
              onChange={(e) => onChange({ ...s, size: parseInt(e.target.value) || 0 })}
              className="bg-gray-800 border-gray-700 h-6 text-[11px] font-mono"
            />
          </div>
        </div>
      );
    }
    case "ByteMatchStatement": {
      const s = statement as Statement & {
        searchString: string;
        fieldToMatch: FieldToMatch;
        positionalConstraint: string;
      };
      return (
        <div className="space-y-1.5">
          <div className="grid grid-cols-[1fr_auto] gap-2">
            <div>
              <Label className="text-[10px] text-gray-500">Search string</Label>
              <Input
                value={s.searchString}
                onChange={(e) => onChange({ ...s, searchString: e.target.value })}
                placeholder="/admin"
                className="bg-gray-800 border-gray-700 h-6 text-[11px] font-mono"
              />
            </div>
            <div>
              <Label className="text-[10px] text-gray-500">Match</Label>
              <Select
                value={s.positionalConstraint}
                onValueChange={(v) => onChange({ ...s, positionalConstraint: v })}
              >
                <SelectTrigger className="bg-gray-800 border-gray-700 h-6 text-[11px] w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {POSITIONAL_CONSTRAINTS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <Label className="text-[10px] text-gray-500">Field</Label>
            <Select
              value={s.fieldToMatch.type}
              onValueChange={(v) =>
                onChange({ ...s, fieldToMatch: { ...s.fieldToMatch, type: v as FieldToMatch["type"] } })
              }
            >
              <SelectTrigger className="bg-gray-800 border-gray-700 h-6 text-[11px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FIELD_TO_MATCH_OPTIONS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      );
    }
    case "RegexMatchStatement": {
      const s = statement as Statement & {
        regexString: string;
        fieldToMatch: FieldToMatch;
      };
      return (
        <div className="grid grid-cols-[1fr_auto] gap-2">
          <div>
            <Label className="text-[10px] text-gray-500">Regex</Label>
            <Input
              value={s.regexString}
              onChange={(e) => onChange({ ...s, regexString: e.target.value })}
              placeholder="^/api/v[0-9]+/"
              className="bg-gray-800 border-gray-700 h-6 text-[11px] font-mono"
            />
          </div>
          <div>
            <Label className="text-[10px] text-gray-500">Field</Label>
            <Select
              value={s.fieldToMatch.type}
              onValueChange={(v) =>
                onChange({ ...s, fieldToMatch: { ...s.fieldToMatch, type: v as FieldToMatch["type"] } })
              }
            >
              <SelectTrigger className="bg-gray-800 border-gray-700 h-6 text-[11px] w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FIELD_TO_MATCH_OPTIONS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      );
    }
    default:
      return <p className="text-[10px] text-gray-500 italic">Unsupported statement type.</p>;
  }
}
