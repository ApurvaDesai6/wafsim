// WAFSim - Complete TypeScript Type Definitions
// Implements AWS WAFv2 specification types

// =============================================================================
// HTTP Request Types
// =============================================================================

export type HTTPProtocol = "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/3";
export type HTTPMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

export interface HttpHeader {
  name: string;
  value: string;
}

export interface HttpRequest {
  // Transport
  protocol: HTTPProtocol;
  method: HTTPMethod;

  // Request target
  uri: string;
  queryParams: Record<string, string>;

  // Headers
  headers: HttpHeader[];

  // Body
  body: string;
  bodyEncoding: "none" | "base64";
  contentType: string;

  // Network
  sourceIP: string;
  country: string; // ISO 3166-1 alpha-2

  // Advanced
  ja3Fingerprint?: string;
  httpVersion?: string;

  // Rate simulation mode
  _rateMode?: boolean;
  ratePerMinute?: number;
}

// =============================================================================
// WAF Action Types
// =============================================================================

export type WAFAction = "ALLOW" | "BLOCK" | "COUNT" | "CAPTCHA" | "CHALLENGE";
export type OverrideAction = "NONE" | "COUNT";

export interface ActionSettings {
  allow?: Record<string, never>;
  block?: BlockAction;
  count?: Record<string, never>;
  captcha?: CaptchaAction;
  challenge?: ChallengeAction;
}

export interface BlockAction {
  customResponse?: CustomResponse;
}

export interface CustomResponse {
  responseCode: number;
  customResponseBodyKey?: string;
  responseHeaders?: Array<{ name: string; value: string }>;
}

export interface CaptchaAction {
  customRequestHandling?: CustomRequestHandling;
}

export interface ChallengeAction {
  customRequestHandling?: CustomRequestHandling;
}

export interface CustomRequestHandling {
  insertHeaders: Array<{ name: string; value: string }>;
}

// =============================================================================
// Text Transformation Types
// =============================================================================

export type TextTransformationType =
  | "NONE"
  | "LOWERCASE"
  | "URL_DECODE"
  | "URL_DECODE_UNI"
  | "HTML_ENTITY_DECODE"
  | "COMPRESS_WHITE_SPACE"
  | "CMD_LINE"
  | "BASE64_DECODE"
  | "BASE64_DECODE_EXT"
  | "HEX_DECODE"
  | "MD5"
  | "REPLACE_NULLS"
  | "REMOVE_NULLS"
  | "NORMALIZE_PATH"
  | "NORMALIZE_PATH_WIN";

export interface TextTransformation {
  type: TextTransformationType;
  priority: number;
}

// =============================================================================
// Field to Match Types
// =============================================================================

export type FieldToMatchType =
  | "URI_PATH"
  | "QUERY_STRING"
  | "BODY"
  | "METHOD"
  | "SINGLE_HEADER"
  | "ALL_HEADERS"
  | "SINGLE_QUERY_ARGUMENT"
  | "ALL_QUERY_ARGUMENTS"
  | "COOKIES"
  | "JSON_BODY"
  | "JA3_FINGERPRINT"
  | "HTTP_VERSION"
  | "HEADER_ORDER";

export type OversizeHandling = "CONTINUE" | "MATCH" | "NO_MATCH";
export type MatchScope = "KEY" | "VALUE" | "ALL";
export type JsonMatchScope = "VALUE" | "KEY" | "ALL";
export type InvalidJsonFallback = "MATCH" | "NO_MATCH" | "EVALUATE_AS_STRING";

export interface FieldToMatch {
  type: FieldToMatchType;
  // SINGLE_HEADER
  name?: string;
  // BODY
  oversizeHandling?: OversizeHandling;
  // ALL_HEADERS, COOKIES
  matchScope?: MatchScope;
  // JSON_BODY
  jsonMatchScope?: JsonMatchScope;
  invalidFallback?: InvalidJsonFallback;
  // JA3_FINGERPRINT
  fallbackBehavior?: "MATCH" | "NO_MATCH";
}

// =============================================================================
// Positional Constraint Types
// =============================================================================

export type PositionalConstraint =
  | "EXACTLY"
  | "STARTS_WITH"
  | "ENDS_WITH"
  | "CONTAINS"
  | "CONTAINS_WORD";

export type SizeComparisonOperator =
  | "EQ"
  | "NE"
  | "LE"
  | "LT"
  | "GE"
  | "GT";

// =============================================================================
// Statement Types - Core WAF Rule Statements
// =============================================================================

export type StatementType =
  | "ByteMatchStatement"
  | "GeoMatchStatement"
  | "IPSetReferenceStatement"
  | "LabelMatchStatement"
  | "ManagedRuleGroupStatement"
  | "RateBasedStatement"
  | "RegexMatchStatement"
  | "RegexPatternSetReferenceStatement"
  | "SizeConstraintStatement"
  | "SqliMatchStatement"
  | "XssMatchStatement"
  | "AndStatement"
  | "OrStatement"
  | "NotStatement"
  | "RuleGroupReferenceStatement";

// Base statement interface
export interface BaseStatement {
  type: StatementType;
}

// Byte Match Statement
export interface ByteMatchStatement extends BaseStatement {
  type: "ByteMatchStatement";
  searchString: string;
  fieldToMatch: FieldToMatch;
  textTransformations: TextTransformation[];
  positionalConstraint: PositionalConstraint;
}

// Geo Match Statement
export interface GeoMatchStatement extends BaseStatement {
  type: "GeoMatchStatement";
  countryCodes: string[]; // ISO 3166-1 alpha-2
  forwardedIPConfig?: ForwardedIPConfig;
}

// IP Set Reference Statement
export interface IPSetReferenceStatement extends BaseStatement {
  type: "IPSetReferenceStatement";
  arn: string; // Reference to IP Set
  ipSetReference: IPSetReference;
  forwardedIPConfig?: ForwardedIPConfig;
}

export interface IPSetReference {
  arn: string;
}

// Label Match Statement
export interface LabelMatchStatement extends BaseStatement {
  type: "LabelMatchStatement";
  key: string;
  scope: "LABEL" | "NAMESPACE";
}

// Managed Rule Group Statement
export interface ManagedRuleGroupStatement extends BaseStatement {
  type: "ManagedRuleGroupStatement";
  vendorName: string;
  name: string;
  version?: string;
  excludedRules?: string[];
  managedRuleGroupConfigs?: ManagedRuleGroupConfig[];
  ruleActionOverrides?: RuleActionOverride[];
  scopeDownStatement?: Statement;
}

export interface ManagedRuleGroupConfig {
  loginPath?: string;
  passwordField?: { identifier: string };
  usernameField?: { identifier: string };
  payloadType?: "JSON" | "FORM_ENCODED";
  awsManagedRulesBotControlRuleSet?: {
    inspectionLevel: "COMMON" | "TARGETED";
    enableMachineLearning?: boolean;
  };
  awsManagedRulesATPRuleSet?: {
    loginPath: string;
    requestInspection?: {
      payloadType: "JSON" | "FORM_ENCODED";
      usernameField: { identifier: string };
      passwordField: { identifier: string };
    };
    responseInspection?: ResponseInspection;
    enableRegexInPath?: boolean;
  };
}

export interface ResponseInspection {
  statusCode?: {
    successCodes: number[];
    failureCodes: number[];
  };
  header?: {
    name: string;
    successValues: string[];
    failureValues: string[];
  };
  bodyContains?: {
    successStrings: string[];
    failureStrings: string[];
  };
  json?: {
    identifier: string;
    successValues: string[];
    failureValues: string[];
  };
}

export interface RuleActionOverride {
  name: string;
  actionToUse: WAFAction;
}

// Rate Based Statement
export interface RateBasedStatement extends BaseStatement {
  type: "RateBasedStatement";
  rateLimit: number;
  evaluationWindowSec: number; // 60, 120, 300, 600
  aggregateKeyType: "IP" | "FORWARDED_IP" | "CUSTOM_KEYS" | "CONSTANT";
  aggregateKeys?: RateAggregateKey[];
  scopeDownStatement?: Statement;
  forwardedIPConfig?: ForwardedIPConfig;
}

export interface RateAggregateKey {
  header?: { name: string };
  cookie?: { name: string };
  queryArgument?: { name: string };
  queryString?: Record<string, never>;
  httpMethod?: Record<string, never>;
  forwardedIP?: Record<string, never>;
  ip?: Record<string, never>;
  labelNamespace?: { namespace: string };
  uriPath?: Record<string, never>;
}

// Regex Match Statement
export interface RegexMatchStatement extends BaseStatement {
  type: "RegexMatchStatement";
  regexString: string;
  fieldToMatch: FieldToMatch;
  textTransformations: TextTransformation[];
}

// Regex Pattern Set Reference Statement
export interface RegexPatternSetReferenceStatement extends BaseStatement {
  type: "RegexPatternSetReferenceStatement";
  arn: string;
  fieldToMatch: FieldToMatch;
  textTransformations: TextTransformation[];
}

// Size Constraint Statement
export interface SizeConstraintStatement extends BaseStatement {
  type: "SizeConstraintStatement";
  fieldToMatch: FieldToMatch;
  comparisonOperator: SizeComparisonOperator;
  size: number;
  textTransformations: TextTransformation[];
}

// SQLi Match Statement
export interface SqliMatchStatement extends BaseStatement {
  type: "SqliMatchStatement";
  fieldToMatch: FieldToMatch;
  textTransformations: TextTransformation[];
  sensitivityLevel?: "LOW" | "HIGH";
}

// XSS Match Statement
export interface XssMatchStatement extends BaseStatement {
  type: "XssMatchStatement";
  fieldToMatch: FieldToMatch;
  textTransformations: TextTransformation[];
  sensitivityLevel?: "LOW" | "HIGH";
}

// And Statement
export interface AndStatement extends BaseStatement {
  type: "AndStatement";
  statements: Statement[];
}

// Or Statement
export interface OrStatement extends BaseStatement {
  type: "OrStatement";
  statements: Statement[];
}

// Not Statement
export interface NotStatement extends BaseStatement {
  type: "NotStatement";
  statement: Statement;
}

// Rule Group Reference Statement
export interface RuleGroupReferenceStatement extends BaseStatement {
  type: "RuleGroupReferenceStatement";
  arn: string;
  excludedRules?: string[];
  ruleActionOverrides?: RuleActionOverride[];
}

// Forwarded IP Configuration
export interface ForwardedIPConfig {
  headerName: string;
  fallbackBehavior: "MATCH" | "NO_MATCH";
}

// Union type for all statements
export type Statement =
  | ByteMatchStatement
  | GeoMatchStatement
  | IPSetReferenceStatement
  | LabelMatchStatement
  | ManagedRuleGroupStatement
  | RateBasedStatement
  | RegexMatchStatement
  | RegexPatternSetReferenceStatement
  | SizeConstraintStatement
  | SqliMatchStatement
  | XssMatchStatement
  | AndStatement
  | OrStatement
  | NotStatement
  | RuleGroupReferenceStatement;

// =============================================================================
// Rule Types
// =============================================================================

export interface Rule {
  name: string;
  priority: number;
  statement: Statement;
  action: WAFAction;
  visibilityConfig: VisibilityConfig;
  ruleLabels?: string[];
  overrideAction?: OverrideAction; // For managed rule groups
}

export interface VisibilityConfig {
  sampledRequestsEnabled: boolean;
  cloudWatchMetricsEnabled: boolean;
  metricName: string;
}

// =============================================================================
// IP Set Types
// =============================================================================

export interface IPSet {
  id: string;
  name: string;
  description?: string;
  scope: "CLOUDFRONT" | "REGIONAL";
  ipAddressVersion: "IPV4" | "IPV6";
  addresses: string[]; // CIDR blocks
  arn: string;
}

// =============================================================================
// Regex Pattern Set Types
// =============================================================================

export interface RegexPatternSet {
  id: string;
  name: string;
  description?: string;
  scope: "CLOUDFRONT" | "REGIONAL";
  regularExpressionList: string[];
  arn: string;
}

// =============================================================================
// WebACL Types
// =============================================================================

export interface WebACL {
  id: string;
  name: string;
  description?: string;
  scope: "CLOUDFRONT" | "REGIONAL";
  defaultAction: WAFAction;
  rules: Rule[];
  visibilityConfig: VisibilityConfig;
  capacity: number; // WCU
  customResponseBodies?: Record<string, CustomResponseBody>;
  tokenDomains?: string[];
}

export interface CustomResponseBody {
  contentType: "TEXT_PLAIN" | "TEXT_HTML" | "APPLICATION_JSON";
  content: string;
}

// =============================================================================
// Evaluation Result Types
// =============================================================================

export interface RuleMatch {
  rule: Rule;
  action: WAFAction;
}

export interface RuleTrace {
  ruleName: string;
  priority: number;
  matched: boolean;
  action: WAFAction | "no-action";
  labelsAdded: string[];
  terminates: boolean;
  reason: string;
  matchedContent?: string;
  transformedContent?: string;
}

export interface EvaluationResult {
  finalAction: WAFAction;
  terminatingRule: RuleMatch | null;
  allMatchedRules: RuleMatch[];
  labelsApplied: string[];
  ruleTrace: RuleTrace[];
  requestWithTransformations: HttpRequest;
  approximatedManagedRules: boolean;
}

// =============================================================================
// Flood Simulation Types
// =============================================================================

export interface FloodSimulation {
  requestsPerMinute: number;
  durationMinutes: number;
  rateRule: RateBasedStatement;
}

export interface FloodSimulationResult {
  triggersAtSeconds: number | null;
  triggerRequestCount: number;
  totalRequests: number;
  blockedRequests: number;
  allowedRequests: number;
  timeline: FloodTimelineEntry[];
}

export interface FloodTimelineEntry {
  elapsedSeconds: number;
  requestCount: number;
  currentRate: number;
  rateLimitHit: boolean;
  action: WAFAction;
}

// =============================================================================
// Topology Types
// =============================================================================

export type AWSResourceType =
  | "INTERNET"
  | "CLOUDFRONT"
  | "ALB"
  | "API_GATEWAY"
  | "APPSYNC"
  | "COGNITO"
  | "EC2"
  | "ECS"
  | "LAMBDA"
  | "S3"
  | "NAT_GATEWAY"
  | "WAF";

export interface AWSResourceNode {
  id: string;
  type: AWSResourceType;
  label: string;
  icon: string;
  wafAttachable: boolean;
  scope?: "CLOUDFRONT" | "REGIONAL";
  position: { x: number; y: number };
  wafId?: string; // If this node is a WAF, reference to the WAF
  data?: Record<string, unknown>;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  wafId?: string; // WAF node attached to this edge
}

export interface TopologyState {
  nodes: AWSResourceNode[];
  edges: TopologyEdge[];
  wafs: WebACL[];
}

// =============================================================================
// Traffic Animation Types
// =============================================================================

export type TrafficStatus = "traveling" | "evaluating" | "blocked" | "allowed" | "counted";

export interface TrafficDot {
  id: string;
  request: HttpRequest;
  result: EvaluationResult;
  position: number; // 0.0 to 1.0 along current edge
  currentEdge: string;
  status: TrafficStatus;
  createdAt: number;
  speed: "slow" | "normal" | "fast";
}

// =============================================================================
// Export Types
// =============================================================================

export interface WAFV2WebACLJson {
  Name: string;
  Scope: "CLOUDFRONT" | "REGIONAL";
  DefaultAction: { Allow?: Record<string, never>; Block?: Record<string, never> };
  Description?: string;
  Rules: WAFV2RuleJson[];
  VisibilityConfig: {
    SampledRequestsEnabled: boolean;
    CloudWatchMetricsEnabled: boolean;
    MetricName: string;
  };
  CustomResponseBodies?: Record<string, { ContentType: string; Content: string }>;
  TokenDomains?: string[];
}

export interface WAFV2RuleJson {
  Name: string;
  Priority: number;
  Statement: Record<string, unknown>;
  Action?: { Allow?: Record<string, never>; Block?: Record<string, never>; Count?: Record<string, never> };
  OverrideAction?: { Allow?: Record<string, never>; Block?: Record<string, never>; Count?: Record<string, never>; None?: Record<string, never> };
  VisibilityConfig: {
    SampledRequestsEnabled: boolean;
    CloudWatchMetricsEnabled: boolean;
    MetricName: string;
  };
  RuleLabels?: Array<{ Name: string }>;
}

// =============================================================================
// Attack Pattern Presets
// =============================================================================

export interface AttackPreset {
  id: string;
  name: string;
  description: string;
  category: "sqli" | "xss" | "rce" | "traversal" | "auth" | "flood" | "bot" | "other";
  request: Partial<HttpRequest>;
  expectedBehavior?: string;
}

// =============================================================================
// Managed Rule Group Data
// =============================================================================

export interface ManagedRuleGroup {
  vendorName: string;
  name: string;
  description: string;
  wcu: number;
  scope: "BOTH" | "CLOUDFRONT_ONLY" | "REGIONAL_ONLY";
  additionalFee: boolean;
  rules: ManagedRule[];
  labelNamespace: string;
}

export interface ManagedRule {
  name: string;
  description: string;
  defaultAction: "Block" | "Count";
  addedLabels: string[];
  sensitivityLevel?: "LOW" | "HIGH";
  simulationCriteria?: SimulationCriteria;
}

export interface SimulationCriteria {
  type: "header_absent" | "header_match" | "body_pattern" | "uri_pattern" | "query_pattern" | "ip_in_list" | "size_check" | "method_check" | "custom";
  field?: string;
  pattern?: string | RegExp;
  patterns?: (string | RegExp)[];
  operator?: "equals" | "contains" | "matches" | "exceeds" | "absent";
  value?: string | number | string[];
}

// =============================================================================
// Store Types
// =============================================================================

export interface WAFSimState {
  // Topology
  topology: TopologyState;

  // Selected items
  selectedNode: string | null;
  selectedEdge: string | null;
  selectedWAF: string | null;

  // Resources
  ipSets: IPSet[];
  regexPatternSets: RegexPatternSet[];

  // Simulation
  currentRequest: HttpRequest;
  evaluationResult: EvaluationResult | null;
  trafficDots: TrafficDot[];
  floodSimulationResult: FloodSimulationResult | null;

  // UI State
  isSimulating: boolean;
  animationSpeed: "slow" | "normal" | "fast";
  showRuleBuilder: boolean;
  showExportModal: boolean;
  showImportModal: boolean;
}

// =============================================================================
// WCU Calculation Types
// =============================================================================

export interface WCUCostBreakdown {
  base: number;
  transformations: number;
  total: number;
  details: string[];
}

// =============================================================================
// NL Generation Types
// =============================================================================

export interface NLGenerationRequest {
  description: string;
  context?: {
    existingRules?: Rule[];
    targetEndpoint?: string;
  };
}

export interface NLGenerationResponse {
  request: HttpRequest;
  explanation: string;
  rateMode?: boolean;
}
