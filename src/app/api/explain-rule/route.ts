import { NextRequest, NextResponse } from "next/server";

const SYSTEM_PROMPT = `You are a WAF rule expert. Explain why a specific rule matched or didn't match a given HTTP request. Provide a concise, 2-sentence explanation. Be specific about which field or pattern was involved.`;

export async function POST(request: NextRequest) {
  try {
    const { rule, httpRequest, matched } = await request.json();
    if (!rule || !httpRequest) return NextResponse.json({ error: "Rule and httpRequest are required" }, { status: 400 });

    const apiKey = process.env.ZAI_API_KEY || "";
    const ruleDesc = describeRule(rule);
    const reqDesc = describeRequest(httpRequest);

    const res = await fetch('https://api.z.ai/api/paas/v4/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: 'GLM-4.7-Flash', thinking: { type: 'disabled' }, temperature: 0.5, max_tokens: 200,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: `Rule: ${ruleDesc}\nRequest: ${reqDesc}\nMatched: ${matched ? "Yes" : "No"}\n\nExplain why this rule ${matched ? "matched" : "did not match"} this request:` },
        ],
      }),
    });
    if (!res.ok) return NextResponse.json({ explanation: "AI explanation unavailable" });
    const data = await res.json();
    return NextResponse.json({ explanation: data.choices?.[0]?.message?.content || "Unable to generate explanation" });
  } catch (error) {
    console.error("Explain rule error:", error);
    return NextResponse.json({ explanation: "Explanation unavailable" });
  }
}

function describeRule(rule: any): string {
  let desc = `Name: ${rule.name || "Unknown"}, Action: ${rule.action || "Unknown"}`;
  if (rule.statement) {
    desc += `, Type: ${rule.statement.type}`;
    if (rule.statement.searchString) desc += `, Searching for: "${rule.statement.searchString}"`;
    if (rule.statement.fieldToMatch) desc += ` in ${rule.statement.fieldToMatch.type || "unknown field"}`;
    if (rule.statement.countryCodes) desc += `, Countries: ${rule.statement.countryCodes.join(", ")}`;
    if (rule.statement.rateLimit) desc += `, Rate limit: ${rule.statement.rateLimit}`;
    if (rule.statement.regexString) desc += `, Regex: "${rule.statement.regexString}"`;
  }
  return desc;
}

function describeRequest(req: any): string {
  let desc = `${req.method || "GET"} ${req.uri || "/"}`;
  if (req.sourceIP) desc += ` from ${req.sourceIP}`;
  if (req.country) desc += ` (${req.country})`;
  if (req.body) desc += `, Body: "${String(req.body).substring(0, 100)}"`;
  if (req.headers?.length) desc += `, Headers: ${req.headers.map((h: any) => h.name).join(", ")}`;
  return desc;
}
