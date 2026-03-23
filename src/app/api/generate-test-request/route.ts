import { NextRequest, NextResponse } from "next/server";

const SYSTEM_PROMPT = `You are an HTTP request generator for AWS WAF testing. Generate HTTP requests that simulate various attack patterns or normal traffic. Output ONLY a valid JSON object (no markdown). Include fields: protocol, method, uri, queryParams, headers, body, bodyEncoding, contentType, sourceIP, country. For SQL injection include payloads in URI/body. For XSS include script tags. For rate floods set _rateMode:true and ratePerMinute.`;

export async function POST(request: NextRequest) {
  try {
    const { description } = await request.json();
    if (!description) return NextResponse.json({ error: "Description is required" }, { status: 400 });

    const apiKey = process.env.ZAI_API_KEY || "";
    const res = await fetch('https://api.z.ai/api/paas/v4/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: 'GLM-4.7-Flash', thinking: { type: 'disabled' }, temperature: 0.7, max_tokens: 1000,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: description },
        ],
      }),
    });

    if (!res.ok) return NextResponse.json({ error: "AI generation unavailable" }, { status: 502 });
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) return NextResponse.json({ error: "Failed to generate request" }, { status: 500 });

    let jsonStr = content.trim().replace(/```json\n?/, "").replace(/\n?```$/, "").replace(/```\n?/, "").replace(/\n?```$/, "");
    const requestJson = JSON.parse(jsonStr);

    if (!requestJson.method) requestJson.method = "GET";
    if (!requestJson.uri) requestJson.uri = "/";
    if (!requestJson.sourceIP) requestJson.sourceIP = "192.168.1.100";
    if (!requestJson.country) requestJson.country = "US";
    if (!requestJson.protocol) requestJson.protocol = "HTTP/1.1";
    if (!requestJson.headers) requestJson.headers = [{ name: "Host", value: "example.com" }, { name: "User-Agent", value: "Mozilla/5.0" }];
    if (!requestJson.queryParams) requestJson.queryParams = {};
    if (!requestJson.body) requestJson.body = "";
    if (!requestJson.bodyEncoding) requestJson.bodyEncoding = "none";
    if (!requestJson.contentType) requestJson.contentType = "application/json";

    return NextResponse.json({ request: requestJson, explanation: `Generated based on: "${description}"` });
  } catch (error) {
    console.error("Generate test request error:", error);
    return NextResponse.json({ error: "Failed to generate request" }, { status: 500 });
  }
}
