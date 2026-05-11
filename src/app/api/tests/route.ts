import { NextResponse } from "next/server";
import { runAllTests } from "@/engines/testSuite";

/**
 * GET /api/tests
 *
 * Runs the in-app test suite (sub-rule coverage + rule ordering scenarios)
 * and returns a structured pass/fail report. The authoritative engine-level
 * test suite lives in src/__tests__/ and is executed via `bun run test`
 * (vitest). This route is a lightweight live-run endpoint for the UI.
 */
export async function GET() {
  try {
    const results = runAllTests();
    return NextResponse.json({
      success: results.summary.failed === 0,
      summary: {
        overall: results.summary,
        subRuleTests: {
          total: results.subRuleResults.length,
          passed: results.subRuleResults.filter((r) => r.passed).length,
          failed: results.subRuleResults.filter((r) => !r.passed).length,
        },
        orderTests: {
          total: results.orderResults.length,
          passed: results.orderResults.filter((r) => r.passed).length,
          failed: results.orderResults.filter((r) => !r.passed).length,
        },
      },
      subRuleResults: results.subRuleResults,
      orderResults: results.orderResults,
    });
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}
