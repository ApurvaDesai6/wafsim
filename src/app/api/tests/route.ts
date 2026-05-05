import { NextResponse } from "next/server";
import { runAllTests } from "@/engines/testSuite";

/**
 * GET /api/tests
 *
 * Runs the in-app test suite (sub-rule coverage + rule ordering scenarios)
 * and returns a structured pass/fail report. The authoritative engine-level
 * test suite lives in src/__tests__/ and is executed via `bun run test`
 * (vitest). This route is intentionally a lightweight live-run endpoint for
 * the UI — it runs instantly in the browser with no test infrastructure.
 */
export async function GET() {
  try {
    const results = runAllTests();
    return NextResponse.json({
      success: results.failed === 0,
      summary: {
        overall: {
          total: results.passed + results.failed,
          passed: results.passed,
          failed: results.failed,
        },
      },
      results: results.results,
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
