import { NextResponse } from "next/server";
import { runAllTests } from "@/__tests__/engineTests";
import { runE2ETests } from "@/__tests__/e2eTests";

export async function GET() {
  try {
    console.log("Running WAFSim Test Suite...\n");
    
    // Run unit tests
    console.log("--- Unit Tests ---");
    const unitResults = runAllTests();
    
    // Run E2E tests
    console.log("\n--- E2E Tests ---");
    const e2eResults = runE2ETests();
    
    const allPassed = unitResults.failed === 0 && e2eResults.failed === 0;
    
    return NextResponse.json({
      success: allPassed,
      summary: {
        unitTests: {
          total: unitResults.passed + unitResults.failed,
          passed: unitResults.passed,
          failed: unitResults.failed,
        },
        e2eTests: {
          total: e2eResults.passed + e2eResults.failed,
          passed: e2eResults.passed,
          failed: e2eResults.failed,
        },
        overall: {
          total: unitResults.passed + unitResults.failed + e2eResults.passed + e2eResults.failed,
          passed: unitResults.passed + e2eResults.passed,
          failed: unitResults.failed + e2eResults.failed,
        },
      },
      unitTestResults: unitResults.results,
      e2eTestResults: e2eResults.results,
    });
  } catch (error) {
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : String(error),
    }, { status: 500 });
  }
}
