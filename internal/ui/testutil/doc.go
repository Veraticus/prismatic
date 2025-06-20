// Package testutil provides comprehensive testing utilities for Prismatic TUI components.
//
// The package includes helpers for:
//   - Creating test data (scans, findings, etc.)
//   - Simulating user input and key presses
//   - Comparing and asserting view outputs
//   - Setting up test databases
//   - Mocking messages and events
//
// # Basic Usage
//
//	import "github.com/joshsymonds/prismatic/internal/ui/testutil"
//
//	func TestMyComponent(t *testing.T) {
//	    // Create test database
//	    db := testutil.CreateMemoryDB(t)
//
//	    // Create test data
//	    scan := testutil.CreateTestScan(t, db, "test-profile", database.ScanStatusCompleted)
//	    findings := testutil.CreateTestFindings(t, db, scan.ID, 10)
//
//	    // Create component
//	    component := NewMyComponent()
//	    component.SetDatabase(db)
//
//	    // Simulate user input
//	    model, cmd := testutil.SimulateKeyPress(component, "j")
//
//	    // Assert view contents
//	    view := model.View()
//	    testutil.AssertViewContains(t, view, []string{"Expected", "Content"})
//	}
//
// # Testing Views
//
// The package provides multiple utilities for testing rendered views:
//
//	// Strip ANSI codes for comparison
//	cleanView := testutil.StripANSI(view)
//
//	// Compare views with normalization
//	testutil.CompareViews(t, expectedView, actualView)
//
//	// Extract specific portions
//	table := testutil.ExtractTable(view, "Header")
//	testutil.AssertTableRowCount(t, view, "Header", 5)
//
// # Simulating Input
//
// Simulate various key presses and messages:
//
//	// Keyboard input
//	model, _ = testutil.SimulateKeyPress(model, "enter")
//	model, _ = testutil.SimulateKeyPress(model, "esc")
//	model, _ = testutil.SimulateKeyPress(model, "j")  // Regular key
//
//	// Mock messages
//	messages := testutil.CreateMockMessages()
//	model, _ = model.Update(messages["scanner_status"])
//
// # Test Data Generation
//
// Generate realistic test data:
//
//	// Create findings with various severities
//	findings := testutil.CreateTestModelsFindings(20)
//
//	// Create scan history
//	history := testutil.CreateTestScanHistory(t, db, 5)
//
//	// Create scanner status
//	status := testutil.CreateTestScannerStatus("trivy", "running")
package testutil
