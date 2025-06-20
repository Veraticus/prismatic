package database

import (
	"testing"
)

func TestScannerFlag(t *testing.T) {
	tests := []struct {
		name     string
		flag     ScannerFlag
		scanner  ScannerFlag
		expected bool
	}{
		{
			name:     "single scanner",
			flag:     ScannerProwler,
			scanner:  ScannerProwler,
			expected: true,
		},
		{
			name:     "multiple scanners",
			flag:     ScannerProwler | ScannerTrivy,
			scanner:  ScannerTrivy,
			expected: true,
		},
		{
			name:     "scanner not present",
			flag:     ScannerProwler,
			scanner:  ScannerTrivy,
			expected: false,
		},
		{
			name:     "all scanners",
			flag:     ScannerProwler | ScannerTrivy | ScannerKubescape | ScannerNuclei | ScannerGitleaks | ScannerCheckov,
			scanner:  ScannerNuclei,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.HasScanner(tt.scanner); got != tt.expected {
				t.Errorf("HasScanner() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScannerFlagOperations(t *testing.T) {
	t.Run("AddScanner", func(t *testing.T) {
		var flag ScannerFlag
		flag.AddScanner(ScannerProwler)
		if !flag.HasScanner(ScannerProwler) {
			t.Error("Expected Prowler to be enabled")
		}

		flag.AddScanner(ScannerTrivy)
		if !flag.HasScanner(ScannerTrivy) {
			t.Error("Expected Trivy to be enabled")
		}
		if !flag.HasScanner(ScannerProwler) {
			t.Error("Expected Prowler to still be enabled")
		}
	})

	t.Run("RemoveScanner", func(t *testing.T) {
		flag := ScannerProwler | ScannerTrivy | ScannerKubescape

		flag.RemoveScanner(ScannerTrivy)
		if flag.HasScanner(ScannerTrivy) {
			t.Error("Expected Trivy to be disabled")
		}
		if !flag.HasScanner(ScannerProwler) {
			t.Error("Expected Prowler to still be enabled")
		}
		if !flag.HasScanner(ScannerKubescape) {
			t.Error("Expected Kubescape to still be enabled")
		}
	})
}

func TestGetEnabledScanners(t *testing.T) {
	tests := []struct {
		name     string
		expected []string
		flag     ScannerFlag
	}{
		{
			name:     "no scanners",
			flag:     0,
			expected: []string{},
		},
		{
			name:     "single scanner",
			flag:     ScannerProwler,
			expected: []string{ScannerNameProwler},
		},
		{
			name:     "multiple scanners",
			flag:     ScannerProwler | ScannerTrivy | ScannerNuclei,
			expected: []string{ScannerNameProwler, ScannerNameTrivy, ScannerNameNuclei},
		},
		{
			name: "all scanners",
			flag: ScannerProwler | ScannerTrivy | ScannerKubescape | ScannerNuclei | ScannerGitleaks | ScannerCheckov,
			expected: []string{
				ScannerNameProwler,
				ScannerNameTrivy,
				ScannerNameKubescape,
				ScannerNameNuclei,
				ScannerNameGitleaks,
				ScannerNameCheckov,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flag.GetEnabledScanners()
			if len(got) != len(tt.expected) {
				t.Errorf("GetEnabledScanners() returned %d scanners, want %d", len(got), len(tt.expected))
				return
			}

			// Create a map for easy lookup
			expectedMap := make(map[string]bool)
			for _, s := range tt.expected {
				expectedMap[s] = true
			}

			for _, s := range got {
				if !expectedMap[s] {
					t.Errorf("GetEnabledScanners() returned unexpected scanner: %s", s)
				}
				delete(expectedMap, s)
			}

			if len(expectedMap) > 0 {
				t.Errorf("GetEnabledScanners() missing scanners: %v", expectedMap)
			}
		})
	}
}

func TestScannerFlagFromNames(t *testing.T) {
	tests := []struct {
		name     string
		names    []string
		expected ScannerFlag
	}{
		{
			name:     "empty list",
			names:    []string{},
			expected: 0,
		},
		{
			name:     "single scanner",
			names:    []string{ScannerNameProwler},
			expected: ScannerProwler,
		},
		{
			name:     "multiple scanners",
			names:    []string{ScannerNameProwler, ScannerNameTrivy, ScannerNameNuclei},
			expected: ScannerProwler | ScannerTrivy | ScannerNuclei,
		},
		{
			name:     "unknown scanner ignored",
			names:    []string{ScannerNameProwler, "unknown", ScannerNameTrivy},
			expected: ScannerProwler | ScannerTrivy,
		},
		{
			name: "all scanners",
			names: []string{
				ScannerNameProwler,
				ScannerNameTrivy,
				ScannerNameKubescape,
				ScannerNameNuclei,
				ScannerNameGitleaks,
				ScannerNameCheckov,
			},
			expected: ScannerProwler | ScannerTrivy | ScannerKubescape | ScannerNuclei | ScannerGitleaks | ScannerCheckov,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScannerFlagFromNames(tt.names)
			if got != tt.expected {
				t.Errorf("ScannerFlagFromNames() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScannerFlagRoundTrip(t *testing.T) {
	// Test that converting from names to flags and back preserves the data
	originalNames := []string{
		ScannerNameProwler,
		ScannerNameKubescape,
		ScannerNameCheckov,
	}

	flag := ScannerFlagFromNames(originalNames)
	resultNames := flag.GetEnabledScanners()

	if len(resultNames) != len(originalNames) {
		t.Errorf("Round trip changed number of scanners: %d -> %d", len(originalNames), len(resultNames))
	}

	// Create maps for comparison
	originalMap := make(map[string]bool)
	for _, name := range originalNames {
		originalMap[name] = true
	}

	for _, name := range resultNames {
		if !originalMap[name] {
			t.Errorf("Round trip produced unexpected scanner: %s", name)
		}
	}
}
