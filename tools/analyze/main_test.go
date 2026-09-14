package main

import (
	"testing"

	"golang.org/x/tools/go/analysis"
)

func TestAnalyzersAreValid(t *testing.T) {
	list := analyzers()
	if len(list) == 0 {
		t.Fatal("no analyzers registered")
	}
	if err := analysis.Validate(list); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestAnalyzerNamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, a := range analyzers() {
		if seen[a.Name] {
			t.Errorf("duplicate analyzer %q", a.Name)
		}
		seen[a.Name] = true
	}
}
