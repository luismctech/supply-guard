package npm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractImportNames_Require(t *testing.T) {
	imports := make(map[string]bool)
	code := `const express = require('express');
const _ = require("lodash");
const local = require('./local');
const sub = require('@scope/pkg/sub');
`
	extractImportNames(code, imports)

	want := map[string]bool{"express": true, "lodash": true, "@scope/pkg": true}
	for name := range want {
		if !imports[name] {
			t.Errorf("expected import %q to be found", name)
		}
	}

	if imports["./local"] {
		t.Error("relative imports should not be included")
	}
}

func TestExtractImportNames_ESModules(t *testing.T) {
	imports := make(map[string]bool)
	code := `import React from 'react';
import { useState } from "react";
import 'side-effect';
import defaultExport from '@org/lib/sub';
`
	extractImportNames(code, imports)

	if !imports["react"] {
		t.Error("expected 'react' import")
	}
	if !imports["side-effect"] {
		t.Error("expected 'side-effect' import")
	}
	if !imports["@org/lib"] {
		t.Error("expected '@org/lib' import")
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"express", "express"},
		{"express/router", "express"},
		{"@scope/pkg", "@scope/pkg"},
		{"@scope/pkg/sub", "@scope/pkg"},
	}

	for _, tt := range tests {
		got := extractPackageName(tt.input)
		if got != tt.want {
			t.Errorf("extractPackageName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCheckPhantomDeps_DetectsUnused(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"test","dependencies":{"express":"^4.0.0","unused-lib":"^1.0.0"}}`
	src := `const express = require('express');`

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	pf := loadProjectFiles(dir)
	findings := checkPhantomDeps(pf)
	found := false
	for _, f := range findings {
		if f.Package == "unused-lib" {
			found = true
		}
	}
	if !found {
		t.Error("expected phantom dependency finding for 'unused-lib'")
	}

	for _, f := range findings {
		if f.Package == "express" {
			t.Error("express is imported and should not be flagged as phantom")
		}
	}
}
