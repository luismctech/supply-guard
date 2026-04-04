package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/engine"
	"github.com/AlbertoMZCruz/supply-guard/internal/report"
)

var watchFilePatterns = []string{
	"package.json", "package-lock.json", "npm-shrinkwrap.json",
	"requirements.txt", "Pipfile", "Pipfile.lock", "setup.py",
	"Cargo.toml", "Cargo.lock",
	"pom.xml", "build.gradle", "build.gradle.kts",
	"*.csproj", "*.sln",
	"supplyguard.yaml", ".npmrc",
}

func runWatch(dir string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot create watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(absDir); err != nil {
		return fmt.Errorf("cannot watch directory: %w", err)
	}
	addWorkflowDir(watcher, absDir)

	writeStreamEvent(os.Stdout, report.StreamEvent{
		Event:     "watch_started",
		Timestamp: time.Now().Format(time.RFC3339),
	})

	doScan(ctx, absDir)

	debounce := time.NewTimer(0)
	debounce.Stop()

	for {
		select {
		case <-ctx.Done():
			writeStreamEvent(os.Stdout, report.StreamEvent{
				Event:     "watch_stopped",
				Timestamp: time.Now().Format(time.RFC3339),
			})
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if isRelevantFile(event.Name) && (event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove)) != 0 {
				debounce.Reset(500 * time.Millisecond)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			writeStreamEvent(os.Stdout, report.StreamEvent{
				Event:     "error",
				Timestamp: time.Now().Format(time.RFC3339),
				Error:     err.Error(),
			})

		case <-debounce.C:
			doScan(ctx, absDir)
		}
	}
}

func doScan(ctx context.Context, dir string) {
	cfg, err := config.Load()
	if err != nil {
		writeStreamEvent(os.Stdout, report.StreamEvent{
			Event:     "error",
			Timestamp: time.Now().Format(time.RFC3339),
			Error:     "config error: " + err.Error(),
		})
		return
	}
	cfg.Quiet = true

	eng := engine.New(cfg)

	writeStreamEvent(os.Stdout, report.StreamEvent{
		Event:     "scan_started",
		Timestamp: time.Now().Format(time.RFC3339),
	})

	result, err := eng.Scan(ctx, dir)
	if err != nil {
		writeStreamEvent(os.Stdout, report.StreamEvent{
			Event:     "error",
			Timestamp: time.Now().Format(time.RFC3339),
			Error:     "scan failed: " + err.Error(),
		})
		return
	}

	for i := range result.Findings {
		result.Findings[i].Fingerprint = result.Findings[i].ComputeFingerprint()
	}
	report.EnrichWithFixes(result.Findings)

	for i := range result.Findings {
		writeStreamEvent(os.Stdout, report.StreamEvent{
			Event:     "finding",
			Timestamp: time.Now().Format(time.RFC3339),
			Finding:   &result.Findings[i],
		})
	}

	writeStreamEvent(os.Stdout, report.StreamEvent{
		Event:     "scan_complete",
		Timestamp: time.Now().Format(time.RFC3339),
		Summary:   &result.Summary,
		Duration:  result.Duration,
	})
}

func writeStreamEvent(w *os.File, evt report.StreamEvent) {
	data, _ := json.Marshal(evt)
	fmt.Fprintf(w, "%s\n", data)
}

func isRelevantFile(path string) bool {
	base := filepath.Base(path)
	for _, pattern := range watchFilePatterns {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")
}

func addWorkflowDir(watcher *fsnotify.Watcher, dir string) {
	wfDir := filepath.Join(dir, ".github", "workflows")
	if info, err := os.Stat(wfDir); err == nil && info.IsDir() {
		_ = watcher.Add(wfDir)
	}
}
