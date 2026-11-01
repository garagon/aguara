package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	"github.com/garagon/aguara/internal/kubeconfig"
)

type privilegeMemo struct {
	mu     sync.Mutex
	ready  bool
	result *kubeconfig.PrivilegeAnalysis
}

// PrivilegeAnalysis shares bounded, read-only evidence for this loaded target.
// Like StringContent, it requires immutable content/path during analysis. It
// retains no parser tree, has no cross-target lifetime, and never caches errors.
func (t *Target) PrivilegeAnalysis(ctx context.Context) (*kubeconfig.PrivilegeAnalysis, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.privilege.mu.Lock()
	defer t.privilege.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.privilege.ready {
		return t.privilege.result, nil
	}
	if t.Content == nil {
		return nil, nil // Do not memoize a target before LoadContent.
	}
	ext := strings.ToLower(filepath.Ext(t.RelPath))
	var result *kubeconfig.PrivilegeAnalysis
	if (ext == ".json" || ext == ".yaml" || ext == ".yml") && len(t.SourceContent()) <= kubeconfig.MaxBytes {
		content := t.StringContent()
		if string(t.SourceContent()) == content {
			var err error
			result, err = kubeconfig.AnalyzePrivileges(ctx, content, ext)
			if err != nil {
				return nil, err
			}
		}
	}
	t.privilege.result, t.privilege.ready = result, true
	return result, nil
}
