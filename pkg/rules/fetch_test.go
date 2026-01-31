package rules_test

import (
	"testing"

	"github.com/movsb/gun/pkg/rules"
)

func TestFetch(t *testing.T) {
	t.SkipNow()
	rules.UpdateChinaDomains(t.Context(), `.`)
	rules.UpdateGFWDomains(t.Context(), `.`)
	rules.UpdateChinaRoutes(t.Context(), `.`)
}
