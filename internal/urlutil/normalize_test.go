// Ported 1:1 from src/utils.test.ts.
package urlutil_test

import (
	"testing"

	"github.com/paambaati/kongcheck/internal/urlutil"
)

func expectNormalized(t *testing.T, input, want, msg string) {
	t.Helper()
	if got := urlutil.NormalizePath(input); got != want {
		t.Errorf("%s: NormalizePath(%q) = %q, want %q", msg, input, got, want)
	}
}

// normalizeNoPanic calls NormalizePath and reports a panic as a test failure
// (the Go analogue of "never throws"). Go strings are always strings, so the
// TS `typeof result === 'string'` check is satisfied by the type system.
func normalizeNoPanic(t *testing.T, input, msg string) (result string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: NormalizePath(%q) panicked: %v", msg, input, r)
		}
	}()
	return urlutil.NormalizePath(input)
}

func TestNormalizePath(t *testing.T) {
	t.Run("normalizePath", func(t *testing.T) {
		t.Run("query-string stripping", func(t *testing.T) {
			t.Run("strips a query string from a plain path", func(t *testing.T) {
				expectNormalized(t, "/api/v1/users?debug=1", "/api/v1/users", "query string must be stripped")
			})

			t.Run("strips a query string with multiple parameters", func(t *testing.T) {
				expectNormalized(t, "/search?q=hello&page=2", "/search", "full query string must be stripped")
			})

			t.Run("returns the original path unchanged when there is no query string", func(t *testing.T) {
				expectNormalized(t, "/api/v1/users", "/api/v1/users", "clean path must not be altered")
			})
		})

		t.Run("fragment stripping", func(t *testing.T) {
			t.Run("strips a URL fragment", func(t *testing.T) {
				expectNormalized(t, "/docs/guide#installation", "/docs/guide", "fragment must be stripped")
			})

			t.Run("strips both a query string and a fragment", func(t *testing.T) {
				expectNormalized(t, "/page?foo=1#section", "/page", "query string and fragment must both be stripped")
			})
		})

		t.Run("percent-encoding preservation", func(t *testing.T) {
			t.Run("preserves percent-encoded characters unchanged", func(t *testing.T) {
				// Kong matches the raw URI; /hello%20world and /hello world are distinct.
				expectNormalized(t, "/api/v1/hello%20world", "/api/v1/hello%20world", "percent encoding must be preserved")
			})

			t.Run("strips a query string while preserving percent-encoding in the path", func(t *testing.T) {
				expectNormalized(t, "/api/v1/hello%20world?debug=1", "/api/v1/hello%20world",
					"query string must be stripped but encoding must be left intact")
			})
		})

		t.Run("dot-segment resolution", func(t *testing.T) {
			t.Run("resolves a single-dot segment", func(t *testing.T) {
				expectNormalized(t, "/api/v1/./users", "/api/v1/users", "single-dot segment must be removed")
			})

			t.Run("resolves double-dot parent traversal", func(t *testing.T) {
				expectNormalized(t, "/api/v1/../v2/users", "/api/v2/users", "double-dot must navigate to parent")
			})

			t.Run("handles consecutive double-dot at the root", func(t *testing.T) {
				expectNormalized(t, "/a/b/../../c", "/c", "traversal past root must stop at root")
			})
		})

		t.Run("clean-path passthrough", func(t *testing.T) {
			t.Run("preserves a clean root path", func(t *testing.T) {
				expectNormalized(t, "/", "/", "root path must be preserved unchanged")
			})

			t.Run("preserves a clean multi-segment path", func(t *testing.T) {
				expectNormalized(t, "/payments/checkout", "/payments/checkout", "clean path must be returned as-is")
			})
		})

		t.Run("malformed / edge-case input", func(t *testing.T) {
			t.Run("always returns a string, never throws", func(t *testing.T) {
				weird := "relative-no-slash"
				var result any = normalizeNoPanic(t, weird, "result must always be a string")
				if _, ok := result.(string); !ok {
					t.Errorf("result must always be a string: got %T, want string", result)
				}
			})

			t.Run("handles empty input without throwing", func(t *testing.T) {
				var result any = normalizeNoPanic(t, "", "result must be a string even for empty input")
				if _, ok := result.(string); !ok {
					t.Errorf("result must be a string even for empty input: got %T, want string", result)
				}
			})
		})
	})
}
