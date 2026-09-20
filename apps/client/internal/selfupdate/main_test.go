package selfupdate

import (
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/testhome"
)

// The per-user directories are sandboxed for this package's tests; see testhome.
func TestMain(m *testing.M) { testhome.Main(m) }
