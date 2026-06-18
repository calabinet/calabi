package listener

import (
	"io"

	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
)

// wrapHeaderRewrite forwards the visitor→client byte stream unchanged: this
// build does not rewrite request headers. (Callers gate on
// pol.HasRequestHeaders(), which is always false here, so it is never invoked;
// it exists so the listeners compile.)
func wrapHeaderRewrite(src io.Reader, _ *policy.Policy, _ []byte) io.Reader {
	return src
}
