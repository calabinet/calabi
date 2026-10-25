package localweb

import (
	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"net/http"
)

func (s *Server) handleInboundCheck(w http.ResponseWriter, r *http.Request) {
	mesh.InboundPolicyHandler(s.cfg.Mesh)(w, r)
}
