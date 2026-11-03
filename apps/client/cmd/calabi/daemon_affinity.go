package main

import (
	"flag"
	"strings"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

func persistStartupEdgeAffinity(fs *flag.FlagSet, affinity string) error {
	affinity = strings.ToLower(strings.TrimSpace(affinity))
	if affinity != "own" && affinity != "platform" {
		return nil
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "edge-affinity" {
			explicit = true
		}
	})
	c, err := creds.Load()
	if err != nil {
		return err
	}
	if c.EdgeAffinitySelected && !explicit {
		return nil
	}
	preferPlatform := affinity == "platform"
	changed := c.PreferPlatformEdge != preferPlatform
	if !changed && (!explicit || c.EdgeAffinitySelected) {
		return nil
	}
	if changed {
		c.PreferPlatformEdge = preferPlatform
		c.LastEdgeNodeID = 0
		c.LastEdgeRegion = ""
		c.EdgeRegion = ""
	}
	if explicit {
		c.EdgeAffinitySelected = true
	}
	return creds.Save(c)
}
