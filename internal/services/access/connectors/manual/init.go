package manual

import "github.com/kennguy3n/fishbone-access/internal/services/access"

// init registers the manual connector against the process-global registry.
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}
