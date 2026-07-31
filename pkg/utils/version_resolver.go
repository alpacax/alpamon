package utils

// DefaultVersionResolver implements common.VersionResolver using
// real GitHub API calls and system package queries.
type DefaultVersionResolver struct{}

func NewDefaultVersionResolver() *DefaultVersionResolver {
	return &DefaultVersionResolver{}
}

func (r *DefaultVersionResolver) GetLatestVersion(proxyURL string) string {
	return GetLatestVersion(proxyURL)
}

func (r *DefaultVersionResolver) GetPamVersion() string {
	return GetPamVersion()
}

func (r *DefaultVersionResolver) InvalidatePamCache() {
	InvalidatePamCache()
}
