package benchmark

import "fmt"

// NewProvider constructs the matching platform adapter for a benchmark session.
func NewProvider(kind, baseURL, token string, cfg SessionConfig) (Provider, error) {
	switch kind {
	case "tsecbench":
		return NewTSecBenchClient(baseURL, token), nil
	case "ctf2":
		return NewCTF2Client(baseURL, token, cfg), nil
	case "generic_mcp":
		return NewGenericMCPClient(baseURL, token, cfg), nil
	default:
		return nil, fmt.Errorf("unknown benchmark provider %q", kind)
	}
}
