package tests

// DiscoveryResult contiene los endpoints y parámetros encontrados
type DiscoveryResult struct {
	Endpoints map[string]*EndpointInfo
	BaseURL   string
}

// EndpointInfo describe un endpoint encontrado
type EndpointInfo struct {
	Path    string
	Methods []string
	Params  []string // Nombres de parámetros (GET/POST)
}
