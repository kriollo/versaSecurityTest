package scanner

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/versaSecurityTest/internal/scanner/tests"
	"golang.org/x/net/html"
)

// Crawler realiza el descubrimiento de la aplicación
type Crawler struct {
	client     tests.HTTPClient
	maxDepth   int
	maxPages   int
	visited    map[string]bool
	visitedMux sync.Mutex
	results    *tests.DiscoveryResult
}

// NewCrawler crea un nuevo crawler
func NewCrawler(client tests.HTTPClient) *Crawler {
	return &Crawler{
		client:   client,
		maxDepth: 3,
		maxPages: 50,
		visited:  make(map[string]bool),
		results: &tests.DiscoveryResult{
			Endpoints: make(map[string]*tests.EndpointInfo),
		},
	}
}

// Discover inicia el proceso de descubrimiento
func (c *Crawler) Discover(ctx context.Context, startURL string) (*tests.DiscoveryResult, error) {
	u, err := url.Parse(startURL)
	if err != nil {
		return nil, err
	}
	c.results.BaseURL = u.Scheme + "://" + u.Host

	c.crawl(ctx, startURL, 0)

	return c.results, nil
}

func (c *Crawler) crawl(ctx context.Context, targetURL string, depth int) {
	if depth > c.maxDepth {
		return
	}

	c.visitedMux.Lock()
	if c.visited[targetURL] || len(c.visited) >= c.maxPages {
		c.visitedMux.Unlock()
		return
	}
	c.visited[targetURL] = true
	c.visitedMux.Unlock()

	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := c.client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	// Analizar el contenido para buscar enlaces y formularios
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return
	}

	// Extraer información del endpoint actual
	u, _ := url.Parse(targetURL)
	path := u.Path
	if path == "" {
		path = "/"
	}

	c.visitedMux.Lock()
	if _, ok := c.results.Endpoints[path]; !ok {
		c.results.Endpoints[path] = &tests.EndpointInfo{
			Path:    path,
			Methods: []string{"GET"},
		}
	}
	// Extraer parámetros de la URL actual
	for param := range u.Query() {
		c.addParam(path, param)
	}
	c.visitedMux.Unlock()

	// Buscar más enlaces y formularios recursivamente
	c.extractLinks(ctx, doc, depth)
}

func (c *Crawler) extractLinks(ctx context.Context, n *html.Node, depth int) {
	if n.Type == html.ElementNode {
		if n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					link := c.resolveURL(a.Val)
					if link != "" && strings.HasPrefix(link, c.results.BaseURL) {
						go c.crawl(ctx, link, depth+1)
					}
				}
			}
		}
		if n.Data == "form" {
			action := ""
			method := "GET"
			for _, a := range n.Attr {
				if a.Key == "action" {
					action = c.resolveURL(a.Val)
				}
				if a.Key == "method" {
					method = strings.ToUpper(a.Val)
				}
			}
			if action != "" && strings.HasPrefix(action, c.results.BaseURL) {
				u, _ := url.Parse(action)
				c.visitedMux.Lock()
				if info, ok := c.results.Endpoints[u.Path]; ok {
					found := false
					for _, m := range info.Methods {
						if m == method {
							found = true
							break
						}
					}
					if !found {
						info.Methods = append(info.Methods, method)
					}
				} else {
					c.results.Endpoints[u.Path] = &tests.EndpointInfo{
						Path:    u.Path,
						Methods: []string{method},
					}
				}
				c.visitedMux.Unlock()
				c.extractFormParams(u.Path, n)
			}
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		c.extractLinks(ctx, child, depth)
	}
}

func (c *Crawler) extractFormParams(path string, n *html.Node) {
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
			for _, a := range n.Attr {
				if a.Key == "name" {
					c.visitedMux.Lock()
					c.addParam(path, a.Val)
					c.visitedMux.Unlock()
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
}

func (c *Crawler) addParam(path, param string) {
	info := c.results.Endpoints[path]
	for _, p := range info.Params {
		if p == param {
			return
		}
	}
	info.Params = append(info.Params, param)
}

func (c *Crawler) resolveURL(href string) string {
	if strings.HasPrefix(href, "http") {
		return href
	}
	u, err := url.Parse(c.results.BaseURL)
	if err != nil {
		return ""
	}
	rel, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return u.ResolveReference(rel).String()
}
