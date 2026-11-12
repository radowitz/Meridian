package mesh

// Cloudflare client for the two resources a Mesh deployment owns.
//
// Checked against developers.cloudflare.com on 2026-11-12 (no call was made
// to the API from this repository; tests use an httptest fake built from
// these shapes):
//
//   - Mesh nodes (formerly WARP Connector), API reference
//     /api/resources/zero_trust/subresources/tunnels/subresources/warp_connector/
//     POST   /accounts/{account_id}/warp_connector            body {"name"}
//     GET    /accounts/{account_id}/warp_connector             list
//     GET    /accounts/{account_id}/warp_connector/{id}        result.status:
//     inactive | degraded | healthy | down
//     DELETE /accounts/{account_id}/warp_connector/{id}
//     GET    /accounts/{account_id}/warp_connector/{id}/token  result is a string
//     Guide: /mesh/guides/run-mesh-in-containers/ (MESH_NODE_TOKEN; "if token
//     retrieval fails after node creation, retry only the token request").
//   - CIDR routes, API reference
//     /api/resources/zero_trust/subresources/networks/subresources/routes/
//     POST   /accounts/{account_id}/teamnet/routes  body {network, tunnel_id,
//     comment (<=100 chars), virtual_network_id?}
//     GET    /accounts/{account_id}/teamnet/routes  query tunnel_id,
//     is_deleted, per_page (<=1000), page ...
//     DELETE /accounts/{account_id}/teamnet/routes/{route_id}
//     Guide: /mesh/features/routes/ (private or public CIDRs; one CIDR per
//     node or tunnel per virtual network; IPv6 routes need MASQUE).
//
// Every response is the v4 envelope {success, errors[{code,message}],
// messages, result}. Authentication: Authorization: Bearer <API token>.
//
// Minimum token permissions (account scope), per the reference pages:
//   - Cloudflare One Connectors Write: create, get, list, delete Mesh
//     nodes and read the node token. ("Cloudflare One Connector: WARP
//     Write" is accepted for create/get/delete, but the token page lists
//     only Connectors Write, Connector: cloudflared Write or Cloudflare
//     Tunnel Write, so Connectors Write is the safe single choice.)
//   - Cloudflare One Networks Write (or Cloudflare Tunnel Write): create,
//     list and delete routes.
//
// Not confirmed by the documentation and therefore handled defensively:
// the list endpoint of Mesh nodes documents no filters (we filter by our
// own unique name client side); the HTTP status for deleting an already
// deleted node or route (404 and an error envelope are both treated as
// "already gone" only when the follow-up GET/list no longer shows it);
// whether a default route can be published (BuildPlan refuses /0).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultAPIBase is Cloudflare's v4 API.
const DefaultAPIBase = "https://api.cloudflare.com/client/v4"

// Cloudflare is what the deployer needs from Cloudflare. CFClient is the
// HTTP implementation; tests may use a fake server behind CFClient.
type Cloudflare interface {
	CreateNode(ctx context.Context, name string) (CFNode, error)
	GetNode(ctx context.Context, id string) (CFNode, error)
	ListNodes(ctx context.Context) ([]CFNode, error)
	DeleteNode(ctx context.Context, id string) error
	NodeToken(ctx context.Context, id string) (string, error)
	CreateRoute(ctx context.Context, network, tunnelID, comment string) (CFRoute, error)
	ListRoutes(ctx context.Context, tunnelID string) ([]CFRoute, error)
	DeleteRoute(ctx context.Context, id string) error
}

// CFNode is the subset of a Mesh node object Meridian reads.
type CFNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	DeletedAt string `json:"deleted_at,omitempty"`
}

// CFRoute is the subset of a route object Meridian reads.
type CFRoute struct {
	ID        string `json:"id"`
	Network   string `json:"network"`
	TunnelID  string `json:"tunnel_id"`
	Comment   string `json:"comment"`
	DeletedAt string `json:"deleted_at,omitempty"`
}

// ErrNotFound is a 404 from Cloudflare.
var ErrNotFound = errors.New("cloudflare: not found")

// APIError is a failed Cloudflare call. It never contains the API token.
type APIError struct {
	Method string
	Path   string
	Status int
	Errors []string
}

func (e *APIError) Error() string {
	msg := strings.Join(e.Errors, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("Cloudflare %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, msg)
}

func (e *APIError) Unwrap() error {
	if e.Status == http.StatusNotFound {
		return ErrNotFound
	}
	return nil
}

var (
	accountRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tokenRe   = regexp.MustCompile(`^[A-Za-z0-9_\-]{20,200}$`)
)

// ValidAccountID: Cloudflare account ids are 32 hex characters.
func ValidAccountID(s string) bool { return accountRe.MatchString(s) }

// ValidAPIToken accepts the character set of Cloudflare API tokens without
// whitespace, so a pasted value cannot smuggle a header line.
func ValidAPIToken(s string) bool { return tokenRe.MatchString(s) }

// CFClient talks to the Cloudflare v4 API.
type CFClient struct {
	Base      string
	AccountID string
	Token     string
	HTTP      *http.Client
}

// NewCFClient validates the credential shape before any request.
func NewCFClient(cred Credentials) (*CFClient, error) {
	if !ValidAccountID(cred.AccountID) {
		return nil, errors.New("Cloudflare account id 应为 32 位十六进制")
	}
	if !ValidAPIToken(cred.APIToken) {
		return nil, errors.New("Cloudflare API token 格式无效")
	}
	return &CFClient{Base: DefaultAPIBase, AccountID: cred.AccountID, Token: cred.APIToken, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

type envelope struct {
	Success bool            `json:"success"`
	Errors  []cfMsg         `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *CFClient) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u := strings.TrimRight(c.Base, "/") + "/accounts/" + c.AccountID + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// url.Error carries the URL (no token) and the cause.
		return fmt.Errorf("Cloudflare %s %s: %w", method, path, stripURL(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var env envelope
	jsonErr := json.Unmarshal(raw, &env)
	if resp.StatusCode/100 != 2 || jsonErr != nil || !env.Success {
		ae := &APIError{Method: method, Path: path, Status: resp.StatusCode}
		for _, m := range env.Errors {
			ae.Errors = append(ae.Errors, fmt.Sprintf("%d %s", m.Code, m.Message))
		}
		if jsonErr != nil && resp.StatusCode/100 == 2 {
			ae.Errors = append(ae.Errors, "响应不是 Cloudflare v4 JSON")
		}
		return ae
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("Cloudflare %s %s: 结果无法解析: %v", method, path, err)
		}
	}
	return nil
}

func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func checkUUID(id string) error {
	if !uuidRe.MatchString(id) {
		return fmt.Errorf("Cloudflare id %q 不是 UUID", id)
	}
	return nil
}

func (c *CFClient) CreateNode(ctx context.Context, name string) (CFNode, error) {
	var n CFNode
	err := c.do(ctx, http.MethodPost, "/warp_connector", nil, map[string]any{"name": name}, &n)
	if err == nil && checkUUID(n.ID) != nil {
		return CFNode{}, errors.New("Cloudflare 创建 Mesh 节点没有返回有效 id")
	}
	return n, err
}

func (c *CFClient) GetNode(ctx context.Context, id string) (CFNode, error) {
	if err := checkUUID(id); err != nil {
		return CFNode{}, err
	}
	var n CFNode
	err := c.do(ctx, http.MethodGet, "/warp_connector/"+id, nil, nil, &n)
	return n, err
}

func (c *CFClient) ListNodes(ctx context.Context) ([]CFNode, error) {
	var out []CFNode
	err := c.do(ctx, http.MethodGet, "/warp_connector", nil, nil, &out)
	return out, err
}

func (c *CFClient) DeleteNode(ctx context.Context, id string) error {
	if err := checkUUID(id); err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/warp_connector/"+id, nil, nil, nil)
}

func (c *CFClient) NodeToken(ctx context.Context, id string) (string, error) {
	if err := checkUUID(id); err != nil {
		return "", err
	}
	var tok string
	if err := c.do(ctx, http.MethodGet, "/warp_connector/"+id+"/token", nil, nil, &tok); err != nil {
		return "", err
	}
	if tok == "" || strings.ContainsAny(tok, " \t\r\n'\"\\$`") {
		return "", errors.New("Cloudflare 返回的节点令牌为空或含有不允许的字符")
	}
	return tok, nil
}

func (c *CFClient) CreateRoute(ctx context.Context, network, tunnelID, comment string) (CFRoute, error) {
	if err := checkUUID(tunnelID); err != nil {
		return CFRoute{}, err
	}
	if len(comment) > 100 {
		comment = comment[:100]
	}
	var r CFRoute
	err := c.do(ctx, http.MethodPost, "/teamnet/routes", nil, map[string]any{"network": network, "tunnel_id": tunnelID, "comment": comment}, &r)
	if err == nil && checkUUID(r.ID) != nil {
		return CFRoute{}, errors.New("Cloudflare 创建路由没有返回有效 id")
	}
	return r, err
}

func (c *CFClient) ListRoutes(ctx context.Context, tunnelID string) ([]CFRoute, error) {
	if err := checkUUID(tunnelID); err != nil {
		return nil, err
	}
	q := url.Values{"tunnel_id": {tunnelID}, "is_deleted": {"false"}, "per_page": {"1000"}}
	var out []CFRoute
	err := c.do(ctx, http.MethodGet, "/teamnet/routes", q, nil, &out)
	return out, err
}

func (c *CFClient) DeleteRoute(ctx context.Context, id string) error {
	if err := checkUUID(id); err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/teamnet/routes/"+id, nil, nil, nil)
}
