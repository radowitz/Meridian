package mesh

// Cloudflare token permission check (read-only).
//
// Checked against developers.cloudflare.com on 2026-11-13 (no call was
// made to the API from this repository; tests use an httptest fake):
//
//   - GET /accounts/{account_id}/tokens/verify — account-owned tokens;
//     result {id, status: active|disabled|expired, expires_on?, not_before?}.
//   - GET /user/tokens/verify — user-owned tokens, same result.
//   - GET /accounts/{account_id}/warp_connector — list Mesh nodes; accepts
//     Cloudflare One Connectors Write or Read, Cloudflare One Connector:
//     WARP Write or Read. Query per_page 1..1000.
//   - GET /accounts/{account_id}/teamnet/routes — list routes; accepts
//     Cloudflare One Networks Write or Read, Cloudflare Tunnel Write or Read.
//
// What this establishes: the token is valid and active, it is accepted for
// this account, and it can read Mesh nodes and routes there. What it
// cannot establish: write access. Both list endpoints accept the Read
// permission as well as Write, and the token's permission list can only be
// read with an extra "API Tokens Read" permission Meridian does not ask
// for. Proving write access would mean creating something; the check never
// does. A deployment's first write (creating the Mesh node) is where a
// missing write permission shows, and the deployment compensates.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
)

// Permission is one permission a Mesh deployment token needs.
type Permission struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Why   string `json:"why"`
}

// RequiredPermissions is what the token for Mesh deployment needs (the
// minimum documented on the endpoints the deployer calls).
var RequiredPermissions = []Permission{
	{Name: "Cloudflare One Connectors Write", Scope: "account",
		Why: "创建、查询、删除 Mesh 节点（warp_connector），读取节点令牌"},
	{Name: "Cloudflare One Networks Write", Scope: "account",
		Why: "发布、列出、撤回 CIDR 路由（teamnet/routes）"},
}

// TokenHowTo is the human-readable way to create the token.
var TokenHowTo = []string{
	"Cloudflare 控制台 → 管理账户 → 账户 API 令牌（Account API Tokens）→ 创建令牌 → 自定义令牌（Cloudflare 要求第一个 API token 在控制台创建）。",
	"权限只加两项，均为账户级：Cloudflare One Connectors · Edit/Write；Cloudflare One Networks · Edit/Write。",
	"账户资源选择要部署 Mesh 的那个账户；不需要任何区域（zone）权限。",
	"可选：设置客户端 IP 过滤为网关的出口 IP、设置到期时间。",
	"创建后把 token 和账户 id（32 位十六进制，在账户首页右侧）填进面板；token 只写不读。",
}

// Probe names.
const (
	ProbeVerify = "token_verify"
	ProbeNodes  = "read_mesh_nodes"
	ProbeRoutes = "read_routes"
)

// probeStatus classifies an error of a read call.
func probeStatus(err error) (string, string) {
	if err == nil {
		return "pass", ""
	}
	var ae *APIError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == http.StatusTooManyRequests || ae.Status >= 500:
			return "error", ae.Error()
		case ae.Status >= 400:
			return "denied", ae.Error()
		default:
			return "error", ae.Error()
		}
	}
	return "error", err.Error()
}

type verifyResult struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresOn string `json:"expires_on"`
}

// CheckPermissions runs the read-only check. It never creates, changes or
// deletes anything, and its result never contains the token.
func (c *CFClient) CheckPermissions(ctx context.Context) credentials.PermissionCheck {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	pc := credentials.PermissionCheck{
		Unconfirmed: []string{
			"写权限（创建 / 删除 Mesh 节点、读取节点令牌、发布 / 撤回路由）：列表接口同时接受 Read 与 Write 权限，只读检查无法区分；读取 token 的权限清单需要额外的「API Tokens Read」权限，Meridian 不要求也不读取。缺少写权限会在部署的「创建 Cloudflare 节点」阶段失败，部署会撤回已创建的内容。",
		},
	}
	// 1. Token validity: account-owned first, then user-owned.
	verify := credentials.PermissionProbe{Name: ProbeVerify, Endpoint: "GET /accounts/{account_id}/tokens/verify"}
	var vr verifyResult
	err := c.doAbs(ctx, http.MethodGet, "/accounts/"+c.AccountID+"/tokens/verify", "/tokens/verify", nil, nil, &vr)
	if err == nil {
		pc.TokenKind = "account"
	} else if st, _ := probeStatus(err); st == "denied" {
		var ur verifyResult
		uerr := c.doAbs(ctx, http.MethodGet, "/user/tokens/verify", "/user/tokens/verify", nil, nil, &ur)
		if uerr == nil {
			vr, err, pc.TokenKind = ur, nil, "user"
			verify.Endpoint = "GET /user/tokens/verify"
		}
	}
	verify.Status, verify.Detail = probeStatus(err)
	if err == nil {
		pc.TokenStatus = vr.Status
		if vr.Status != "active" {
			verify.Status = "denied"
			verify.Detail = fmt.Sprintf("token 状态是 %q，不是 active", vr.Status)
		} else {
			kind := "账户令牌"
			if pc.TokenKind == "user" {
				kind = "用户令牌"
			}
			verify.Detail = "token 有效（" + kind + "）"
			if vr.ExpiresOn != "" {
				verify.Detail += "，到期 " + vr.ExpiresOn
			}
			pc.Confirmed = append(pc.Confirmed, verify.Detail)
		}
	}
	if verify.Status == "denied" {
		pc.Missing = append(pc.Missing, "有效且处于 active 状态的 API token")
	}
	pc.Checks = append(pc.Checks, verify)

	// 2. Mesh nodes (Connectors), 3. routes (Networks): read calls only.
	nodes := credentials.PermissionProbe{Name: ProbeNodes, Endpoint: "GET /accounts/{account_id}/warp_connector"}
	var nl []CFNode
	err = c.do(ctx, http.MethodGet, "/warp_connector", url.Values{"per_page": {"1"}}, nil, &nl)
	nodes.Status, nodes.Detail = probeStatus(err)
	if err == nil {
		nodes.Detail = "可以读取这个账户的 Mesh 节点（Connectors Read 或 Write）"
		pc.Confirmed = append(pc.Confirmed, nodes.Detail)
	} else if nodes.Status == "denied" {
		pc.Missing = append(pc.Missing, RequiredPermissions[0].Name)
	}
	pc.Checks = append(pc.Checks, nodes)

	routes := credentials.PermissionProbe{Name: ProbeRoutes, Endpoint: "GET /accounts/{account_id}/teamnet/routes"}
	var rl []CFRoute
	err = c.do(ctx, http.MethodGet, "/teamnet/routes", url.Values{"per_page": {"1"}, "is_deleted": {"false"}}, nil, &rl)
	routes.Status, routes.Detail = probeStatus(err)
	if err == nil {
		routes.Detail = "可以读取这个账户的路由（Networks Read 或 Write）"
		pc.Confirmed = append(pc.Confirmed, routes.Detail)
	} else if routes.Status == "denied" {
		pc.Missing = append(pc.Missing, RequiredPermissions[1].Name)
	}
	pc.Checks = append(pc.Checks, routes)

	pc.OK = true
	var bad []string
	for _, p := range pc.Checks {
		if p.Status != "pass" {
			pc.OK = false
			bad = append(bad, p.Name+"="+p.Status)
		}
	}
	switch {
	case pc.OK:
		pc.Detail = "token 有效，能读取 Mesh 节点和路由；写权限未能用只读检查证明（见 unconfirmed）。"
	case len(pc.Missing) > 0:
		pc.Detail = "Cloudflare 拒绝了部分检查：" + strings.Join(bad, ", ") + "。按 required_permissions 重新创建或修改 token。"
	default:
		pc.Detail = "检查没有完成（网络或 Cloudflare 错误）：" + strings.Join(bad, ", ") + "。这不说明权限缺失，稍后重试。"
	}
	return pc
}
