package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// The name-sniffing forwarder (settings.sniff; compile/render_sniff.go,
// internal/sniff). GET /api/sniff: the setting, what it covers and what
// stays address-only, and the forwarder's health and bounded recent
// decisions read through the host agent's parameterless status read.
// PUT /api/sniff: the setting (saved into the topology like every
// setting; it takes effect with the next gateway install).

// SniffRuntime is the host agent's forwarder status read (hostexec.Client
// in main).
type SniffRuntime interface {
	SniffStatus(ctx context.Context) (hostexec.SniffStatus, error)
}

type sniffSettingView struct {
	Enabled        bool     `json:"enabled"`
	Ports          []int    `json:"ports"`
	ECHPublicNames []string `json:"ech_public_names"`
	RecordNames    bool     `json:"record_names"`
	// Configured: the stored values (nil fields mean the defaults).
	Configured *model.SniffSettings `json:"configured,omitempty"`
}

type sniffRuntimeView struct {
	Available bool            `json:"available"`
	Code      string          `json:"code,omitempty"`
	Message   string          `json:"message,omitempty"`
	Present   bool            `json:"present"`
	Active    string          `json:"active,omitempty"`
	Health    json.RawMessage `json:"health,omitempty"`
	Recent    json.RawMessage `json:"recent,omitempty"`
	ReadAt    string          `json:"read_at,omitempty"`
}

// sniffCoverage is the plain-language split the panel and the import
// preview show (docs/architecture.md「按域名嗅探的转发」).
var sniffCoverage = struct {
	ByName      []string `json:"by_name"`
	AddressOnly []string `json:"address_only"`
	Costs       []string `json:"costs"`
}{
	ByName: []string{
		"局域网和远程接入设备新建的 TCP 连接，目的端口在接管列表里（默认 80、443），并且客户端在 1 秒内发出了 TLS ClientHello 的 SNI 或 HTTP/1 的 Host：按名字在有序规则表里自上而下匹配（关键词规则按子串生效），再由目标自己的解析器重新解析后连接",
	},
	AddressOnly: []string{
		"所有 UDP，包括 QUIC（UDP 443 仍由「走隧道的流量拒绝 UDP 443」开关处理）",
		"不在接管列表里的 TCP 端口",
		"读不到名字的 TCP：没有 SNI、SNI 是地址、HTTP/2 明文前言、非 TLS/HTTP 协议、服务器先说话的协议、超时、畸形或超长",
		"带 ECH 且明文名字是已知 ECH 公共名（默认 cloudflare-ech.com）的连接：真名字被加密，按目的地址",
		"目的是本机、局域网、私有地址、远程接入地址池或已知 DoH 地址的连接（不接管）",
		"接管之前已经建立的连接（只接管新连接的第一个 SYN）",
	},
	Costs: []string{
		"带 ECH 扩展、明文名字不在公共名列表里的连接按明文名字判断：浏览器发的 GREASE ECH 时这就是真名字；真正启用 ECH 而提供方的公共名不在列表里时，会按那个公共名分流（通常落到默认组）",
		"按名字判断的连接连接的是目标解析器给的地址，不是客户端自己解析到的地址",
		"所有被接管的连接经过网关上的用户态转发，占用网关的 CPU 和内存，并增加约一个往返的建立时延（服务器先说话的协议多等 1 秒）",
		"服务停止或崩溃时被接管的连接直接失败，不会回落到按地址的路径",
		"中继被淘汰时，转发服务已建立的连接不会像转发流量那样被立即重置，而是留在原中继上直到结束；新连接按新的权重分配",
	},
}

func sniffSetting(t model.Topology) sniffSettingView {
	s := t.Settings.Sniff
	v := sniffSettingView{Enabled: t.SniffOn(), Ports: s.EffectivePorts(), ECHPublicNames: s.EffectiveECHPublicNames(), Configured: s}
	if s != nil {
		v.RecordNames = s.RecordNames
	}
	return v
}

func (s *Server) getSniff(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := map[string]any{"setting": sniffSetting(t), "listen_port": validate.SniffListenPort, "coverage": sniffCoverage}
	rt := sniffRuntimeView{}
	switch {
	case s.Sniff == nil:
		rt.Code, rt.Message = "agent_unavailable", "没有配置 host agent，读不到嗅探服务的状态"
	default:
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		st, err := s.Sniff.SniffStatus(ctx)
		switch {
		case err != nil && errors.Is(err, hostexec.ErrUnavailable):
			rt.Code, rt.Message = "agent_unavailable", err.Error()
		case err != nil:
			rt.Code, rt.Message = "read_failed", err.Error()
		default:
			rt.Available, rt.Present, rt.Active, rt.Health, rt.Recent, rt.ReadAt = true, st.Present, st.Active, st.Health, st.Recent, st.ReadAt
			switch {
			case st.Error != "":
				rt.Code, rt.Message = "read_failed", st.Error
			case !st.Present && t.SniffOn():
				rt.Code, rt.Message = "not_running", "嗅探服务没有运行（还没有按开启后的拓扑安装到网关，或服务已停止）：被接管的连接此时都会失败"
			case st.Present && !t.SniffOn():
				rt.Code, rt.Message = "not_configured", "网关上仍在运行嗅探服务，但当前拓扑已关闭它：下一次安装会移除"
			}
		}
	}
	out["runtime"] = rt
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putSniff(w http.ResponseWriter, r *http.Request) {
	var b model.SniffSettings
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	t, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		v := b
		t.Settings.Sniff = &v
		return nil
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"setting": sniffSetting(t)})
}
