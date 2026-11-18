package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Service groups (a switchable layer between rules and region groups,
// "service_groups" and Rule "target_service") no longer exist. A document
// that still has them is migrated when it is decoded, whatever the path
// (store, API body, fixture): every rule that went through a service group
// gets that group's target (region group, exit, direct or reject) and keeps
// its name in MihomoGroup; the groups, their select mode and probes are
// dropped and never written again. A rule whose service group is missing or
// has no target cannot be migrated and the decode fails with a message that
// names it. Decoding a migrated document again changes nothing.

type legacyServiceGroup struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TargetGroup  string `json:"target_group"`
	TargetExit   string `json:"target_exit"`
	TargetAction string `json:"target_action"`
}

type legacyTopology struct {
	ServiceGroups []legacyServiceGroup `json:"service_groups"`
	Rules         []struct {
		TargetService string `json:"target_service"`
	} `json:"rules"`
}

// UnmarshalJSON decodes a topology and migrates legacy service groups.
func (t *Topology) UnmarshalJSON(b []byte) error {
	type plain Topology
	p := plain(*t)
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*t = Topology(p)
	if !bytes.Contains(b, []byte(`"service_groups"`)) && !bytes.Contains(b, []byte(`"target_service"`)) {
		return nil
	}
	var lg legacyTopology
	if err := json.Unmarshal(b, &lg); err != nil {
		return err
	}
	return migrateServiceGroups(t, lg)
}

func migrateServiceGroups(t *Topology, lg legacyTopology) error {
	byID := map[string]legacyServiceGroup{}
	for _, s := range lg.ServiceGroups {
		byID[s.ID] = s
	}
	for i := range t.Rules {
		if i >= len(lg.Rules) || lg.Rules[i].TargetService == "" {
			continue
		}
		r := &t.Rules[i]
		s, ok := byID[lg.Rules[i].TargetService]
		if !ok || (s.TargetGroup == "" && s.TargetExit == "" && s.TargetAction == "") {
			return fmt.Errorf("规则「%s」指向的服务组 %s 不存在或没有目标，无法迁移为直接指向地区组；请先在旧版本中改正后再升级", r.Name, lg.Rules[i].TargetService)
		}
		r.TargetGroup, r.TargetExit, r.TargetAction = s.TargetGroup, s.TargetExit, s.TargetAction
		if r.MihomoGroup == "" {
			r.MihomoGroup = s.Name
		}
	}
	if m := t.MihomoImport; m != nil {
		for k, v := range m.Mapping {
			if strings.HasPrefix(v, "service:") {
				delete(m.Mapping, k)
			}
		}
	}
	return nil
}
