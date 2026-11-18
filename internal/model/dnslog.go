package model

// DNSLogSettings is the gateway's DNS query journal (internal/dnsjournal;
// docs/architecture.md「网关解析日志」). Nil or Enabled false: the gateway's
// SmartDNS writes no audit log, no reader runs and the compiled bundle is
// byte-identical to one without the setting.
//
// With it on, the gateway's SmartDNS config enables its audit log into a
// root-only directory on the gateway and "meridian dns-journal" turns the
// lines into a bounded record of the queries the gateway's resolver
// answered: time, the device's address (and MAC when known), the name, the
// query type, whether there was an answer, the resolver group, the time it
// took and the number of answer addresses. The record holds names, so this
// is an explicit switch, off by default, written only by PUT /api/dns-log
// and applied only by a gateway install (preflight, review, install).
// Turning it off stops the collection with the next install and deletes
// the records on the gateway once that install has succeeded.
type DNSLogSettings struct {
	Enabled bool `json:"enabled"`
}

// DNSLogOn reports whether the query journal is enabled.
func (t Topology) DNSLogOn() bool {
	return t.Settings.DNSLog != nil && t.Settings.DNSLog.Enabled
}
