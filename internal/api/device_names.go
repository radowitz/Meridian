package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cachedDeviceName struct {
	name    string
	expires time.Time
}

type deviceNameCache struct {
	mu      sync.Mutex
	entries map[string]cachedDeviceName
	slots   chan struct{}
}

func (v *sniffJournalView) sourceAddresses() []string {
	var page struct {
		Active, Records []struct{ Source string }
	}
	var summary struct{ Devices []struct{ Device string } }
	_ = json.Unmarshal(v.Page, &page)
	_ = json.Unmarshal(v.Summary, &summary)
	addresses := make([]string, 0, len(page.Active)+len(page.Records)+len(summary.Devices))
	for _, row := range page.Active {
		addresses = append(addresses, row.Source)
	}
	for _, row := range page.Records {
		addresses = append(addresses, row.Source)
	}
	for _, row := range summary.Devices {
		addresses = append(addresses, row.Device)
	}
	return addresses
}

func (c *deviceNameCache) lookup(ctx context.Context, addresses []string) map[string]string {
	wanted := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		ip, err := netip.ParseAddr(address)
		if err == nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) && ip.Zone() == "" {
			wanted[address] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	now := time.Now()
	names := make(map[string]string)
	readDHCPNames(wanted, names, now)
	ctx, cancel := context.WithTimeout(ctx, 180*time.Millisecond)
	defer cancel()

	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[string]cachedDeviceName)
		c.slots = make(chan struct{}, 12)
	}
	var pending []string
	for _, address := range addresses {
		if _, ok := wanted[address]; !ok {
			continue
		}
		delete(wanted, address)
		if names[address] != "" {
			continue
		}
		if entry, ok := c.entries[address]; ok && now.Before(entry.expires) {
			if entry.name != "" {
				names[address] = entry.name
			}
		} else if len(pending) < cap(c.slots) {
			pending = append(pending, address)
		}
	}
	c.mu.Unlock()

	results := make(chan struct {
		address, name string
	}, len(pending))
	started := 0
	for _, address := range pending {
		select {
		case c.slots <- struct{}{}:
			started++
		default:
			continue
		}
		go func(address string) {
			defer func() { <-c.slots }()
			ptr, _ := net.DefaultResolver.LookupAddr(ctx, address)
			name := ""
			for _, candidate := range ptr {
				if name = deviceHostname(candidate); name != "" {
					break
				}
			}
			ttl := 45 * time.Second
			if name != "" {
				ttl = 5 * time.Minute
			}
			c.mu.Lock()
			if len(c.entries) >= 2048 {
				for key, entry := range c.entries {
					if !now.Before(entry.expires) {
						delete(c.entries, key)
					}
				}
				if len(c.entries) >= 2048 {
					clear(c.entries)
				}
			}
			c.entries[address] = cachedDeviceName{name, now.Add(ttl)}
			c.mu.Unlock()
			results <- struct{ address, name string }{address, name}
		}(address)
	}
	// A full lookup pool may reject some of the requested lookups.
	for i := 0; i < started; i++ {
		select {
		case result := <-results:
			if result.name != "" {
				names[result.address] = result.name
			}
		case <-ctx.Done():
			return names
		}
	}
	return names
}

func deviceHostname(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || name == "*" || len(name) > 253 {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, ch := range label {
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return ""
			}
		}
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	return name
}

func readDHCPNames(wanted map[string]struct{}, names map[string]string, now time.Time) {
	paths := []string{"/var/lib/misc/dnsmasq.leases", "/tmp/dhcp.leases"}
	if path := os.Getenv("MERIDIAN_DHCP_LEASES_FILE"); path != "" {
		paths = []string{path}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanDHCPNames(io.LimitReader(f, 1<<20), wanted, names, now)
		_ = f.Close()
	}
}

// dnsmasq leases contain expiry, MAC/DUID, address, hostname and client ID.
func scanDHCPNames(r io.Reader, wanted map[string]struct{}, names map[string]string, now time.Time) {
	lines := bufio.NewScanner(r)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 5 {
			continue
		}
		expires, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || (expires != 0 && expires <= now.Unix()) {
			continue
		}
		ip, err := netip.ParseAddr(fields[2])
		if err != nil {
			continue
		}
		address := ip.String()
		if _, ok := wanted[address]; !ok || names[address] != "" {
			continue
		}
		if name := deviceHostname(fields[3]); name != "" {
			names[address] = name
		}
	}
}
