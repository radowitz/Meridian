package api

import "context"

// The API tests compare answers with committed fixtures (TestDemoFixtures):
// a CI runner whose resolver answers reverse lookups for private addresses,
// or a machine with a dnsmasq lease file, must not add device names to them.
// Tests that need names set MERIDIAN_DHCP_LEASES_FILE.
func init() {
	lookupDeviceAddr = func(context.Context, string) ([]string, error) { return nil, nil }
	dhcpLeasePaths = nil
}
