package model

// DNSHostsInclude is an optional gateway SmartDNS drop-in. The resolver
// owns no state in the topology, so normal reinstalls leave these records intact.
const DNSHostsInclude = "conf-file /var/lib/meridian/keywords/meridian-panel-hosts.[c]onf"
