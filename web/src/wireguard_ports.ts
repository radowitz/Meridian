import type { Topology } from "./types";

/** Choose a port once for a new managed link. Saved links retain their port. */
export function newWireGuardPort(topo: Topology, from: string, to: string): number | undefined {
  const ends = [from, to].map(id => topo.nodes.find(node => node.id === id));
  if (ends.some(node => !node?.managed || node.nat_dial_out || node.listen_port)) return undefined;

  const occupied = new Set<number>();
  for (const node of topo.nodes) {
    if (node.listen_port) occupied.add(node.listen_port);
    if (node.wss_listen_port) occupied.add(node.wss_listen_port);
  }
  for (const link of topo.links) {
    if (link.wg_port) {
      occupied.add(link.wg_port);
      if (link.transport === "udp_wss_failover") occupied.add(link.wg_port + 1);
    }
    if (link.wss_local_port) occupied.add(link.wss_local_port);
  }

  const start = Math.floor(Math.random() * 9_999);
  for (let offset = 0; offset < 9_999; offset++) {
    const port = 20_000 + (start + offset) % 9_999;
    if (!occupied.has(port) && !occupied.has(port + 1)) return port;
  }
  return undefined;
}
