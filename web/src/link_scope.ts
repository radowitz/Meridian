import type { LinkLogObjectState, LinkLogScope } from "./types";

/**
 * Objects the link journal still remembers but no longer measures (a sniff
 * self-check target or external exit removed from the rules), as
 * "kind|id" keys. Their last reading is history, not a current fault.
 */
export function inactiveObjects(scope: LinkLogScope | undefined): string[] {
  return (scope?.unobserved ?? []).filter((o) => o.class === "sniff_target" || o.class === "external_exit").map((o) => `${o.kind}|${o.id}`);
}

/**
 * Whether an object of the current summary counts as a current reading.
 * Only an old reading (stale) of an object the rules no longer measure is
 * history: the scope follows the saved rules, which can be ahead of what the
 * gateway runs, so a fresh reading is always kept, alarm included.
 */
export function isCurrent(o: Pick<LinkLogObjectState, "kind" | "id" | "stale">, inactive: string[]): boolean {
  return !(o.stale && inactive.includes(`${o.kind}|${o.id}`));
}
