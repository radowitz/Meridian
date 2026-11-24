// One bounded automatic read of the hubs' group state per page visit, shared
// by 出口 and 概览: only when a hub can be read, no read is running and the
// last read of this hub identity is older than a minute. No polling.

import { useEffect, useRef } from "react";
import type { GroupHubState, RegionGroupsView } from "./types";

export const AUTO_REFRESH_AFTER_MS = 60_000;

/** The hubs whose state the view carries (both in dual-hub mode). */
export function hubsOf(d: RegionGroupsView | undefined): GroupHubState[] {
  if (!d) return [];
  return d.carrying?.mode === "dual" && d.hub_states?.length ? d.hub_states : d.hub_state ? [d.hub_state] : [];
}

/** Whether an automatic read is due for this view. */
export function hubReadDue(d: RegionGroupsView | undefined, now = Date.now()): boolean {
  const hubs = hubsOf(d);
  if (hubs.length === 0 || hubs.some((h) => h.refreshing)) return false;
  // A read of another hub identity says nothing about this one.
  const last = (h: GroupHubState) => (h.last_read && h.last_read.current_hub !== false ? Date.parse(h.last_read.read_at) : 0);
  return hubs.some((h) => h.readable && now - last(h) >= AUTO_REFRESH_AFTER_MS);
}

/** Calls `read` once, the first time the view arrives and a read is due. */
export function useHubAutoRead(data: RegionGroupsView | undefined, read: () => void) {
  const done = useRef(false);
  useEffect(() => {
    if (done.current || hubsOf(data).length === 0) return;
    done.current = true;
    if (hubReadDue(data)) read();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);
}
