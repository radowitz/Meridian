// App-wide state: hash router with an unsaved-changes guard, the global
// status (host agent, installed version, pending install, running jobs) and
// the shared topology document used by the editors.

import { App as AntApp } from "antd";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import * as api from "./api";
import type { Issue, PanelStatus, PathReport, Topology } from "./types";

// =================================================================== router ===

export interface Route {
  /** First path segment: "" (overview), "servers", "keys", … */
  page: string;
  /** Remaining segments, decoded: `#/servers/srv-1` → ["srv-1"]. */
  params: string[];
  /** Query after "?", e.g. `#/keys?new=1`. */
  query: URLSearchParams;
}

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#/, "");
  const [pathPart, queryPart = ""] = raw.split("?");
  const segs = pathPart
    .split("/")
    .filter(Boolean)
    .map((s) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    });
  return { page: segs[0] || "", params: segs.slice(1), query: new URLSearchParams(queryPart) };
}

/** Builds `#/page/param…` with encoded segments. */
export function href(page: string, ...params: (string | undefined)[]) {
  const segs = [page, ...params.filter((p): p is string => !!p)].map(encodeURIComponent);
  return `#/${segs.filter(Boolean).join("/")}`;
}

type Guard = () => string | null;

interface RouterCtx {
  route: Route;
  /** Navigate to a hash (e.g. href("servers", id)); asks first when a guard is active. */
  navigate: (to: string, opts?: { replace?: boolean }) => void;
  registerGuard: (g: Guard) => () => void;
}

const RouterContext = createContext<RouterCtx | null>(null);

export function RouterProvider({ children }: { children: ReactNode }) {
  const { modal } = AntApp.useApp();
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  const guards = useRef(new Set<Guard>());
  const current = useRef(window.location.hash);
  const reverting = useRef(false);

  const activeGuard = useCallback((): string | null => {
    for (const g of guards.current) {
      const msg = g();
      if (msg) return msg;
    }
    return null;
  }, []);

  const go = useCallback((to: string, replace?: boolean) => {
    const target = to.startsWith("#") ? to : `#${to}`;
    current.current = target;
    if (replace) window.history.replaceState(null, "", target);
    else if (window.location.hash !== target) window.history.pushState(null, "", target);
    setRoute(parseHash(target));
  }, []);

  const navigate = useCallback(
    (to: string, opts?: { replace?: boolean }) => {
      const msg = activeGuard();
      if (!msg) {
        go(to, opts?.replace);
        return;
      }
      modal.confirm({
        title: "离开这个页面？",
        content: msg,
        okText: "放弃修改并离开",
        okButtonProps: { danger: true },
        cancelText: "留在这里",
        onOk: () => {
          guards.current.clear();
          go(to, opts?.replace);
        },
      });
    },
    [activeGuard, go, modal],
  );

  useEffect(() => {
    // Back/forward and typed URLs arrive as hashchange/popstate.
    const onChange = () => {
      const next = window.location.hash;
      if (reverting.current) {
        reverting.current = false;
        return;
      }
      if (next === current.current) return;
      const msg = activeGuard();
      if (!msg) {
        current.current = next;
        setRoute(parseHash(next));
        return;
      }
      const target = next;
      reverting.current = true;
      window.history.replaceState(null, "", current.current || "#/");
      reverting.current = false;
      modal.confirm({
        title: "离开这个页面？",
        content: msg,
        okText: "放弃修改并离开",
        okButtonProps: { danger: true },
        cancelText: "留在这里",
        onOk: () => {
          guards.current.clear();
          go(target, false);
        },
      });
    };
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      if (activeGuard()) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    window.addEventListener("hashchange", onChange);
    window.addEventListener("popstate", onChange);
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => {
      window.removeEventListener("hashchange", onChange);
      window.removeEventListener("popstate", onChange);
      window.removeEventListener("beforeunload", onBeforeUnload);
    };
  }, [activeGuard, go, modal]);

  const registerGuard = useCallback((g: Guard) => {
    guards.current.add(g);
    return () => {
      guards.current.delete(g);
    };
  }, []);

  const value = useMemo(() => ({ route, navigate, registerGuard }), [route, navigate, registerGuard]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

/** Router or null (outside the provider, e.g. inside antd's static modal holder). */
export function useOptionalRouter(): RouterCtx | null {
  return useContext(RouterContext);
}

export function useRouter(): RouterCtx {
  const ctx = useContext(RouterContext);
  if (!ctx) throw new Error("useRouter outside RouterProvider");
  return ctx;
}

/**
 * Asks before navigating away (in-app links, back button, closing the tab)
 * while `dirty` is true.
 */
export function useUnsavedGuard(dirty: boolean, message = "有未保存的修改，离开后会丢失。") {
  const { registerGuard } = useRouter();
  const ref = useRef({ dirty, message });
  ref.current = { dirty, message };
  useEffect(() => registerGuard(() => (ref.current.dirty ? ref.current.message : null)), [registerGuard]);
}

// ============================================================ global status ===

export type InstallState =
  /** Not read yet. */
  | { kind: "loading" }
  /** The stored topology compiles to exactly what is installed on the gateway. */
  | { kind: "in_sync"; version: number }
  /**
   * The stored topology differs from what is installed. `appliedOnly`: it
   * was written to the data directory (apply without install) but the host
   * still runs the older installed version.
   */
  | { kind: "changed"; version: number | null; appliedOnly: boolean }
  /** Nothing installed on the gateway yet (withdrawn: withdrawn down to the LAN guard). */
  | { kind: "not_installed"; withdrawn?: boolean }
  /** The stored topology does not compile (draft with errors). */
  | { kind: "error"; message: string }
  /** Installed by an adopted legacy install without a hash: cannot compare. */
  | { kind: "unknown"; version: number | null };

export interface RunningJobs {
  lists: boolean;
  unlock: boolean;
  mesh: boolean;
}

interface StatusCtx {
  /** GET /api/status (null until the first answer). */
  status: PanelStatus | null;
  statusError: api.ApiError | null;
  install: InstallState;
  jobs: RunningJobs;
  /** Re-read the status now. */
  refresh: () => void;
  /** Call after a mutation answered `apply_required: true`. */
  markApplyRequired: () => void;
}

const StatusContext = createContext<StatusCtx | null>(null);

const POLL_MS = 20000;
const POLL_BUSY_MS = 5000;

export function installStateOf(s: PanelStatus): InstallState {
  const i = s.install;
  switch (i.state) {
    case "in_sync":
      return { kind: "in_sync", version: i.installed_version ?? 0 };
    case "changed":
      return { kind: "changed", version: i.installed_version, appliedOnly: i.applied && i.applied_matches };
    case "not_installed":
      return { kind: "not_installed" };
    case "withdrawn":
      return { kind: "not_installed", withdrawn: true };
    case "invalid":
      return { kind: "error", message: i.error || "拓扑无法编译" };
    default:
      return { kind: "unknown", version: i.installed_version };
  }
}

export function StatusProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<PanelStatus | null>(null);
  const [statusError, setStatusError] = useState<api.ApiError | null>(null);
  const [assumeChanged, setAssumeChanged] = useState(false);
  const seq = useRef(0);

  const refresh = useCallback(() => {
    const my = ++seq.current;
    api
      .getStatus()
      .then((s) => {
        if (my !== seq.current) return;
        setStatus(s);
        setStatusError(null);
        setAssumeChanged(false);
      })
      .catch((e) => my === seq.current && setStatusError(e instanceof api.ApiError ? e : new api.ApiError(0, {})));
  }, []);

  const jobs: RunningJobs = useMemo(
    () => ({
      lists: !!status?.jobs.lists.running,
      unlock: !!status?.jobs.unlock.running,
      mesh: !!status?.jobs.mesh.running,
    }),
    [status],
  );
  const busy = jobs.lists || jobs.unlock || jobs.mesh;

  useEffect(() => {
    refresh();
    const t = window.setInterval(
      () => {
        if (document.visibilityState !== "hidden") refresh();
      },
      busy ? POLL_BUSY_MS : POLL_MS,
    );
    return () => window.clearInterval(t);
  }, [refresh, busy]);

  const markApplyRequired = useCallback(() => {
    setAssumeChanged(true);
    refresh();
  }, [refresh]);

  const install: InstallState = useMemo(() => {
    if (!status) return { kind: "loading" };
    const st = installStateOf(status);
    if (assumeChanged && st.kind === "in_sync") return { kind: "changed", version: st.version, appliedOnly: false };
    return st;
  }, [status, assumeChanged]);

  const value = useMemo(
    () => ({ status, statusError, install, jobs, refresh, markApplyRequired }),
    [status, statusError, install, jobs, refresh, markApplyRequired],
  );
  return <StatusContext.Provider value={value}>{children}</StatusContext.Provider>;
}

export function useStatus(): StatusCtx {
  const ctx = useContext(StatusContext);
  if (!ctx) throw new Error("useStatus outside StatusProvider");
  return ctx;
}

// ======================================================== topology document ===

interface TopologyCtx {
  /** The working copy (local edits included); null while loading. */
  topo: Topology | null;
  error: api.ApiError | null;
  /** Local edits not yet saved. */
  dirty: boolean;
  saving: boolean;
  issues: Issue[];
  paths: PathReport[];
  /** Replace the working copy (editors call this on every change). */
  setTopo: (t: Topology) => void;
  /** PUT the working copy; draft skips the validation gate. */
  save: (draft: boolean) => Promise<boolean>;
  validate: () => Promise<void>;
  /** Drop local edits and re-read the stored document. */
  reload: () => Promise<void>;
  /**
   * Another API changed the stored document (lists policy, region groups,
   * remote access…): apply the same change to the saved base and the
   * working copy so a later save does not write the old value back.
   */
  applyServerChange: (fn: (t: Topology) => Topology) => void;
}

const TopologyContext = createContext<TopologyCtx | null>(null);

export function TopologyProvider({ children }: { children: ReactNode }) {
  const { markApplyRequired } = useStatus();
  const [base, setBase] = useState<Topology | null>(null);
  const [topo, setTopoState] = useState<Topology | null>(null);
  const [error, setError] = useState<api.ApiError | null>(null);
  const [saving, setSaving] = useState(false);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [paths, setPaths] = useState<PathReport[]>([]);

  const reload = useCallback(async () => {
    try {
      const t = await api.getTopology();
      setBase(t);
      setTopoState(t);
      setError(null);
    } catch (e) {
      setError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const dirty = useMemo(() => !!base && !!topo && JSON.stringify(base) !== JSON.stringify(topo), [base, topo]);

  const save = useCallback(
    async (draft: boolean) => {
      if (!topo) return false;
      setSaving(true);
      try {
        const res = await api.putTopology({ ...topo, settings: { ...topo.settings, draft } }, draft);
        setBase(res.topology);
        setTopoState(res.topology);
        setIssues(res.issues || []);
        setPaths(res.paths || []);
        setError(null);
        markApplyRequired();
        return true;
      } catch (e) {
        if (e instanceof api.ApiError) {
          setIssues(e.issues || []);
          throw e;
        }
        throw e;
      } finally {
        setSaving(false);
      }
    },
    [topo, markApplyRequired],
  );

  const validate = useCallback(async () => {
    if (!topo) return;
    const res = await api.validate(topo);
    setIssues(res.issues || []);
    setPaths(res.paths || []);
  }, [topo]);

  const applyServerChange = useCallback((fn: (t: Topology) => Topology) => {
    setBase((b) => (b ? fn(b) : b));
    setTopoState((t) => (t ? fn(t) : t));
  }, []);

  const value = useMemo(
    () => ({
      topo,
      error,
      dirty,
      saving,
      issues,
      paths,
      setTopo: setTopoState,
      save,
      validate,
      reload,
      applyServerChange,
    }),
    [topo, error, dirty, saving, issues, paths, save, validate, reload, applyServerChange],
  );
  return <TopologyContext.Provider value={value}>{children}</TopologyContext.Provider>;
}

export function useTopologyDoc(): TopologyCtx {
  const ctx = useContext(TopologyContext);
  if (!ctx) throw new Error("useTopologyDoc outside TopologyProvider");
  return ctx;
}
