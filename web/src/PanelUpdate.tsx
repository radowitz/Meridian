// Upgrade notice (docs/architecture.md「静态文件缓存与升级提示」).
//
// The running bundle knows the build id it was built with (__MERIDIAN_BUILD__,
// vite.config.ts). It reads the served build id (version.json) when the page
// becomes visible again and every POLL_MS while visible; when the two differ
// it shows a non-blocking notice with a 刷新 button. It never reloads by
// itself, so there is no reload loop.
//
// Limit: a tab still running a build from before this notice existed has none
// of this code; the first upgrade to this version may still need one manual
// refresh. Later upgrades show the notice.

import { Alert, Button } from "antd";
import { useEffect, useState } from "react";
import { fetchBuildVersion } from "./api";
import {
  Note,
} from "./ui";
// Used only on click, so the import cycle with App (which mounts this) is harmless.
import { panelReload } from "./App";

declare const __MERIDIAN_BUILD__: string | undefined;

/** The id this bundle was built with; undefined for dev server, vitest and the demo build. */
export const RUNNING_BUILD: string | undefined = typeof __MERIDIAN_BUILD__ === "string" ? __MERIDIAN_BUILD__ : undefined;

/** Low-frequency check while the page stays visible. */
export const POLL_MS = 5 * 60 * 1000;

export function PanelUpdate({
  build = RUNNING_BUILD,
  fetchVersion = fetchBuildVersion,
}: {
  build?: string;
  fetchVersion?: (signal?: AbortSignal) => Promise<string | null>;
}) {
  const [updated, setUpdated] = useState(false);

  useEffect(() => {
    if (!build || updated) return;
    const ctl = new AbortController();
    let busy = false;
    const check = async () => {
      if (busy || document.visibilityState === "hidden") return;
      busy = true;
      try {
        const served = await fetchVersion(ctl.signal);
        if (!ctl.signal.aborted && served && served !== build) setUpdated(true);
      } finally {
        busy = false;
      }
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") void check();
    };
    document.addEventListener("visibilitychange", onVisible);
    const timer = window.setInterval(() => void check(), POLL_MS);
    return () => {
      ctl.abort();
      document.removeEventListener("visibilitychange", onVisible);
      window.clearInterval(timer);
    };
  }, [build, fetchVersion, updated]);

  if (!updated) return null;
  return (
    <div className="panel-update" data-testid="panel-update" style={{ position: "fixed", right: 16, bottom: 16, zIndex: 1100, maxWidth: "calc(100vw - 32px)" }}>
      <Alert
        type="info"
        showIcon
        message="面板已更新"
        description={<Note>{"网关上的面板已换成新版本，这个标签页还是旧版本。刷新后使用新版本。"}</Note>}
        action={
          <Button type="primary" size="small" onClick={() => panelReload.run()}>
            刷新
          </Button>
        }
      />
    </div>
  );
}
