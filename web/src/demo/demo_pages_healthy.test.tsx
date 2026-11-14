// Every page of the panel in the demo's "healthy" scenario (testkit.tsx):
// renders without the page error boundary and without a request the demo
// cannot answer; a few checks that the scenario's state is what is shown.

import { screen } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: healthy", () => {
  keepFetch();
  pageTests("healthy", ALL_PAGES, {
    "": () => {
      expect(screen.getByTestId("global-status")).toHaveTextContent("宿主通道正常");
      expect(document.body).toHaveTextContent("主链路（多中继分担）");
      expect(screen.getAllByText("分担中").length).toBeGreaterThanOrEqual(2);
      // The external SOCKS exit has no key of its own and needs none.
      expect(document.body).not.toHaveTextContent("不受管的节点要在拓扑里填入公钥");
    },
  });
});
