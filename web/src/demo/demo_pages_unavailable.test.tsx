// Every page in the demo's "unavailable" (first run) scenario (testkit.tsx).

import { screen } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: unavailable", () => {
  keepFetch();
  pageTests("unavailable", ALL_PAGES, {
    "": () => {
      expect(screen.getByTestId("global-status")).toHaveTextContent("宿主通道不可用");
      expect(document.body).toHaveTextContent("还没有服务器");
    },
  });
});
