// Every page in the demo's "degraded" scenario (testkit.tsx).

import { screen } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: degraded", () => {
  keepFetch();
  pageTests("degraded", ALL_PAGES, {
    "": () => {
      expect(document.body).toHaveTextContent("备用枢纽承载");
      expect(screen.getAllByText("已剔除").length).toBeGreaterThanOrEqual(2);
    },
  });
});
