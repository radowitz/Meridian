import { expect, it } from "vitest";
import { sameJSON } from "./state";

it("agrees with JSON.stringify equality", () => {
  const shared = { rules: [{ id: "a", domains: ["x"] }] };
  const cases: [unknown, unknown][] = [
    [{ a: 1, b: shared }, { a: 1, b: shared }],
    [{ a: 1, b: undefined }, { a: 1 }],
    [{ a: 1, b: 2 }, { b: 2, a: 1 }],
    [[1, undefined], [1, null]],
    [{ a: [1, 2] }, { a: [1, 2, 3] }],
    [{ a: "1" }, { a: 1 }],
    [{ a: null }, {}],
    [{ n: { x: 1 } }, { n: { x: 1 } }],
    [[], {}],
    [{ a: NaN }, { a: null }],
    [[Infinity], [null]],
  ];
  for (const [a, b] of cases) expect(sameJSON(a, b)).toBe(JSON.stringify(a) === JSON.stringify(b));
});
