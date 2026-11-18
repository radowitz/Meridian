// The explanatory text a page shows by default (docs: 说明默认收起). Used by
// prose_budget.test.tsx and the demo page tests (demo/testkit.tsx): every
// page shows at most one sentence of explanation until 「说明」 is opened.
// Danger consequences, errors and blocking notices are exempt.

/** Elements whose text is explanation (not data, not a label). */
export const PROSE = [
  ".page-header-desc",
  ".ant-typography-secondary",
  "div.ant-typography",
  "main p",
  ".ant-radio-wrapper",
  ".ant-checkbox-wrapper",
  ".ant-collapse-content",
  ".ant-form-item-extra",
  ".ant-alert-info",
  ".ant-alert-success",
  ".explain",
  ".safety-unverified",
  ".ant-drawer-body > p",
  ".ant-modal-body > p",
  // Grey text blocks however they are built (a muted/explain class, or a
  // block of secondary text), so a paragraph cannot slip past by its markup.
  "div.muted:not(.mono-small)",
].join(",");

/** Exempt: danger consequences, errors, blocking notices. */
export const EXEMPT = ".ant-alert-warning, .ant-alert-error, .ant-typography-warning, .ant-typography-danger, .safety-failclosed, .safety-signoff, .ant-modal-confirm, [data-prose-exempt]:not(.explain, .muted, .ant-typography-secondary), .ant-table-cell, .ant-tooltip, .ant-popover, .ant-select-dropdown, .help-guide";

/** Sentences in a text: terminated pieces, plus an unterminated tail of 15+ characters. */
export function sentences(text: string): string[] {
  const t = text.replace(/\s+/g, " ").trim();
  const out: string[] = [];
  const re = /[^。！？；!?]+[。！？；!?]/g;
  let last = 0;
  for (const m of t.matchAll(re)) {
    if (m[0].replace(/[\s（）()「」。！？；!?]/g, "").length >= 10) out.push(m[0].trim());
    last = (m.index ?? 0) + m[0].length;
  }
  const tail = t.slice(last).trim();
  if ((tail.match(/[\u4e00-\u9fff]/g) ?? []).length >= 15) out.push(tail);
  return out;
}

function visible(el: Element): boolean {
  for (let e: Element | null = el; e; e = e.parentElement) {
    if ((e as HTMLElement).hidden || e.getAttribute("aria-hidden") === "true") return false;
    const st = (e as HTMLElement).style;
    if (st && st.display === "none") return false;
  }
  return true;
}

/** The explanatory sentences visible in `root` by default. */
/**
 * `authoredOnly` leaves out inline secondary text (span.ant-typography-secondary
 * and the tables/lists of server-supplied data around it): with real-size data
 * those carry data (digests, server notes, provenance), not the page's own
 * explanation. The block-level explanation selectors still count.
 */
export function proseSentences(root: ParentNode = document.body, opts: { authoredOnly?: boolean } = {}): string[] {
  const els = Array.from(root.querySelectorAll(PROSE)).filter(
    (e) => !e.closest(EXEMPT) && visible(e) && !(opts.authoredOnly && e.matches("span.ant-typography-secondary, .ant-collapse-content")),
  );
  const outer = els.filter((e) => !els.some((o) => o !== e && o.contains(e)));
  return outer.flatMap((e) => {
    const c = e.cloneNode(true) as Element;
    c.querySelectorAll("[hidden], [aria-hidden=true], .ant-alert-action, .explain-toggle, button, .help-button, .ant-tag, .status-text, " + EXEMPT).forEach((b) => b.remove());
    return sentences(c.textContent ?? "");
  });
}


/**
 * The 「说明」 entries a page shows: at most one, in the page header. Notes
 * that explain a state next to it (alerts, empty states, safety notices),
 * table rows, drawers and dialogs are their own places and do not count.
 */
export function helpEntries(root: ParentNode = document.body): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>("main .explain-toggle, main .help-button")).filter(
    (b) => visible(b) && !b.closest(".ant-table-wrapper, .data-cards, .ant-alert-error, .empty-state, .safety-notice, .ant-drawer, .ant-modal, .ant-popover, [hidden]") && !b.matches("[data-testid='acc-inactive-toggle']"),
  );
}

/** Coloured status tags are for problems only (failed, needs attention, needs a sign-off). */
export function healthyTags(root: ParentNode = document.body): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(".status-tag.ant-tag")).filter(
    (t) => visible(t) && !t.closest("[hidden]") && !["attention", "failed", "signoff"].includes(t.getAttribute("data-status") ?? ""),
  );
}

/** Grey hints next to options ("（没有启用的规则）"): an option that cannot be picked is hidden or plain, never explained in place. */
export function optionHints(root: ParentNode = document.body): string[] {
  return Array.from(root.querySelectorAll<HTMLElement>("main .ant-checkbox-wrapper, main .ant-radio-wrapper, main .ant-radio-button-wrapper"))
    .filter((o) => visible(o) && !o.closest(".ant-drawer, .ant-modal, [hidden]"))
    .map((o) => o.textContent ?? "")
    .filter((t) => /（[^）]*(没有|未|不能|只记录|无法)[^）]*）/.test(t));
}
