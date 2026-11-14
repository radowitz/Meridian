// Layout audit used from the browser's JS console on the local panel
// (the local panel origin). Defines window.__audit(width, pages, waitMs) and
// window.__fmt(result). It loads the panel in an iframe of the given width
// and reports, per page: document overflow (ox), content spilling out of its
// box, elements beyond the viewport or their card, labels/tags/buttons that
// wrap, text squeezed into a one-character column, tables that need
// horizontal scrolling, and absolutely positioned elements (e.g. .sr-only
// hidden labels) that lie outside the horizontally scrolling box around them
// while that box is not their containing block (they then widen every
// ancestor's scroll area, up to the document).
window.__audit = async function (width, pages, wait) {
  let f = document.getElementById('__af');
  if (!f) { f = document.createElement('iframe'); f.id = '__af'; f.style.cssText = 'position:fixed;left:0;top:0;height:1000px;border:0;z-index:99999;background:#fff'; document.body.appendChild(f); }
  f.style.width = width + 'px';
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  if (!f.src) { f.src = location.origin + '/#/'; await new Promise(r => { f.onload = r }); await sleep(1500); }
  const out = {};
  for (const p of pages) {
    f.contentWindow.location.hash = '#/' + p; await sleep(wait || 1500);
    const W = f.contentWindow, D = f.contentDocument, vw = W.innerWidth;
    const res = { ox: D.documentElement.scrollWidth - vw, spill: [], beyond: [], outCard: [], wrap: [], squeeze: [], hscroll: [], absOut: [] };
    const desc = el => { let c = (el.className && el.className.baseVal === undefined ? String(el.className) : '').split(/\s+/).filter(x => x && !/^css-/.test(x)).slice(0, 2).join('.'); return el.tagName.toLowerCase() + (c ? '.' + c : ''); };
    const txt = el => (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 26);
    const scrollAnc = el => { for (let a = el.parentElement; a && a !== D.body; a = a.parentElement) { const s = W.getComputedStyle(a); if (/(auto|scroll|hidden)/.test(s.overflowX)) return a; } return null; };
    // Lines of visible text only: text inside .sr-only (visually hidden labels) is not counted.
    const lines = el => { const tops = []; const tw = D.createTreeWalker(el, NodeFilter.SHOW_TEXT); for (let n = tw.nextNode(); n; n = tw.nextNode()) { if (!n.textContent.trim() || (n.parentElement && n.parentElement.closest('.sr-only'))) continue; const rg = D.createRange(); rg.selectNodeContents(n); for (const r of rg.getClientRects()) { if (r.width < 1 || r.height < 6) continue; if (!tops.some(t => Math.abs(t - r.top) < r.height * 0.6)) tops.push(r.top); } } return tops.length; };
    const hScrollAnc = el => { for (let a = el.parentElement; a && a !== D.body; a = a.parentElement) { if (/(auto|scroll)/.test(W.getComputedStyle(a).overflowX)) return a; } return null; };
    const seen = new Set(); const push = (k, arr, el, extra) => { const key = k + desc(el) + txt(el); if (seen.has(key) || arr.length >= 12) return; seen.add(key); arr.push(desc(el) + ' «' + txt(el) + '»' + (extra ? ' ' + extra : '')); };
    for (const el of D.body.querySelectorAll('*')) {
      if (el.closest('svg,.react-flow,.ant-tooltip,.ant-select-dropdown,.ant-dropdown')) continue;
      const s0 = W.getComputedStyle(el);
      if (s0.position === 'absolute' && s0.display !== 'none') {
        // Its containing block is el.offsetParent; if that is outside the scrolling box, the box does not clip it.
        const sa = hScrollAnc(el), cb = el.offsetParent, r0 = el.getBoundingClientRect();
        if (sa && cb && cb !== sa && !sa.contains(cb)) { const sr = sa.getBoundingClientRect(); if (r0.right > sr.right + 1 || r0.left < sr.left - 1) push('a', res.absOut, el, 'outside ' + desc(sa) + ' by ' + Math.round(Math.max(r0.right - sr.right, sr.left - r0.left)) + 'px, containing block ' + desc(cb)); }
      }
      const r = el.getBoundingClientRect(); if (r.width === 0 || r.height === 0) continue;
      const s = s0; if (s.visibility === 'hidden' || s.display === 'none') continue;
      if (s.display !== 'inline' && s.overflowX === 'visible' && el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0 && el.children.length < 8) { const sa = scrollAnc(el); push('s', res.spill, el, '+' + (el.scrollWidth - el.clientWidth) + 'px' + (sa ? ' (clipped by ' + desc(sa) + ' ' + W.getComputedStyle(sa).overflowX + ')' : ' (visible)')); }
      if (/(auto|scroll)/.test(s.overflowX) && el.scrollWidth > el.clientWidth + 2) push('h', res.hscroll, el, 'scrolls ' + (el.scrollWidth - el.clientWidth) + 'px of ' + el.clientWidth);
      if (r.right > vw + 1 && !scrollAnc(el) && el.children.length < 4) push('b', res.beyond, el, 'right=' + Math.round(r.right));
      const card = el.closest('.ant-card-body,.ant-modal-body,.ant-drawer-body,.ant-alert');
      if (card && card !== el && el.children.length < 4) { const cr = card.getBoundingClientRect(); const sa = scrollAnc(el); if ((r.right > cr.right + 1 || r.left < cr.left - 1) && (!sa || !card.contains(sa) || sa === card)) push('c', res.outCard, el, 'by ' + Math.round(Math.max(r.right - cr.right, cr.left - r.left)) + 'px'); }
      if (el.matches('button,.ant-tag,th,.ant-menu-item,.ant-tabs-tab,.ant-descriptions-item-label,.ant-statistic-title,.ant-form-item-label>label,.ant-segmented-item-label,.ant-steps-item-title,.ant-select-selection-item,.ant-radio-button-wrapper,.ant-list-item-meta-title,.ant-card-head-title,.ant-badge-status-text,code,h1,h2,h3,h4,.ant-page-header-heading-title')) { const n = lines(el); if (n >= 2 && txt(el).length > 0) push('w', res.wrap, el, n + ' lines w=' + Math.round(r.width)); }
      if (el.children.length === 0 && txt(el).length >= 3 && r.width < 34 && r.height > 50) push('q', res.squeeze, el, Math.round(r.width) + 'x' + Math.round(r.height));
    }
    out[p || 'overview'] = res;
  }
  window.__last = out;
  return out;
};
window.__fmt = (o, keys) => Object.entries(o).filter(([k]) => !keys || keys.includes(k)).map(([k, v]) => k + ': ox=' + v.ox + '\n' + ['spill', 'hscroll', 'beyond', 'outCard', 'wrap', 'squeeze', 'absOut'].filter(c => v[c].length).map(c => '  ' + c + ':\n    ' + v[c].join('\n    ')).join('\n')).join('\n');
