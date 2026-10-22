/** Sentinel IDS - API client (Frontend <-> Backend) */
(function () {
  const cfg = window.SENTINEL_CONFIG || {};
  const API_BASE = cfg.API_BASE || `${location.protocol}//${location.hostname}:3000/api`;
  const TOKEN_KEY = 'sentinel_token';
  let onAuthLost = () => {}, onMustChange = () => {};

  async function req(method, path, body) {
    const headers = {};
    const t = localStorage.getItem(TOKEN_KEY);
    if (t) headers.Authorization = 'Bearer ' + t;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try { res = await fetch(API_BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined }); }
    catch { const e = new Error(UI.T('Không kết nối được Backend (' + API_BASE + '). Backend đã chạy chưa?', 'Cannot reach Backend (' + API_BASE + ').')); e.network = true; throw e; }
    let data = null; try { data = await res.json(); } catch {}
    if (!res.ok) {
      const msg = (data && data.error) || ('HTTP ' + res.status);
      if (res.status === 401 && t && path !== '/auth/login') onAuthLost();
      if (res.status === 403 && msg === 'MUST_CHANGE_PASSWORD') onMustChange();
      const e = new Error(msg); e.status = res.status; throw e;
    }
    return data;
  }
  const api = {
    base: API_BASE,
    host: new URL(API_BASE).hostname,
    get: p => req('GET', p), post: (p, b) => req('POST', p, b || {}), put: (p, b) => req('PUT', p, b || {}),
    patch: (p, b) => req('PATCH', p, b || {}), del: p => req('DELETE', p),
    setToken: t => t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY),
    hasToken: () => !!localStorage.getItem(TOKEN_KEY),
    on(authLost, mustChange) { onAuthLost = authLost; onMustChange = mustChange; },
    async ticket() { return (await req('POST', '/auth/ticket', {})).ticket; }
  };
  window.API = api;
})();
