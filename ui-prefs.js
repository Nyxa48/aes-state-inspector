(function (root) {
  "use strict";

  const STORAGE_KEYS = {
    lang: "aes_lang",
    theme: "aes_theme",
    present: "aes_present"
  };

  function readStorage(key, fallback) {
    try {
      const val = root.localStorage ? root.localStorage.getItem(key) : null;
      return val !== null ? val : fallback;
    } catch (_) {
      return fallback;
    }
  }

  function writeStorage(key, val) {
    try {
      if (root.localStorage) root.localStorage.setItem(key, String(val));
    } catch (_) {}
  }

  function normalizeLang(lang) {
    return lang === "en" ? "en" : "tr";
  }

  function normalizeTheme(theme) {
    return theme === "light" ? "light" : "dark";
  }

  function readBootPrefs(search) {
    const params = new URLSearchParams(search || "");
    const qLang = params.get("lang");
    const qTheme = params.get("theme");
    const qPresent = params.get("present");
    return {
      params,
      lang: (qLang === "en" || qLang === "tr") ? qLang : normalizeLang(readStorage(STORAGE_KEYS.lang, "tr")),
      theme: (qTheme === "light" || qTheme === "dark") ? qTheme : normalizeTheme(readStorage(STORAGE_KEYS.theme, "dark")),
      present: (qPresent === "1" || qPresent === "0") ? qPresent === "1" : readStorage(STORAGE_KEYS.present, "false") === "true"
    };
  }

  function applyTheme(theme) {
    const clean = normalizeTheme(theme);
    root.document.documentElement.setAttribute("data-theme", clean);
    writeStorage(STORAGE_KEYS.theme, clean);
    return clean;
  }

  function syncLangControls(lang) {
    const clean = normalizeLang(lang);
    root.document.documentElement.lang = clean;
    writeStorage(STORAGE_KEYS.lang, clean);
    root.document.querySelectorAll(".lang-btn").forEach(btn => {
      const active = btn.dataset.lang === clean;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-pressed", String(active));
    });
    return clean;
  }

  function toggleRootTheme(applyFn) {
    const cur = root.document.documentElement.getAttribute("data-theme") || "dark";
    return applyFn(cur === "dark" ? "light" : "dark");
  }

  function buildHref(href, overrides) {
    const [basePath, rawQuery = ""] = String(href).split("?");
    const params = new URLSearchParams(rawQuery);
    Object.entries(overrides || {}).forEach(([k, v]) => {
      if (v === null || v === undefined || v === "") params.delete(k);
      else params.set(k, String(v));
    });
    const qs = params.toString();
    return qs ? `${basePath}?${qs}` : basePath;
  }

  const api = {
    STORAGE_KEYS,
    readStorage,
    writeStorage,
    normalizeLang,
    normalizeTheme,
    readBootPrefs,
    applyTheme,
    syncLangControls,
    toggleRootTheme,
    buildHref
  };

  root.UIPrefs = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
