(function (root) {
  "use strict";

  function initDeck({ enMap, trExtra = {} }) {
    const trMap = { ...trExtra };
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      if (trMap[el.dataset.i18n] === undefined) trMap[el.dataset.i18n] = el.innerHTML;
    });

    const slides = Array.from(document.querySelectorAll(".slide"));
    const total = slides.length;
    let current = 1;
    let notesVisible = false;
    let currentLang = "tr";

    const totEl = document.getElementById("totNum");
    if (totEl) totEl.textContent = String(total);

    const getDict = () => (currentLang === "en" ? enMap : trMap);

    function updateDeckLinks(theme) {
      document.querySelectorAll("a[data-lab-link]").forEach((a) => {
        a.setAttribute("href", root.UIPrefs.buildHref(a.getAttribute("href"), { lang: currentLang, theme }));
      });
    }

    function applyTheme(theme) {
      const clean = root.UIPrefs.applyTheme(theme);
      const dict = getDict();
      const btn = document.getElementById("themeToggleBtn");
      if (btn) btn.textContent = clean === "dark" ? dict["ui.themeLight"] : dict["ui.themeDark"];
      updateDeckLinks(clean);
    }

    function showSlide(n) {
      current = Math.min(Math.max(n, 1), total);
      slides.forEach((s, i) => s.classList.toggle("active", i === current - 1));
      const active = slides[current - 1];
      const noteEl = document.getElementById("speakerNoteText");
      if (noteEl && active) {
        noteEl.textContent = currentLang === "en" ? (active.dataset.noteEn || "") : (active.dataset.noteTr || "");
      }
      const curEl = document.getElementById("curNum");
      if (curEl) curEl.textContent = String(current);
      const bar = document.getElementById("progressBar");
      if (bar) bar.style.width = `${(current / total) * 100}%`;
      const prevBtn = document.getElementById("prevBtn");
      const nextBtn = document.getElementById("nextBtn");
      if (prevBtn) prevBtn.disabled = current === 1;
      if (nextBtn) nextBtn.disabled = current === total;
    }

    function applyLanguage(lang) {
      currentLang = root.UIPrefs.syncLangControls(lang);
      const dict = getDict();
      if (dict["ui.docTitle"]) document.title = dict["ui.docTitle"];
      document.querySelectorAll("[data-i18n]").forEach((el) => {
        const key = el.dataset.i18n;
        if (dict[key] !== undefined) el.innerHTML = dict[key];
      });
      applyTheme(document.documentElement.getAttribute("data-theme") || "dark");
      showSlide(current);
    }

    function toggleNotes(force) {
      notesVisible = typeof force === "boolean" ? force : !notesVisible;
      const notesBox = document.getElementById("speakerNotes");
      const notesBtn = document.getElementById("notesToggleBtn");
      if (notesBox) notesBox.classList.toggle("visible", notesVisible);
      if (notesBtn) notesBtn.setAttribute("aria-pressed", String(notesVisible));
    }

    document.querySelectorAll(".lang-btn").forEach((btn) => {
      btn.addEventListener("click", () => applyLanguage(btn.dataset.lang));
    });
    const prevBtn = document.getElementById("prevBtn");
    const nextBtn = document.getElementById("nextBtn");
    const notesBtn = document.getElementById("notesToggleBtn");
    const themeBtn = document.getElementById("themeToggleBtn");
    if (prevBtn) prevBtn.addEventListener("click", () => showSlide(current - 1));
    if (nextBtn) nextBtn.addEventListener("click", () => showSlide(current + 1));
    if (notesBtn) notesBtn.addEventListener("click", () => toggleNotes());
    if (themeBtn) themeBtn.addEventListener("click", () => root.UIPrefs.toggleRootTheme(applyTheme));

    document.addEventListener("keydown", (e) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "ArrowRight" || e.key === " " || e.key === "PageDown") {
        e.preventDefault();
        showSlide(current + 1);
      } else if (e.key === "ArrowLeft" || e.key === "PageUp") {
        e.preventDefault();
        showSlide(current - 1);
      } else if (e.key.toLowerCase() === "n") {
        toggleNotes();
      } else if (e.key.toLowerCase() === "t") {
        root.UIPrefs.toggleRootTheme(applyTheme);
      }
    });

    const boot = root.UIPrefs.readBootPrefs(window.location.search);
    if (boot.params.get("notes") === "1") toggleNotes(true);
    const qSlide = parseInt(boot.params.get("slide"), 10);
    if (!Number.isNaN(qSlide)) current = Math.min(Math.max(qSlide, 1), total);
    root.UIPrefs.applyTheme(boot.theme);
    applyLanguage(boot.lang);
  }

  root.DeckController = { initDeck };
})(typeof window !== "undefined" ? window : globalThis);
