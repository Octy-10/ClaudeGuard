(() => {
  "use strict";

  const menu = document.getElementById("toolMenu");
  const maximize = document.querySelector('[data-window="maximize"]');
  const themeBtn = document.getElementById("btnTheme");
  const themeGlyph = document.getElementById("themeGlyph");

  function applyTheme(dark, persist = false) {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    if (themeGlyph) themeGlyph.setAttribute("href", dark ? "#i-sun" : "#i-moon");
    if (themeBtn) {
      const label = dark ? "切换日间主题" : "切换夜间主题";
      themeBtn.title = label;
      themeBtn.setAttribute("aria-label", label);
    }
    if (persist) {
      try { localStorage.setItem("cg_theme", dark ? "dark" : "light"); } catch {}
    }
    window.pywebview?.api?.set_theme_frame?.(dark);
  }

  applyTheme(document.documentElement.dataset.theme === "dark", false);
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      applyTheme(document.documentElement.dataset.theme !== "dark", true);
    });
  }

  function setMaximized(active) {
    const label = active ? "还原窗口" : "最大化";
    maximize.title = label;
    maximize.setAttribute("aria-label", label);
    document.getElementById("maximizeGlyph").setAttribute("d", active
      ? "M1.5 3.5h7v7h-7z M3.5 1.5h7v7"
      : "M1.5 1.5h9v9h-9z");
  }
  async function send(action) {
    const dispatch = window.pywebview?.api?.window_command;
    if (dispatch) setMaximized(await dispatch(action));
  }
  window.syncCaption = () => send("state");
  window.addEventListener("pywebviewready", () => {
    window.syncCaption();
    window.pywebview?.api?.set_theme_frame?.(document.documentElement.dataset.theme === "dark");
  });
  for (const button of document.querySelectorAll("[data-window]")) {
    button.addEventListener("click", () => send(button.dataset.window));
  }
  document.querySelector(".caption-drag").addEventListener("dblclick", () => send("maximize"));
  document.addEventListener("pointerdown", (event) => {
    if (!menu.contains(event.target)) menu.open = false;
  });
  menu.querySelector(".menu-items").addEventListener("click", () => {
    menu.open = false;
    if (!document.querySelector("dialog[open]")) menu.querySelector("summary").focus();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.open) {
      menu.open = false;
      menu.querySelector("summary").focus();
    }
  });
})();
