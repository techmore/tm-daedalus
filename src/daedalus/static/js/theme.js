/* Applies the saved light/dark and palette choices before first paint. Loaded without defer in <head>.
 * No saved choice (or storage blocked) follows the operating system. */
(function () {
  try {
    var mode = window.localStorage.getItem("daedalus-theme");
    if (mode === "light" || mode === "dark") document.documentElement.setAttribute("data-theme", mode);
    var palette = window.localStorage.getItem("daedalus-palette");
    if (palette === "slate") document.documentElement.setAttribute("data-palette", palette);
  } catch (error) { /* storage unavailable: follow the system */ }
})();
