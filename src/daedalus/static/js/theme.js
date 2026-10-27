/* Applies the saved light/dark and palette choices before first paint. Loaded without defer in <head>.
 * No saved choice (or storage blocked) is light; "system" follows the operating system. */
(function () {
  try {
    var mode = window.localStorage.getItem("daedalus-theme");
    if (mode !== "system") document.documentElement.setAttribute("data-theme", mode === "dark" ? "dark" : "light");
    var palette = window.localStorage.getItem("daedalus-palette");
    if (palette === "slate") document.documentElement.setAttribute("data-palette", palette);
  } catch (error) { document.documentElement.setAttribute("data-theme", "light"); }
})();
