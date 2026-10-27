/* Applies the saved light/dark choice before first paint. Loaded without defer in <head>.
 * No saved choice (or storage blocked) follows the operating system. */
(function () {
  try {
    var mode = window.localStorage.getItem("daedalus-theme");
    if (mode === "light" || mode === "dark") document.documentElement.setAttribute("data-theme", mode);
  } catch (error) { /* storage unavailable: follow the system */ }
})();
