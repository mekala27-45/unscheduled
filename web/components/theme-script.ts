/**
 * Runs in <head> before first paint: applies a saved light or dark choice so the page never flashes
 * the wrong theme, and marks the document as scripted so no-script fallbacks can step aside.
 */
export const THEME_KEY = "unscheduled-theme";

export const THEME_SCRIPT = `(function(){var d=document.documentElement;d.classList.add("js");try{var t=localStorage.getItem("${THEME_KEY}");if(t==="light"||t==="dark"){d.setAttribute("data-theme",t);}}catch(e){}})();`;
