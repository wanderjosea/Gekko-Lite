/**
 * gekko-banner — muestra el banner de tools/pi-hitl.sh como header de la TUI de pi.
 *
 * Por qué: pi entra al alternate screen (\e[?1049h + \e[2J) al arrancar, así que todo lo
 * impreso antes por el launcher queda oculto hasta salir. El launcher vuelca el banner ya
 * renderizado (ANSI) en $GEKKO_BANNER_FILE y esta extensión lo pinta dentro de pi.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { keyHint, keyText, rawKeyHint } from "@earendil-works/pi-coding-agent";
import { truncateToWidth } from "@earendil-works/pi-tui";
import { readFileSync } from "node:fs";

export default function (pi: ExtensionAPI) {
  pi.on("session_start", async (_event, ctx) => {
    const file = process.env.GEKKO_BANNER_FILE;
    if (ctx.mode !== "tui" || !file) return;
    let lines: string[];
    try {
      lines = readFileSync(file, "utf8").replace(/\n+$/, "").split("\n");
    } catch {
      return; // sin banner → header nativo de pi
    }
    ctx.ui.setHeader((_tui, theme) => ({
      // pi-tui aborta si una línea excede el ancho de la terminal → truncar siempre.
      render: (width: number) => {
        // Mismos atajos que el header nativo de pi (lee las keybindings reales del usuario).
        const hints = [
          keyHint("app.interrupt", "interrupt"),
          rawKeyHint(`${keyText("app.clear")}/${keyText("app.exit")}`, "clear/exit"),
          rawKeyHint("/", "commands"),
          rawKeyHint("!", "bash"),
          keyHint("app.tools.expand", "more"),
        ].join(theme.fg("muted", " · "));
        return [...lines, "", `  ${hints}`].map((l) => truncateToWidth(l, width, ""));
      },
      invalidate() {},
    }));
  });
}
