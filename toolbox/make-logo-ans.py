#!/usr/bin/env python3
"""Pre-renderiza toolbox/gekko-logo.png → toolbox/gekko-logo.ans (arte ANSI half-block,
truecolor, respetando transparencia). Half-block ▀: un carácter = 2 píxeles verticales
(fg = píxel de arriba, bg = píxel de abajo). Las zonas transparentes quedan sin color,
así el logo se funde con cualquier fondo de terminal. Reproducible: regenerá con

    python3 toolbox/make-logo-ans.py [ancho_en_celdas]

El .ans resultante lo imprime el banner de tools/pi-hitl.sh. Sin dependencia de chafa.
"""
import sys
from pathlib import Path
from PIL import Image

HERE = Path(__file__).resolve().parent
SRC = HERE / "gekko-logo.png"
DST = HERE / "gekko-logo.ans"
W = int(sys.argv[1]) if len(sys.argv) > 1 else 40  # ancho en celdas (= píxeles de ancho)

im = Image.open(SRC).convert("RGBA")
ph = round(W * im.height / im.width)
ph += ph % 2                     # alto par: cada fila de texto = 2 píxeles
im = im.resize((W, ph), Image.LANCZOS)
px = im.load()

def opaque(p): return p[3] > 128

out = []
for ry in range(ph // 2):
    cells = []
    for x in range(W):
        t = px[x, ry * 2]
        b = px[x, ry * 2 + 1]
        to, bo = opaque(t), opaque(b)
        if to and bo:
            cells.append(f"\033[0m\033[38;2;{t[0]};{t[1]};{t[2]};48;2;{b[0]};{b[1]};{b[2]}m▀")
        elif to:
            cells.append(f"\033[0m\033[38;2;{t[0]};{t[1]};{t[2]}m▀")  # ▀ sólo arriba
        elif bo:
            cells.append(f"\033[0m\033[38;2;{b[0]};{b[1]};{b[2]}m▄")  # ▄ sólo abajo
        else:
            cells.append("\033[0m ")                                      # transparente
    cells.append("\033[0m")
    out.append("".join(cells))

DST.write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"escrito {DST} — {W} celdas de ancho, {ph // 2} filas")
