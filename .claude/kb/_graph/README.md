# KB Graph — vista tipo Obsidian del knowledge base

Genera un grafo dirigido por fuerzas (estética "red neuronal") a partir de las
notas curadas de `.claude/kb/`. Autocontenido y **offline**: un solo `.html`,
sin CDN ni red.

## Uso
```bash
python3 .claude/kb/_graph/build_graph.py     # -> kb-graph.html
xdg-open .claude/kb/_graph/kb-graph.html     # abrir en el navegador
```

Regenéralo cada vez que agregues/edites notas del KB.

## Qué grafica
- **Nodo** = una nota curada (`techniques/`, `tools/`, `platforms/`, `payloads/`).
  Color = categoría; tamaño = nº de enlaces (grado).
- **Arista**:
  - `wikilink` (azul, sólida) — referencia explícita `[[slug]]` en el cuerpo.
  - `tag` (color mezcla, tenue→brillante) — notas que comparten tags del
    frontmatter; grosor = nº de tags compartidos.

## Interacción
Arrastra nodos · rueda = zoom · click = resalta un nodo y sus vecinos · hover =
tooltip con título, categoría, grado y tags.

## Ajustes (`build_graph.py`)
- `MIN_SHARED_TAGS` — umbral de tags compartidos para crear arista
  (`1` = denso/neuronal, `2` = clusters, `3` = disperso).
- `CONTENT_GLOBS` — qué notas entran (excluye `_template.md`, índice y el árbol
  vendored de la PoC).
- `CATEGORY_COLOR` — paleta por categoría.

> Cuantos más `[[wikilinks]]` pongas entre notas, más se parece al grafo de una
> mente conectada y menos depende de la heurística de tags.
