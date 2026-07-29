---
title: Bad Epoll — kernel epoll UAF privesc (CVE-2026-46242)
slug: bad-epoll-privesc
category: techniques
updated: 2026-07-04
summary: "CVE-2026-46242 kernel epoll UAF (race cond.) → root, incl. Android; build/run de la PoC pública"
tags: [linux, kernel, privesc, race-condition, uaf, epoll, android]
sensitive: false
---

# Bad Epoll — kernel epoll UAF privesc (CVE-2026-46242)

## When to use
Shell de bajo privilegio en Linux con kernel v6.4–v7.0 sin el parche `a6dc643c6931`
(o Android con kernel v6.4+, ej. Pixel 10). Kernel exploit de última instancia —
**agotar sudo/SUID/caps/cron primero** (ver `[[privilege-escalation]]`). Requiere
compilar C++ contra el target real; no hay binario genérico plug-and-play.

## Qué es
Race condition (UAF) en el subsistema `epoll`, introducida en el commit
`58c9b016e128` (2023-04-08), parcheada en `a6dc643c6931` (2026-04-24). Afecta
v6.4–v7.0. No tiene kill-switch (epoll es núcleo, no se puede descargar) y se
puede disparar dentro del sandbox de renderer de Chrome — puede rootear Android
(pocos bugs de la serie "Bad *" logran esto).

Fue la segunda de dos races introducidas por el mismo commit; la primera
(CVE-2026-43074) la encontró la IA de Anthropic Mythos, pero **Mythos no
encontró esta** — ventana de ~6 instrucciones y normalmente no dispara KASAN.

## Root cause
`ep_remove()` limpia `file->f_ep` bajo `file->f_lock` pero sigue usando el
objeto `file` dentro de la sección crítica (`hlist_del_rcu()` + `spin_unlock()`).
Un `__fput()` concurrente puede observar el NULL transitorio, saltarse
`eventpoll_release_file()`, y liberar un `struct eventpoll` todavía vigilado →
UAF write-0 de 8 bytes en offset 160 de un objeto kmalloc-192 liberado. Como
`struct file` usa `SLAB_TYPESAFE_BY_RCU`, el slot liberado se puede reciclar vía
`alloc_empty_file()` → cross-cache attack sobre un `struct file`.

Cadena completa: KASLR leak (prefetch side-channel) → trigger de la race (4
objetos epoll en 2 pares; false-sharing + IRQ de un `timerfd` compartido para
ensanchar la ventana) → UAF write-0 → cross-cache sobre `struct file` (vía pipe)
→ arbitrary kernel read por `/proc/self/fdinfo` → hijack de `file->f_op->poll`
→ ROP chain → root shell.

## Key facts / commands

| Campo | Valor |
|---|---|
| CVE | CVE-2026-46242 |
| Nombre | "Bad Epoll" (serie Bad Binder / Bad IO_uring / Bad Spin) |
| Bug introducido | `58c9b016e128` (2023-04-08) |
| Parche | `a6dc643c6931` (2026-04-24) |
| Versiones afectadas | v6.4-rc1 – v7.0 (v6.1 y anteriores NO afectados) |
| Requisito kernel config | `CONFIG_EPOLL` (casi siempre on) |
| Fiabilidad del PoC | 99% en `lts-6.12.67`, 98% en `cos-121-18867.294.100` |
| Android | Pixel 10 (v6.6+) vulnerable, exploit de root en progreso; Pixel 8 y dispositivos v6.1-based NO afectados |
| Descubridor | Jaeyoung Chung (CompSec Lab, SNU) vía Google kernelCTF |

### Compilar y correr la PoC — bundle vendorizado (offline, preferido)
Todo el código, docs, y dependencias de build (`libxdk`/`kernel-research`,
`target_db.kxdb`) están vendorizados en este repo bajo
`.claude/kb/payloads/bad-epoll-cve-2026-46242/` — no depende de que GitHub/GCS
sigan sirviendo las fuentes. Ver el `README.md` de ese bundle para el
procedimiento completo y la procedencia (commits, licencias).
```bash
BUNDLE=".claude/kb/payloads/bad-epoll-cve-2026-46242"
cd "$BUNDLE/exploit/lts-6.12.67"
cp -r ../../vendor/kernel-research . && cp ../../vendor/target_db.kxdb .
make && ./exploit    # sin red; ver gotchas del bundle si falla
```
Target alternativo: `cos-121-18867.294.100/` (mismo `exploit.cpp` symlinkeado).

### Compilar desde upstream (si se necesita la versión más reciente)
```bash
git clone -b submit-cve-2026-46242 https://github.com/J-jaeyoung/security-research.git
cd security-research/pocs/linux/kernelctf/CVE-2026-46242_lts_cos/exploit/lts-6.12.67
# Prereqs: g++, cmake, make, wget, git, libkeyutils-dev
make            # clona google/kernel-research, compila libxdk, baja target_db.kxdb (red: storage.googleapis.com)
./exploit        # o: make run
```

## Gotchas
- **No es un binario genérico de privesc.** El exploit está afinado para los
  kernels exactos de kernelCTF (`lts-6.12.67`, `cos-121-18867.294.100`) — offsets
  SLUB (`SLAB_CPU_PARTIAL_192/256`, `SLAB_OBJ_PER_SLAB_192/256`), tamaño de
  `struct file` (192 vs 256), y la base de auto-detección `target_db.kxdb` son
  específicos de esos builds. Contra un kernel de engagement con la misma
  versión mayor probablemente haga falta re-tunear offsets.
- El build necesita `g++`/`cmake`/`make`/`libkeyutils-dev` en el host que
  compila (no en este sandbox de análisis) — usar la máquina del operador o el
  target si tiene toolchain. Con el bundle vendorizado (arriba) no hace falta
  red; con el flujo upstream sí (`git clone` + `wget` a `storage.googleapis.com`).
- Ventana de carrera de solo ~6 instrucciones — depende de CPU pinning y de un
  `timerfd` compartido con ~3000 waiters async para ensancharla; no esperar la
  misma fiabilidad si se porta a hardware distinto sin ajustar
  `RACE_ENQUEUE_FORKS` / `RACE_WAITER_EPFDS` / `RACE_WAITER_DUPS`.
- Mitigación: solo aplicar el parche upstream o el backport de la distro; no
  hay workaround (epoll no se puede descargar sin romper el sistema).

## References
- Relacionado: [[privilege-escalation]], [[bad-epoll-cve-2026-46242]] (bundle vendorizado)
- **Bundle vendorizado (offline, código + deps de build)**: `.claude/kb/payloads/bad-epoll-cve-2026-46242/`
- Resumen público: https://github.com/J-jaeyoung/bad-epoll
- Root-cause writeup: https://github.com/J-jaeyoung/security-research/blob/submit-cve-2026-46242/pocs/linux/kernelctf/CVE-2026-46242_lts_cos/docs/vulnerability.md
- Exploit writeup: https://github.com/J-jaeyoung/security-research/blob/submit-cve-2026-46242/pocs/linux/kernelctf/CVE-2026-46242_lts_cos/docs/exploit.md
- Código fuente: https://github.com/J-jaeyoung/security-research/blob/submit-cve-2026-46242/pocs/linux/kernelctf/CVE-2026-46242_lts_cos/exploit/lts-6.12.67/exploit.cpp
- Patch commit: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a6dc643c69311677c574a0f17a3f4d66a5f3744b
- CVE relacionada (encontrada por Mythos): CVE-2026-43074
- Cobertura: https://thehackernews.com/2026/07/new-bad-epoll-linux-kernel-flaw-lets.html
