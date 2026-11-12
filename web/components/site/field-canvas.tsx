"use client";

import { useEffect, useRef } from "react";
import { layoutField, LABEL_CELLS, type FieldData, type FieldLayout, type Tone } from "@/lib/field";
import { formatDate, formatInt, formatShare } from "@/lib/format";

const CELL_W = 8;
const CELL_H = 16;
const LENS = 56;
const FRAME_MS = 1000 / 30;

const TONE_VARS: Record<Exclude<Tone, 0>, string> = {
  1: "--color-glyph-1",
  2: "--color-glyph-2",
  3: "--color-glyph-3",
  4: "--color-glyph-4",
  5: "--color-accent-deep",
  6: "--color-muted",
};

/**
 * The field on one canvas: a character per cell, tinted by the share analyzed. A lens follows the
 * pointer at 30 frames a second at most, only while the field is on screen; under reduced motion it
 * is one composed still. The readout under it names the day under the pointer.
 */
export function FieldCanvas({ data, readoutId }: { data: FieldData; readoutId: string }) {
  const canvas = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const el = canvas.current;
    const figure = el?.closest("figure");
    const readout = document.getElementById(readoutId);
    if (!el || !figure) return;
    const ctx = el.getContext("2d");
    if (!ctx) return;
    const still = matchMedia("(prefers-reduced-motion: reduce)");
    let layout: FieldLayout | null = null;
    let width = 0;
    let height = 0;
    let offsetX = 0;
    let colors: Record<number, string> = {};
    let pointer: { x: number; y: number } | null = null;
    let visible = true;
    let last = 0;
    let frame = 0;

    const readColors = () => {
      const css = getComputedStyle(document.documentElement);
      colors = Object.fromEntries(Object.entries(TONE_VARS).map(([k, v]) => [Number(k), css.getPropertyValue(v).trim()]));
    };

    const draw = () => {
      if (!layout) return;
      const dpr = window.devicePixelRatio || 1;
      if (el.width !== Math.round(width * dpr) || el.height !== Math.round(height * dpr)) {
        el.width = Math.round(width * dpr);
        el.height = Math.round(height * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);
      ctx.font = `13px ${getComputedStyle(el).fontFamily}`;
      ctx.textBaseline = "middle";
      const lens = pointer && !still.matches ? pointer : null;
      layout.rows.forEach((row, r) => {
        const cy = r * CELL_H + CELL_H / 2;
        row.cells.forEach((cell, c) => {
          if (cell.tone === 0) return;
          const cx = offsetX + c * CELL_W;
          let tone: Exclude<Tone, 0> = cell.tone;
          if (lens && tone !== 6) {
            const d = Math.hypot(cx + CELL_W / 2 - lens.x, cy - lens.y);
            if (d < LENS) tone = Math.min(5, tone + (d < LENS / 2 ? 2 : 1)) as Exclude<Tone, 0>;
          }
          ctx.fillStyle = colors[tone] ?? colors[1];
          ctx.fillText(cell.ch, cx, cy);
        });
      });
    };

    const fit = () => {
      const box = el.getBoundingClientRect();
      width = box.width;
      height = box.height;
      const cpd = width >= (LABEL_CELLS + 62) * CELL_W ? 2 : 1;
      layout = layoutField(data, cpd);
      offsetX = Math.max(0, Math.floor((width - layout.columns * CELL_W) / 2));
      draw();
      figure.setAttribute("data-live", "true");
    };

    const describe = (x: number, y: number) => {
      if (!layout || !readout) return;
      const row = layout.rows[Math.floor(y / CELL_H)];
      const cell = row?.cells[Math.floor((x - offsetX) / CELL_W)];
      const day = cell && cell.day >= 0 ? [...data.days].sort((a, b) => (a.date < b.date ? -1 : 1))[cell.day] : null;
      readout.textContent = day
        ? `${formatDate(day.date, "long")}: ${formatInt(day.published)} new CVEs, ${day.analyzed_30d === null ? "not yet 30 days old" : `${formatShare(day.analyzed_30d)} analyzed by the NVD within 30 days`}.`
        : "";
    };

    const onMove = (e: PointerEvent) => {
      const box = el.getBoundingClientRect();
      pointer = { x: e.clientX - box.left, y: e.clientY - box.top };
      describe(pointer.x, pointer.y);
      if (!visible || still.matches) return;
      const now = performance.now();
      if (now - last < FRAME_MS) {
        cancelAnimationFrame(frame);
        frame = requestAnimationFrame(() => {
          last = performance.now();
          draw();
        });
        return;
      }
      last = now;
      draw();
    };
    const onLeave = () => {
      pointer = null;
      if (readout) readout.textContent = "";
      draw();
    };
    const recolor = () => {
      readColors();
      draw();
    };

    readColors();
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
    });
    io.observe(el);
    const scheme = matchMedia("(prefers-color-scheme: dark)");
    scheme.addEventListener("change", recolor);
    window.addEventListener("themechange", recolor);
    el.addEventListener("pointermove", onMove);
    el.addEventListener("pointerleave", onLeave);
    void document.fonts?.ready.then(() => draw());

    return () => {
      ro.disconnect();
      io.disconnect();
      cancelAnimationFrame(frame);
      scheme.removeEventListener("change", recolor);
      window.removeEventListener("themechange", recolor);
      el.removeEventListener("pointermove", onMove);
      el.removeEventListener("pointerleave", onLeave);
    };
  }, [data, readoutId]);

  return <canvas ref={canvas} className="hero-field__canvas mono" aria-hidden="true" />;
}
