// sigil.js — Das Siegel.
//
// Aus dem SHA-256 des öffentlichen Schlüssels wird ein Emblem gezeichnet:
// ein Belichtungsring mit 32 Strichen und ein achsensymmetrisches Gitter.
// Zwei Identitäten mit unterschiedlichen Schlüsseln sehen sofort unterschiedlich
// aus — das macht den Fingerabdruck-Vergleich für Menschen praktikabel.

import { svgEl } from './util.js';

export function sigil(hash, { size = 96, animate = false, title = '' } = {}) {
  const h = hash || new Uint8Array(32);

  const svg = svgEl('svg', {
    class: 'sigil' + (animate ? ' sigil--develop' : ''),
    viewBox: '0 0 100 100',
    width: size,
    height: size,
    role: title ? 'img' : 'presentation',
    'aria-hidden': title ? null : 'true',
    // Der Farbton kommt aus dem Hash, bleibt aber im Blau-Türkis-Band der
    // Gestaltung. Über den ganzen Kreis gestreut kämen Grün- und Rottöne heraus,
    // die gegen den Bernstein-Akzent arbeiten.
    style: { '--sigil-hue': String(155 + Math.round((h[31] / 256) * 120)) }
  });
  if (title) svg.appendChild(svgEl('title', {}, title));

  // Grundplatte
  svg.appendChild(svgEl('circle', { class: 'sg-plate', cx: 50, cy: 50, r: 47 }));
  svg.appendChild(svgEl('circle', { class: 'sg-ring', cx: 50, cy: 50, r: 40.5 }));

  // Belichtungsring: 32 Striche, Länge und Stärke aus je einem Hash-Byte
  const ticks = svgEl('g', { class: 'sg-ticks' });
  for (let i = 0; i < 32; i++) {
    const b = h[i];
    const a = ((i / 32) * Math.PI * 2) - Math.PI / 2;
    const r0 = 41.5;
    const r1 = r0 + 1.5 + (b & 0b111);
    ticks.appendChild(svgEl('line', {
      class: (b & 0b1000) ? 'sg-tick sg-b' : 'sg-tick sg-a',
      x1: (50 + Math.cos(a) * r0).toFixed(2),
      y1: (50 + Math.sin(a) * r0).toFixed(2),
      x2: (50 + Math.cos(a) * r1).toFixed(2),
      y2: (50 + Math.sin(a) * r1).toFixed(2)
    }));
  }
  svg.appendChild(ticks);

  // Gitter 5×5, gespiegelt an der Mittelachse
  const grid = svgEl('g', { class: 'sg-grid' });
  const cell = 9, x0 = 50 - cell * 2.5 + cell / 2, y0 = x0;
  let n = 0;
  for (let col = 0; col < 3; col++) {
    for (let row = 0; row < 5; row++) {
      const b = h[(n + 7) % 32];
      n++;
      const kind = (b >> (col % 3)) & 0b11;
      if (kind === 0) continue;
      const tone = (b & 0b10000) ? 'sg-b' : 'sg-a';
      const cols = col === 2 ? [2] : [col, 4 - col];
      for (const c of cols) {
        const cx = x0 + c * cell, cy = y0 + row * cell;
        const node = kind === 1
          ? svgEl('circle', { class: `sg-cell ${tone}`, cx: cx.toFixed(2), cy: cy.toFixed(2), r: 1.6 })
          : kind === 2
            ? svgEl('circle', { class: `sg-cell ${tone}`, cx: cx.toFixed(2), cy: cy.toFixed(2), r: 2.8 })
            : svgEl('rect', {
              class: `sg-cell ${tone}`, x: (cx - 2.4).toFixed(2), y: (cy - 2.4).toFixed(2),
              width: 4.8, height: 4.8, rx: 1,
              transform: `rotate(45 ${cx.toFixed(2)} ${cy.toFixed(2)})`
            });
        node.style.setProperty('--d', `${(row * 3 + col) * 22}ms`);
        grid.appendChild(node);
      }
    }
  }
  svg.appendChild(grid);

  // Blende in der Mitte
  svg.appendChild(svgEl('circle', { class: 'sg-core', cx: 50, cy: 50, r: (h[0] & 1) ? 3.2 : 2.2 }));

  return svg;
}
