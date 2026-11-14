import type { Terminal } from "@xterm/xterm";

const ansi = ["#172238", "#f58995", "#61dbb5", "#ffd28a", "#8eaafa", "#d6a8fa", "#83d9ed", "#e3eaf8",
  "#7f91af", "#ffabb3", "#9af1d0", "#ffdfa9", "#b8c9fa", "#e9c8ff", "#b1ebf9", "#f6f8ff"];
function color(value: number, palette: boolean) {
  if (!palette) return `#${value.toString(16).padStart(6, "0")}`;
  if (value < 16) return ansi[value];
  if (value >= 232) return `rgb(${Array(3).fill(8 + (value - 232) * 10).join(",")})`;
  const cube = [0, 95, 135, 175, 215, 255], index = value - 16;
  return `rgb(${cube[Math.floor(index / 36)]},${cube[Math.floor(index / 6) % 6]},${cube[index % 6]})`;
}

// Use xterm's public visible buffer: includes alternate-screen apps and ANSI
// styling, excludes scrollback and never captures the local login dialog.
export function sshPreview(terminal: Terminal) {
  const canvas = document.createElement("canvas");
  canvas.width = 192; canvas.height = 108;
  const ctx = canvas.getContext("2d");
  if (!ctx || !terminal.cols || !terminal.rows) return;
  ctx.fillStyle = "#080c16";
  ctx.fillRect(0, 0, 192, 108);
  const scale = Math.min(192 / (terminal.cols * 9), 108 / (terminal.rows * 18));
  ctx.translate((192 - terminal.cols * 9 * scale) / 2, (108 - terminal.rows * 18 * scale) / 2);
  ctx.scale(scale, scale);
  const buffer = terminal.buffer.active;
  const cell = buffer.getNullCell();
  for (let y = 0; y < terminal.rows; y++) {
    const line = buffer.getLine(buffer.viewportY + y);
    if (!line) continue;
    for (let x = 0; x < terminal.cols; x++) {
      const c = line.getCell(x, cell);
      if (!c || !c.getWidth()) continue;
      let fg = c.isFgDefault() ? "#e3eaf8" : color(c.getFgColor(), c.isFgPalette());
      let bg = c.isBgDefault() ? "#080c16" : color(c.getBgColor(), c.isBgPalette());
      if (c.isInverse()) [fg, bg] = [bg, fg];
      const width = c.getWidth() * 9;
      ctx.fillStyle = bg; ctx.fillRect(x * 9, y * 18, width, 18);
      if (c.isInvisible()) continue;
      ctx.fillStyle = fg;
      ctx.globalAlpha = c.isDim() ? 0.5 : 1;
      ctx.font = `${c.isItalic() ? "italic " : ""}${c.isBold() ? "bold " : ""}15px ${terminal.options.fontFamily}`;
      ctx.fillText(c.getChars(), x * 9, y * 18 + 14, width);
      if (c.isUnderline()) ctx.fillRect(x * 9, y * 18 + 16, width, 1);
      if (c.isStrikethrough()) ctx.fillRect(x * 9, y * 18 + 9, width, 1);
      ctx.globalAlpha = 1;
    }
  }
  const rgba = ctx.getImageData(0, 0, 192, 108).data;
  let pixels = "c06c"; // Width and height, followed by RGBA bytes.
  for (const byte of rgba) pixels += byte.toString(16).padStart(2, "0");
  return { image: canvas.toDataURL("image/png"), pixels };
}
