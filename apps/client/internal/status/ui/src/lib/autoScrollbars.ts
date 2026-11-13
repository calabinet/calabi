// Shared by nested panes and portals. Keep the gutter width stable while only
// painting the thumb during user scrolling; idle log auto-follow stays quiet.
export function installAutoScrollbars() {
  const active = new Map<HTMLElement, ReturnType<typeof setTimeout>>();
  const pinned = new Set<HTMLElement>();
  const hide = (element: HTMLElement) => {
    element.classList.remove("scrollbar-active");
    active.delete(element);
  };
  const show = (element: HTMLElement) => {
    clearTimeout(active.get(element));
    element.classList.add("scrollbar-active");
    active.set(element, setTimeout(() => {
      if (!pinned.has(element)) hide(element);
    }, 900));
  };
  const wheel = (event: WheelEvent) => {
    const dx = event.deltaX || (event.shiftKey ? event.deltaY : 0);
    const dy = event.shiftKey ? 0 : event.deltaY;
    let element = event.target instanceof Element ? event.target : null;
    for (; element; element = element.parentElement) {
      if (!(element instanceof HTMLElement)) continue;
      const style = getComputedStyle(element);
      const movable = (delta: number, offset: number, maximum: number, overflow: string) =>
        /^(auto|scroll|overlay)$/.test(overflow) && maximum > 1 &&
        (delta < 0 ? offset > 0 : delta > 0 && offset < maximum - 1);
      if (movable(dy, element.scrollTop, element.scrollHeight - element.clientHeight, style.overflowY) ||
          movable(dx, element.scrollLeft, element.scrollWidth - element.clientWidth, style.overflowX)) {
        show(element);
        break;
      }
    }
  };
  const down = (event: PointerEvent) => {
    for (const element of active.keys()) {
      if (event.target instanceof Node && element.contains(event.target)) pinned.add(element);
    }
  };
  const release = () => {
    for (const element of pinned) show(element);
    pinned.clear();
  };
  const clear = () => {
    for (const [element, timer] of active) { clearTimeout(timer); hide(element); }
    pinned.clear();
  };
  document.addEventListener("wheel", wheel, { capture: true, passive: true });
  document.addEventListener("pointerdown", down, true);
  document.addEventListener("pointerup", release, true);
  document.addEventListener("pointercancel", release, true);
  window.addEventListener("blur", release);
  document.addEventListener("visibilitychange", clear);
  return () => {
    clear();
    document.removeEventListener("wheel", wheel, true);
    document.removeEventListener("pointerdown", down, true);
    document.removeEventListener("pointerup", release, true);
    document.removeEventListener("pointercancel", release, true);
    window.removeEventListener("blur", release);
    document.removeEventListener("visibilitychange", clear);
  };
}
