// ChartFrame.tsx — the box a recharts chart is drawn in, for a chart whose
// height is whatever its flex parent has left over.
//
// The chart is positioned OUT OF FLOW on purpose. ResponsiveContainer measures
// its box and then renders an <svg> with that height written on it in pixels.
// Left in flow, that svg is the box's own content — so on a page whose height is
// content-driven (Overview is min-height:100%, not height:100%) the last size the
// chart was measured at becomes the minimum size of the box it measures. It can
// grow and never shrink. That is how Overview came to overflow by exactly the
// height the stat cards gained when their numbers arrived: the charts had been
// measured against the short, still-empty cards and could not give the space
// back. Out of flow, the frame's height comes only from its parent and
// `minHeight`, and the chart follows it in both directions.
//
// The parent must be a flex row (the Card body sets display:flex): the frame
// takes the width by flex and the height by stretch, with no percentage height
// that would need every ancestor's height to be definite.
import type { ReactElement } from "react";
import { ResponsiveContainer } from "recharts";

// The smallest height a chart is still readable at. Below it the frame stops
// shrinking and the page scrolls instead of squeezing the chart into a sliver.
export const CHART_MIN_HEIGHT = 110;

export default function ChartFrame({
  minHeight = CHART_MIN_HEIGHT,
  children,
}: {
  minHeight?: number;
  children: ReactElement;
}) {
  return (
    <div style={{ position: "relative", flex: 1, minWidth: 0, minHeight }}>
      {/* overflow:hidden covers the one frame between the box shrinking and
          recharts redrawing at the new size. */}
      <div style={{ position: "absolute", top: 0, right: 0, bottom: 0, left: 0, overflow: "hidden" }}>
        <ResponsiveContainer>{children}</ResponsiveContainer>
      </div>
    </div>
  );
}
