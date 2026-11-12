"use client";

import { Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { EDGES, INK_ORDER, NODES, NODE_WIDTH, type MapNode, type Side } from "@/lib/system-map";

const POS: Record<Side, Position> = { top: Position.Top, right: Position.Right, bottom: Position.Bottom, left: Position.Left };
const SIDES: Side[] = ["top", "right", "bottom", "left"];

type SysData = MapNode & Record<string, unknown>;

function SystemNode({ data }: NodeProps<Node<SysData>>) {
  return (
    <div className="sysnode" data-later={data.week ? "true" : undefined} data-lead={data.lead ? "true" : undefined} style={{ width: NODE_WIDTH }}>
      {SIDES.map((s) => (
        <Handle key={`t-${s}`} id={`t-${s}`} type="target" position={POS[s]} isConnectable={false} />
      ))}
      {SIDES.map((s) => (
        <Handle key={`s-${s}`} id={`s-${s}`} type="source" position={POS[s]} isConnectable={false} />
      ))}
      {data.week ? <span className="sysnode__week">Week {data.week}</span> : null}
      {data.href ? (
        <Link href={data.href} className="sysnode__title sysnode__link">
          {data.title}
        </Link>
      ) : (
        <span className="sysnode__title">{data.title}</span>
      )}
    </div>
  );
}

const nodeTypes = { system: SystemNode };

/**
 * The system map in React Flow: fixed, not draggable, no zoom on scroll, so it reads like a drawing
 * and its links work like links. The first five nodes ink on once when the map scrolls into view.
 */
export function SystemMap() {
  const wrap = useRef<HTMLDivElement>(null);
  const [ink, setInk] = useState<"rest" | "in">("rest");

  // Drawn at rest from the start, so a reader, a crawler or a capture never meets a blank map. The
  // ink-on plays once, only when the map scrolls in from below, where nobody has seen it yet.
  useEffect(() => {
    const el = wrap.current;
    if (!el || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (el.getBoundingClientRect().top < window.innerHeight) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInk("in");
          io.disconnect();
        }
      },
      { rootMargin: "0px 0px -15% 0px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const nodes = useMemo<Node<SysData>[]>(
    () =>
      NODES.map((n) => {
        const i = INK_ORDER.indexOf(n.id);
        return {
          id: n.id,
          type: "system",
          position: { x: n.x, y: n.y },
          data: { ...n },
          draggable: false,
          selectable: false,
          focusable: false,
          className: i >= 0 ? "ink" : undefined,
          style: i >= 0 ? ({ "--i": i } as CSSProperties) : undefined,
        };
      }),
    [],
  );

  const edges = useMemo<Edge[]>(
    () =>
      EDGES.map((e) => ({
        id: `${e.from}-${e.to}`,
        source: e.from,
        target: e.to,
        sourceHandle: `s-${e.out}`,
        targetHandle: `t-${e.in}`,
        type: "smoothstep",
        focusable: false,
        selectable: false,
        className: e.later ? "edge-later" : undefined,
      })),
    [],
  );

  return (
    <div ref={wrap} className="map-canvas" data-ink={ink} aria-label="System map of unscheduled" role="figure">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.06, maxZoom: 1 }}
        minZoom={0.5}
        maxZoom={1}
        nodesDraggable={false}
        nodesConnectable={false}
        nodesFocusable={false}
        edgesFocusable={false}
        elementsSelectable={false}
        panOnDrag={false}
        panOnScroll={false}
        zoomOnScroll={false}
        zoomOnPinch={false}
        zoomOnDoubleClick={false}
        preventScrolling={false}
        disableKeyboardA11y
        proOptions={{ hideAttribution: false }}
      />
    </div>
  );
}
