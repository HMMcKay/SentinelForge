import cytoscape, { type Core, type ElementDefinition, type EventObjectNode, type StylesheetStyle } from 'cytoscape';
import { useEffect, useMemo, useRef } from 'react';
import type { TimelineGraph, TimelineNode } from '../types';
import { Icon } from '../components/Icon';

const graphStyles: StylesheetStyle[] = [
  {
    selector: 'node',
    style: {
      'background-color': '#48655e',
      'border-color': '#9ab6ad',
      'border-width': 1,
      color: '#dcece7',
      label: 'data(label)',
      'font-family': 'ui-monospace, SFMono-Regular, Consolas, monospace',
      'font-size': 9,
      'min-zoomed-font-size': 7,
      'text-background-color': '#091411',
      'text-background-opacity': 0.86,
      'text-background-padding': '3px',
      'text-margin-y': 7,
      'text-valign': 'bottom',
      width: 25,
      height: 25,
      'overlay-opacity': 0,
    },
  },
  { selector: 'node[type = "process"]', style: { 'background-color': '#48d8aa', 'border-color': '#b5f9e1', shape: 'round-rectangle', width: 31, height: 25 } },
  { selector: 'node[type = "network"]', style: { 'background-color': '#52a7e8', 'border-color': '#a6d9ff', shape: 'diamond' } },
  { selector: 'node[type = "file"]', style: { 'background-color': '#b897e8', 'border-color': '#decaff', shape: 'rectangle' } },
  { selector: 'node[type = "registry"]', style: { 'background-color': '#f4ba57', 'border-color': '#ffe2a3', shape: 'hexagon' } },
  { selector: 'node[type = "alert"]', style: { 'background-color': '#f06c75', 'border-color': '#ffd2d5', 'border-width': 2, shape: 'octagon', width: 35, height: 35, 'font-weight': 700 } },
  { selector: 'node[type = "scenario"]', style: { 'background-color': '#55c7cd', 'border-color': '#b0f5f7', shape: 'tag' } },
  { selector: 'node[type = "cluster"]', style: { 'background-color': '#294740', 'border-color': '#49e6b3', 'border-style': 'double', 'border-width': 4, shape: 'round-rectangle', width: 42, height: 34 } },
  { selector: 'node[severity = "critical"]', style: { 'border-color': '#ff6673', 'border-width': 3 } },
  { selector: 'node[severity = "high"]', style: { 'border-color': '#f19566', 'border-width': 2 } },
  {
    selector: 'edge',
    style: {
      width: 1.3,
      'line-color': '#405b55',
      'target-arrow-color': '#405b55',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.7,
      'curve-style': 'bezier',
      opacity: 0.72,
      label: 'data(edgeLabel)',
      color: '#93aaa3',
      'font-size': 7,
      'text-background-color': '#07110f',
      'text-background-opacity': 0.8,
      'text-background-padding': '2px',
    },
  },
  { selector: 'edge[type = "process"]', style: { 'line-color': '#49e6b3', 'target-arrow-color': '#49e6b3' } },
  { selector: 'edge[type = "alert"]', style: { 'line-color': '#f06c75', 'target-arrow-color': '#f06c75', 'line-style': 'dashed', width: 2 } },
  { selector: 'edge[type = "scenario"]', style: { 'line-color': '#55c7cd', 'target-arrow-color': '#55c7cd', 'line-style': 'dotted' } },
  { selector: 'edge[type = "correlation"]', style: { 'line-color': '#b897e8', 'target-arrow-color': '#b897e8' } },
  { selector: ':selected', style: { 'border-color': '#ffffff', 'border-width': 4, 'overlay-color': '#ffffff', 'overlay-opacity': 0.08, 'overlay-padding': 7 } },
  { selector: '.context-dim', style: { opacity: 0.12, 'text-opacity': 0 } },
  { selector: '.evidence-highlight', style: { opacity: 1, 'z-index': 999, 'border-color': '#fff2b8', 'border-width': 4 } },
  { selector: 'edge.evidence-highlight', style: { opacity: 1, width: 3, 'line-color': '#ffe28a', 'target-arrow-color': '#ffe28a' } },
  { selector: '.replay-hidden', style: { display: 'none' } },
];

function toElements(graph: TimelineGraph): ElementDefinition[] {
  return [
    ...graph.nodes.map((node) => ({
      group: 'nodes' as const,
      data: {
        id: node.id,
        label: node.label.length > 34 ? `${node.label.slice(0, 32)}…` : node.label,
        type: node.type,
        severity: node.severity,
        timestamp: node.timestamp || '',
      },
    })),
    ...graph.edges.map((edge) => ({
      group: 'edges' as const,
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: edge.type,
        edgeLabel: edge.count && edge.count > 1 ? `${edge.count}×` : edge.label || '',
        timestamp: edge.timestamp || '',
      },
    })),
  ];
}

function evidenceMatch(node: TimelineNode, evidence: Set<string>): boolean {
  return evidence.has(node.id)
    || Boolean(node.eventId && evidence.has(node.eventId))
    || node.memberIds.some((id) => evidence.has(id));
}

export function TimelineCanvas({
  graph,
  selectedId,
  evidenceIds,
  visibleUntil,
  onSelect,
}: {
  graph: TimelineGraph;
  selectedId?: string;
  evidenceIds: string[];
  visibleUntil?: string;
  onSelect: (node?: TimelineNode) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const coreRef = useRef<Core>();
  const nodeMapRef = useRef(new Map<string, TimelineNode>());
  const selectRef = useRef(onSelect);
  const elements = useMemo(() => toElements(graph), [graph]);

  useEffect(() => {
    selectRef.current = onSelect;
  }, [onSelect]);

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const core = cytoscape({
      container: containerRef.current,
      elements: [],
      style: graphStyles,
      minZoom: 0.15,
      maxZoom: 3,
      selectionType: 'single',
      boxSelectionEnabled: true,
      textureOnViewport: true,
      hideEdgesOnViewport: true,
      motionBlur: true,
    });
    coreRef.current = core;
    core.on('tap', 'node', (event: EventObjectNode) => selectRef.current(nodeMapRef.current.get(event.target.id())));
    core.on('tap', (event) => {
      if (event.target === core) selectRef.current(undefined);
    });
    return () => {
      core.destroy();
      coreRef.current = undefined;
    };
  }, []);

  useEffect(() => {
    const core = coreRef.current;
    if (!core) return;
    nodeMapRef.current = new Map(graph.nodes.map((node) => [node.id, node]));
    core.startBatch();
    core.elements().remove();
    core.add(elements);
    core.endBatch();
    const layout = core.layout(graph.nodes.length > 350
      ? { name: 'grid', animate: false, avoidOverlap: true, spacingFactor: 1.25 }
      : {
          name: 'cose',
          animate: false,
          randomize: true,
          componentSpacing: 90,
          idealEdgeLength: () => 90,
          nodeRepulsion: () => 7000,
          gravity: 0.18,
          numIter: 600,
          padding: 34,
        });
    layout.run();
    core.fit(undefined, 42);
  }, [elements, graph.nodes]);

  useEffect(() => {
    const core = coreRef.current;
    if (!core) return;
    core.nodes().unselect();
    if (selectedId) core.getElementById(selectedId).select();
    core.elements().removeClass('context-dim evidence-highlight');
    const evidence = new Set(evidenceIds);
    if (!evidence.size) return;
    core.elements().addClass('context-dim');
    const highlightedIds = new Set<string>();
    graph.nodes.forEach((node) => {
      if (node.id === selectedId || evidenceMatch(node, evidence)) {
        highlightedIds.add(node.id);
        core.getElementById(node.id).removeClass('context-dim').addClass('evidence-highlight');
      }
    });
    core.edges().forEach((edge) => {
      if (highlightedIds.has(edge.source().id()) && highlightedIds.has(edge.target().id())) {
        edge.removeClass('context-dim').addClass('evidence-highlight');
      }
    });
  }, [evidenceIds, graph.nodes, selectedId]);

  useEffect(() => {
    const core = coreRef.current;
    if (!core) return;
    const cutoff = visibleUntil ? new Date(visibleUntil).getTime() : Number.POSITIVE_INFINITY;
    core.nodes().forEach((node) => {
      const timestamp = String(node.data('timestamp'));
      const time = timestamp ? new Date(timestamp).getTime() : Number.NEGATIVE_INFINITY;
      node.toggleClass('replay-hidden', Number.isFinite(time) && time > cutoff);
    });
    core.edges().forEach((edge) => {
      edge.toggleClass('replay-hidden', edge.source().hasClass('replay-hidden') || edge.target().hasClass('replay-hidden'));
    });
  }, [visibleUntil, graph.nodes]);

  const zoom = (factor: number) => {
    const core = coreRef.current;
    if (!core) return;
    core.zoom(Math.max(core.minZoom(), Math.min(core.maxZoom(), core.zoom() * factor)));
    core.center();
  };

  const fit = () => coreRef.current?.fit(coreRef.current.elements(':visible'), 44);
  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === '+' || event.key === '=') zoom(1.25);
    if (event.key === '-') zoom(0.8);
    if (event.key === '0') fit();
    if (event.key === 'Escape') onSelect(undefined);
  };

  return (
    <div className="timeline-canvas-wrap">
      <div
        aria-label={`Forensic graph with ${graph.nodes.length} nodes and ${graph.edges.length} relationships. Use mouse or touch to pan and zoom.`}
        className="timeline-canvas"
        onKeyDown={handleKeyDown}
        ref={containerRef}
        role="img"
        tabIndex={0}
      />
      <div className="graph-controls" aria-label="Graph viewport controls">
        <button aria-label="Zoom in" onClick={() => zoom(1.25)} type="button"><Icon name="zoom-in" size={17} /></button>
        <button aria-label="Zoom out" onClick={() => zoom(0.8)} type="button"><Icon name="zoom-out" size={17} /></button>
        <button aria-label="Fit graph to view" onClick={fit} type="button">Fit</button>
      </div>
      <div className="graph-hint"><span>Drag to pan</span><span>Scroll to zoom</span><span>Box-select with Shift</span></div>
    </div>
  );
}
