import { useEffect, useRef } from "react";
import * as d3 from "d3";
import { AttackPath, GraphLink, GraphNode } from "../api/client";

type SimNode = GraphNode & d3.SimulationNodeDatum;
type SimLink = GraphLink & d3.SimulationLinkDatum<SimNode>;

const colors: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  CVE: "#ef4444",
  Package: "#0ea5e9",
  Service: "#8b5cf6",
  Server: "#64748b",
  BusinessData: "#14b8a6",
  ThreatActor: "#111827",
  AttackTechnique: "#f59e0b"
};

export function GraphViewer({ nodes, links, paths }: { nodes: GraphNode[]; links: GraphLink[]; paths: AttackPath[] }) {
  const ref = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const width = ref.current.clientWidth || 900;
    const height = 620;
    const svg = d3.select(ref.current);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const simNodes: SimNode[] = nodes.map((node) => ({ ...node }));
    const simLinks: SimLink[] = links.map((link) => ({ ...link }));
    const hot = new Set(paths.slice(0, 2).flatMap((path) => [path.cve_id, path.package_name, path.service_name, path.data_name]));

    const simulation = d3.forceSimulation(simNodes)
      .force("link", d3.forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(116))
      .force("charge", d3.forceManyBody().strength(-420))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(38));

    const link = svg.append("g")
      .attr("stroke", "#94a3b8")
      .attr("stroke-opacity", 0.5)
      .selectAll("line")
      .data(simLinks)
      .join("line")
      .attr("stroke-width", 1.5);

    const dragBehavior = d3.drag<SVGGElement, SimNode>()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    const node = svg.append("g")
      .selectAll("g")
      .data(simNodes)
      .join("g") as d3.Selection<SVGGElement, SimNode, SVGGElement, unknown>;

    node.call(dragBehavior);

    node.append("circle")
      .attr("r", (d) => hot.has(d.name) ? 15 : 11)
      .attr("fill", (d) => colors[d.severity || d.label] || "#334155")
      .attr("stroke", (d) => hot.has(d.name) ? "#111827" : "#ffffff")
      .attr("stroke-width", (d) => hot.has(d.name) ? 3 : 1.5);

    node.append("text")
      .text((d) => d.name)
      .attr("x", 18)
      .attr("y", 4)
      .attr("class", "nodeLabel");

    node.append("title").text((d) => `${d.label}: ${d.name}`);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => (d.source as SimNode).x || 0)
        .attr("y1", (d) => (d.source as SimNode).y || 0)
        .attr("x2", (d) => (d.target as SimNode).x || 0)
        .attr("y2", (d) => (d.target as SimNode).y || 0);
      node.attr("transform", (d) => `translate(${d.x || 0},${d.y || 0})`);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, links, paths]);

  return (
    <section className="graphStage">
      <svg ref={ref} role="img" aria-label="SecureGraph attack graph" />
    </section>
  );
}
