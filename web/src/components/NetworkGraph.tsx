import { useEffect, useRef, useState, useCallback } from "react"

export interface GraphNode {
  id: string
  label: string
  size: number
  color: string
  x?: number
  y?: number
  vx?: number
  vy?: number
}

export interface GraphEdge {
  source: string
  target: string
  weight: number
  label?: string
}

interface Props {
  nodes: GraphNode[]
  edges: GraphEdge[]
  width?: number
  height?: number
}

// Force-directed graph with pan/zoom controls.
export function NetworkGraph({ nodes: initNodes, edges, width = 500, height = 400 }: Props) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [hovered, setHovered] = useState<string | null>(null)
  const animRef = useRef<number>(0)

  // Pan & zoom state
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const dragging = useRef(false)
  const dragStart = useRef({ x: 0, y: 0 })
  const panStart = useRef({ x: 0, y: 0 })

  useEffect(() => {
    if (!initNodes.length) return
    const cx = width / 2, cy = height / 2, r = Math.min(width, height) * 0.35
    const positioned = initNodes.map((n, i) => {
      const angle = (2 * Math.PI * i) / initNodes.length
      return { ...n, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), vx: 0, vy: 0 }
    })
    setNodes(positioned)
    setZoom(1)
    setPan({ x: 0, y: 0 })

    let frame = 0
    const maxFrames = 120
    const nodeMap = new Map(positioned.map((n) => [n.id, n]))

    function tick() {
      if (frame >= maxFrames) return
      frame++
      const arr = [...nodeMap.values()]
      // Repulsion
      for (let i = 0; i < arr.length; i++) {
        for (let j = i + 1; j < arr.length; j++) {
          const a = arr[i], b = arr[j]
          let dx = b.x! - a.x!, dy = b.y! - a.y!
          const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy))
          const force = 6000 / (dist * dist)
          dx = (dx / dist) * force
          dy = (dy / dist) * force
          a.vx! -= dx; a.vy! -= dy
          b.vx! += dx; b.vy! += dy
        }
      }
      // Attraction (edges)
      for (const e of edges) {
        const a = nodeMap.get(e.source), b = nodeMap.get(e.target)
        if (!a || !b) continue
        let dx = b.x! - a.x!, dy = b.y! - a.y!
        const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy))
        const idealDist = 100 + (1 / Math.max(1, e.weight)) * 40
        const force = (dist - idealDist) * 0.015
        dx = (dx / dist) * force
        dy = (dy / dist) * force
        a.vx! += dx; a.vy! += dy
        b.vx! -= dx; b.vy! -= dy
      }
      // Center gravity
      for (const n of arr) {
        n.vx! += (cx - n.x!) * 0.003
        n.vy! += (cy - n.y!) * 0.003
      }
      // Apply + damping
      const damping = 0.75 - (frame / maxFrames) * 0.3
      for (const n of arr) {
        n.vx! *= damping; n.vy! *= damping
        n.x! += n.vx!; n.y! += n.vy!
      }
      setNodes([...arr])
      animRef.current = requestAnimationFrame(tick)
    }
    animRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(animRef.current)
  }, [initNodes, edges, width, height])

  // Zoom controls
  const zoomIn = useCallback(() => setZoom((z) => Math.min(5, z * 1.3)), [])
  const zoomOut = useCallback(() => setZoom((z) => Math.max(0.3, z / 1.3)), [])
  const resetView = useCallback(() => { setZoom(1); setPan({ x: 0, y: 0 }) }, [])

  // Mouse wheel zoom
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12
    setZoom((z) => Math.max(0.3, Math.min(5, z * factor)))
  }, [])

  // Pan via mouse drag
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return
    dragging.current = true
    dragStart.current = { x: e.clientX, y: e.clientY }
    panStart.current = { ...pan }
  }, [pan])

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging.current) return
    setPan({
      x: panStart.current.x + (e.clientX - dragStart.current.x) / zoom,
      y: panStart.current.y + (e.clientY - dragStart.current.y) / zoom,
    })
  }, [zoom])

  const handleMouseUp = useCallback(() => { dragging.current = false }, [])

  if (!nodes.length) return null
  const nodeMap = new Map(nodes.map((n) => [n.id, n]))

  const vbX = -pan.x
  const vbY = -pan.y
  const vbW = width / zoom
  const vbH = height / zoom

  return (
    <div className="network-container">
      <div className="network-controls">
        <button className="net-btn" onClick={zoomIn} title="Zoom in">+</button>
        <button className="net-btn" onClick={zoomOut} title="Zoom out">−</button>
        <button className="net-btn" onClick={resetView} title="Reset view">⟲</button>
        <span className="net-zoom-label">{Math.round(zoom * 100)}%</span>
      </div>
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        viewBox={`${vbX} ${vbY} ${vbW} ${vbH}`}
        className="network-svg"
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        {/* Edges */}
        {edges.map((e, i) => {
          const a = nodeMap.get(e.source), b = nodeMap.get(e.target)
          if (!a || !b) return null
          const highlighted = hovered === e.source || hovered === e.target
          return (
            <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={highlighted ? "#818cf8" : "#3a4560"}
              strokeWidth={Math.min(4, 1 + e.weight * 0.5)}
              opacity={highlighted ? 1 : 0.6}
            />
          )
        })}
        {/* Edge labels */}
        {edges.map((e, i) => {
          const a = nodeMap.get(e.source), b = nodeMap.get(e.target)
          if (!a || !b || e.weight < 2) return null
          return (
            <text key={`el${i}`} x={(a.x! + b.x!) / 2} y={(a.y! + b.y!) / 2 - 6}
              textAnchor="middle" fontSize={9} fill="#8a96b2" opacity={0.8}>
              {e.label || e.weight}
            </text>
          )
        })}
        {/* Nodes */}
        {nodes.map((n) => {
          const r = Math.max(10, Math.min(26, n.size))
          return (
            <g key={n.id} onMouseEnter={() => setHovered(n.id)} onMouseLeave={() => setHovered(null)}>
              <circle cx={n.x} cy={n.y} r={r} fill={n.color}
                opacity={hovered === n.id ? 1 : 0.85}
                stroke={hovered === n.id ? "#fff" : "none"} strokeWidth={2} />
              <text x={n.x} y={n.y! + r + 12} textAnchor="middle" fontSize={10} fill="#c8d0e0" fontWeight={500}>
                {n.label}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
