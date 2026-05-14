import { useState } from "react";
import "./WorkflowGraph.css";
import WorkflowLayerToggle from "./WorkflowLayerToggle.jsx";
import UnifiedFlowLayer    from "./UnifiedFlowLayer.jsx";

import AgentFlowLayer    from './AgentFlowLayer.jsx';
import KernelFlowLayer   from './KernelFlowLayer.jsx';

export default function WorkflowGraph({ llmEvents, kernelEvents }) {
  const [activeLayer, setActiveLayer] = useState("unified");

  return (
    <div className="wf-wrapper">
      <WorkflowLayerToggle activeLayer={activeLayer} onSwitch={setActiveLayer} />

      {/* Unified layer - original graph, zero changes */}
      {activeLayer === "unified" && (
        <UnifiedFlowLayer llmEvents={llmEvents} kernelEvents={kernelEvents} />
      )}

      {/* Agent Activity layer */}
      {activeLayer === "agent" && (
        <AgentFlowLayer llmEvents={llmEvents} kernelEvents={kernelEvents} />
      )}

      {/* Kernel Verdicts layer */}
      {activeLayer === "kernel" && (
        <KernelFlowLayer llmEvents={llmEvents} kernelEvents={kernelEvents} />
      )}
    </div>
  );
}
