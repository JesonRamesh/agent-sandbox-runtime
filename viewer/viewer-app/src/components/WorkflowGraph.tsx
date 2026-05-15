import { useState } from "react";
import "./WorkflowGraph.css";
import WorkflowLayerToggle from "./WorkflowLayerToggle";
import UnifiedFlowLayer    from "./UnifiedFlowLayer";

import AgentFlowLayer    from './AgentFlowLayer';
import KernelFlowLayer   from './KernelFlowLayer';

interface WorkflowGraphProps {
  llmEvents: any[];
  kernelEvents: any[];
}

export default function WorkflowGraph({ llmEvents, kernelEvents }: WorkflowGraphProps) {
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
