# DEFNETT dashboard

Reading: operator console for a local security lab, with a calm technical voice and an agent-to-collector network map. Dials: ENERGY 2 / RHYTHM 2 / MOTION 1.

- Warm off-white and navy echo the lab architecture; teal marks verified telemetry, amber marks review, and muted red marks an active containment decision.
- The node-and-path motif maps real agent heartbeats, collector analysis, HAProxy, and application backends. It suggests a neural network visually but does not claim the rules engine is a neural model.
- System sans fonts keep labels readable without a network font dependency; monospace is reserved for file paths and hashes so evidence fields scan as identifiers.
- The topology is the primary focal area because the operator needs to see where telemetry flows and which backend currently receives traffic.
- The recovery panel shows each persisted playbook stage, quarantine evidence, and the backend result so operators can audit why a server rejoined or stayed isolated.
- Sections alternate between a wide topology and a compact event ledger so the page follows the investigation from system state to evidence.
- Motion is limited to state changes when fresh data arrives. Reduced-motion preferences disable transitions.
- The dashboard consumes the lab collector API; all visible analysis labels distinguish canary/rule logic from an unconnected ML model.
