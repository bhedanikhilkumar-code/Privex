# Agent Handoff & Conflict Resolution Protocol: PRIVEX

## 1. Overview & Purpose

To prevent communication drift, unverified side effects, and race conditions, all autonomous agents in the PRIVEX project must communicate completion using the standardized **Structured Handoff Protocol**.

The Master Orchestrator enforces this protocol as the mandatory quality gate before integrating any agent output into the main codebase.

---

## 2. Standard 11-Point Handoff Schema

When a specialist subagent completes an assigned task, it must return its final response adhering strictly to this markdown structure:

```markdown
### 1. Task Definition
- **Task ID**: [e.g. TASK-CORE-004]
- **Objective**: [Brief description of what was requested]
- **Assigned Role**: [Agent role name]

### 2. Work Performed
- [Detailed summary of architectural design, documentation, or code changes made]

### 3. Files Modified / Created
- `path/to/file1` (Created / Modified / Deleted)
- `path/to/file2`

### 4. Tests Performed
- [List of unit tests, integration tests, benchmark runs, or lint checks executed]
- [Command executed, e.g. `npm test`, `npx vitest run ...`]

### 5. Verification Results
- **Pass / Fail**: [All Passed / X Failed]
- **Coverage**: [Statements % | Lines % | Branches %]
- **Key Metrics**: [e.g. Latency p95: 0.72ms, Accuracy: 100%]

### 6. Architectural Decisions Made
- [Any specific decision taken within the agent's delegated scope]

### 7. Assumptions
- [Assumptions regarding upstream inputs, platform behavior, or hardware]

### 8. Identified Risks & Security Impact
- [Security, privacy, or reliability risks introduced or uncovered]

### 9. Remaining Issues & Blockers
- [Unresolved edge cases, pending dependencies, or deferred items]

### 10. Dependencies on Other Components
- [Subsystems or agents that must be updated as a consequence of this change]

### 11. Recommended Next Action
- [Explicit recommendation for the Master Orchestrator's next step]
```

---

## 3. Seven-Step Conflict Resolution Protocol

If two agents submit changes that conflict, overlap on shared files, or breach architectural contracts, the Master Orchestrator strictly executes this 7-step remediation procedure:

```
┌────────────────────────────────────────────────────────┐
│  STEP 1: HALT INTEGRATION                              │
│  Freeze pending merges; quarantine conflicting outputs │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│  STEP 2: DIFF & CONTRACT COMPARISON                    │
│  Extract AST/textual diff; evaluate interface schema   │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│  STEP 3: IDENTIFY CANONICAL CONTRACT                   │
│  Consult docs/ and types.ts for authoritative source   │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│  STEP 4: CONTRACT CONFORMANCE EVALUATION               │
│  Determine which agent respected the official contract │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ├───────────────────────────────┐
                     [One Conforms]               [Neither Conforms]
                           │                               │
┌──────────────────────────▼─────────────────┐   ┌─────────▼──────────────┐
│  Accept Conforming; Reject Divergent       │   │ Reject Both; Issue RFC │
└──────────────────────────┬─────────────────┘   └─────────┬──────────────┘
                           │                               │
┌──────────────────────────▼───────────────────────────────▼┐
│  STEP 5: DISPATCH REMEDIATION PROMPT                      │
│  Instruct divergent agent with specific contract mismatch │
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────▼────────────────────────────────┐
│  STEP 6: RE-RUN FULL TEST & BENCHMARK SUITE               │
│  Execute regression suite against integrated resolution   │
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────▼────────────────────────────────┐
│  STEP 7: FINAL ATOMIC INTEGRATION                         │
│  Commit cleanly with updated Decision Register entry      │
└───────────────────────────────────────────────────────────┘
```

### Detailed Conflict Resolution Rules:
1. **Never Silently Overwrite**: Merging by "last write wins" is strictly prohibited. Every conflict must be resolved explicitly.
2. **Authority Hierarchy**: In interface disputes:
   - System Architect overrides Platform Specialists.
   - Cybersecurity Architect overrides Feature Specialists on security concerns.
   - Privacy Specialist overrides Feature Specialists on data retention/collection.
   - Master Orchestrator serves as the final binding arbitrator.
3. **Rollback Safety**: The Master Orchestrator maintains git checkpoint tags before integrating multi-agent tasks, enabling immediate clean rollback if conflicts compromise build or test integrity.

---

## 4. Parallel Execution Governance

To ensure Safe Parallelism without triggering merge conflicts:
- **Phase Independence**: Agents operating across separate apps (e.g. `apps/extension` and `apps/mobile`) execute concurrently once `packages/core` contracts are locked.
- **Contract Freezes**: When `packages/core/src/types.ts` is undergoing an update, all downstream platform agents are paused until the new core library is compiled and published locally.
