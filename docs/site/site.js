"use strict";

const repository = "https://github.com/HMMcKay/SentinelForge";
const stages = {
  simulate: {
    label: "01 / Simulate",
    title: "Create a behavior inside a defined boundary.",
    description:
      "Eight allowlisted scenarios cover benign process chains, encoded PowerShell, scoped registry and task activity, localhost interaction, and file-burst behavior against a synthetic corpus. Dry-run, independent lab gates, and cleanup manifests make the boundary explicit.",
    contract:
      "Known scenario + owned sandbox + cleanup manifest. No arbitrary remote scripts or user-selected targets.",
    link: "/tree/main/simulations",
    linkLabel: "Inspect the simulation runner",
  },
  collect: {
    label: "02 / Collect",
    title: "Read telemetry, then persist before delivery.",
    description:
      "The .NET worker reads the Sysmon channel, batches events, and writes a durable local spool before sending. Bounded exponential backoff handles outages; a disk cap prevents unbounded growth. Sensor identity is protected with Windows DPAPI.",
    contract:
      "Per-sensor authentication + bounded batches + visible degraded health. Spool limits can cause reported loss; this is not a lossless collection claim.",
    link: "/tree/main/agent",
    linkLabel: "Inspect the Windows sensor",
  },
  normalize: {
    label: "03 / Normalize",
    title: "Give every event a stable, versioned shape.",
    description:
      "The ingestion boundary validates timestamps, sensor and host identity, process lineage, activity fields, scenario references, and bounded metadata. Stable event identifiers make repeated delivery idempotent. Raw-event references preserve the connection to the source.",
    contract:
      "Versioned normalized-event schema + parameterized storage + duplicate-safe ingestion. Familiar ECS/OCSF ideas, without a conformance claim.",
    link: "/blob/main/schemas/normalized-event-v1.schema.json",
    linkLabel: "Read the event contract",
  },
  detect: {
    label: "04 / Detect",
    title: "Evaluate a match and preserve its reason.",
    description:
      "A deterministic Sigma-like subset handles field matches and boolean conditions. Stateful correlation adds ordered sequences and thresholds within explicit windows, grouping keys, and deduplication periods. Unsupported rule semantics fail validation.",
    contract:
      "Rule version + matched fields + evidence event IDs + ATT&CK mapping + confidence and severity. A title alone is not an explanation.",
    link: "/blob/main/docs/detection-authoring.md",
    linkLabel: "Read the detection model",
  },
  investigate: {
    label: "05 / Investigate",
    title: "Move from an alert to the actual evidence chain.",
    description:
      "The dashboard presents alert rationale and exact evidence, then links it into a graph of process lineage, activity, correlation, and scenario membership. Filters and event-time replay help reconstruct the sequence; clustering and query bounds keep the view manageable.",
    contract:
      "Typed relationships + stored alert evidence + visible truncation. Graph proximity is not treated as proof of causation.",
    link: "/blob/main/docs/timeline.md",
    linkLabel: "Inspect the forensic timeline",
  },
  verify: {
    label: "06 / Verify",
    title: "Reproduce the result and check the boundary.",
    description:
      "A seeded demo includes positive and near-miss cases. Backend, frontend, CLI, sensor, scenario-safety, and browser tests cover different contracts. Cleanup manifests and verification reverse scenario-owned artifacts. Real Windows integration remains a separate lab exercise.",
    contract:
      "Recorded test results + deterministic fixtures + explicit unverified integrations. Passing mocks are not presented as endpoint evidence.",
    link: "/blob/main/docs/validation-report.md",
    linkLabel: "Read the validation record",
  },
};

document.querySelectorAll("[data-stage]").forEach((button) => {
  button.addEventListener("click", () => {
    const stage = stages[button.dataset.stage];
    document
      .querySelectorAll("[data-stage]")
      .forEach((item) =>
        item.setAttribute("aria-pressed", String(item === button)),
      );
    document.getElementById("stage-label").textContent = stage.label;
    document.getElementById("stage-title").textContent = stage.title;
    document.getElementById("stage-description").textContent =
      stage.description;
    document.getElementById("stage-contract").textContent = stage.contract;
    const link = document.getElementById("stage-link");
    link.href = repository + stage.link;
    link.textContent = stage.linkLabel + " ↗";
  });
});

const dialog = document.getElementById("image-dialog");
document.querySelectorAll("[data-image]").forEach((button) => {
  button.addEventListener("click", () => {
    const image = document.getElementById("dialog-image");
    image.src = button.dataset.image;
    image.alt = button.querySelector("img").alt;
    document.getElementById("image-caption").textContent =
      button.dataset.caption;
    dialog.showModal();
  });
});
dialog.addEventListener("click", (event) => {
  if (event.target === dialog) {
    const bounds = dialog.getBoundingClientRect();
    if (
      event.clientX < bounds.left ||
      event.clientX > bounds.right ||
      event.clientY < bounds.top ||
      event.clientY > bounds.bottom
    )
      dialog.close();
  }
});

document.getElementById("copy-commands").addEventListener("click", async () => {
  const status = document.getElementById("copy-status");
  try {
    await navigator.clipboard.writeText(
      document.getElementById("run-commands").textContent.trim(),
    );
    status.textContent =
      "Commands copied. Review them before running in your local checkout.";
  } catch {
    status.textContent =
      "Clipboard access is unavailable. Select the commands above and copy them manually.";
  }
});
