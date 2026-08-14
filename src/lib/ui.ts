import ora, { type Ora } from "ora";
import pc from "picocolors";
import type { RunBus, StageId, RunStartPayload, RunDonePayload } from "../core/events.js";
import type { Severity } from "../stages/normalize/types.js";

/**
 * The human CONSOLE channel. Subscribes to a RunBus and renders a clean CLI:
 * a header, one spinner-backed section per stage that resolves to ✓/✗ with a
 * short result, and a color-coded severity summary. Never prints JSON.
 *
 * Only active in PRETTY mode — in JSON/CI mode the reporter is not attached and
 * the structured logger emits raw JSON to stdout instead.
 */

export interface ReporterOptions {
  verbose: boolean;
}

const STAGE_LABEL: Record<StageId, string> = {
  recon: "Recon",
  scan: "Scan",
  normalize: "Normalize",
  import: "Import",
  report: "Report",
};

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function severityColor(sev: Severity, text: string): string {
  switch (sev) {
    case "CRITICAL":
      return pc.bgRed(pc.white(` ${text} `));
    case "HIGH":
      return pc.red(text);
    case "MEDIUM":
      return pc.yellow(text);
    case "LOW":
      return pc.cyan(text);
    case "INFO":
    default:
      return pc.dim(text);
  }
}

export interface Reporter {
  detach(): void;
}

export function createReporter(bus: RunBus, options: ReporterOptions): Reporter {
  let spinner: Ora | null = null;
  let activeTitle = "";

  /** Print a line without clobbering the live spinner. */
  const printLine = (line: string): void => {
    if (spinner) {
      spinner.clear();
      process.stdout.write(line + "\n");
      spinner.render();
    } else {
      process.stdout.write(line + "\n");
    }
  };

  bus.onRunStart((p: RunStartPayload) => {
    const shortId = p.runId.slice(0, 8);
    const destructive = p.allowDestructive ? pc.bgRed(pc.white(" DESTRUCTIVE ")) : "";
    process.stdout.write("\n");
    process.stdout.write(`  ${pc.cyan("⛨")} ${pc.bold("Cytadel Sentinel")}  ${pc.dim(p.toolName)}\n`);
    process.stdout.write(
      `  ${pc.dim("scope")} ${pc.bold(p.scopeName)}   ${pc.dim("run")} ${pc.bold(shortId)}   ${pc.dim("auth")} ${pc.bold(
        p.authMode,
      )}  ${destructive}\n\n`,
    );
  });

  bus.onStageStart(({ stage, title }) => {
    activeTitle = title || STAGE_LABEL[stage];
    // Keep the spinner on stdout so header/stages/summary form one stream.
    spinner = ora({ text: activeTitle, indent: 2, color: "cyan", stream: process.stdout }).start();
  });

  // Collapse the SCOPE_ACCEPT spam into a single "N/M in scope" line.
  bus.onScopeSummary(({ accepted, total }) => {
    if (spinner) spinner.text = `${activeTitle} ${pc.dim(`— ${accepted}/${total} in scope`)}`;
  });

  bus.onStageProgress(({ message, detail }) => {
    if (detail && !options.verbose) return;
    printLine(`      ${pc.dim("·")} ${pc.dim(message)}`);
  });

  bus.onStageDone(({ stage, summary }) => {
    const text = `${pc.bold(STAGE_LABEL[stage])} ${pc.dim("·")} ${summary}`;
    if (spinner) spinner.succeed(text);
    else printLine(`  ${pc.green("✓")} ${text}`);
    spinner = null;
  });

  bus.onStageFail(({ stage, error }) => {
    const text = `${pc.bold(STAGE_LABEL[stage])} ${pc.red("·")} ${pc.red(error)}`;
    if (spinner) spinner.fail(text);
    else printLine(`  ${pc.red("✗")} ${text}`);
    spinner = null;
  });

  bus.onRunDone((p: RunDonePayload) => {
    process.stdout.write("\n");
    if (p.status === "FAILED") {
      process.stdout.write(`  ${pc.red("✗ run FAILED")}\n`);
      if (p.error) process.stdout.write(`    ${pc.red(p.error)}\n\n`);
      return;
    }

    const counts = p.severity ?? emptyCounts();
    const total = SEVERITY_ORDER.reduce((n, s) => n + (counts[s] ?? 0), 0);
    process.stdout.write(`  ${pc.green("✓ run COMPLETED")}\n`);
    process.stdout.write(`  ${pc.dim("Findings")} ${pc.dim(`(${total})`)}\n`);
    process.stdout.write(
      "    " +
        SEVERITY_ORDER.map((s) => severityColor(s, `${s} ${counts[s] ?? 0}`)).join(pc.dim("   ")) +
        "\n",
    );
    if (p.engagementId) {
      process.stdout.write(`  ${pc.dim("DefectDojo")} engagement #${p.engagementId}\n`);
    }
    if (p.reportPath) {
      const url = pathToFileUrl(p.reportPath);
      process.stdout.write(`  ${pc.dim("Report")} ${pc.cyan(pc.underline(url))}\n`);
    }
    process.stdout.write("\n");
  });

  return {
    detach(): void {
      if (spinner) {
        spinner.stop();
        spinner = null;
      }
      bus.removeAllListeners();
    },
  };
}

function emptyCounts(): Record<Severity, number> {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

/** Absolute file path -> file:// URL that most terminals render as clickable. */
function pathToFileUrl(p: string): string {
  const normalized = p.replace(/\\/g, "/");
  const withSlash = normalized.startsWith("/") ? normalized : "/" + normalized;
  return "file://" + encodeURI(withSlash);
}
