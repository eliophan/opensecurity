/**
 * CLI UX utilities: progress spinner, verbose logging, and formatting.
 */

export type LogLevel = "silent" | "normal" | "verbose";

export type ProgressOptions = {
    verbose?: boolean;
    silent?: boolean;
};

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_INTERVAL = 80;

export class Logger {
    private level: LogLevel;

    constructor(options: ProgressOptions = {}) {
        if (options.silent) {
            this.level = "silent";
        } else if (options.verbose) {
            this.level = "verbose";
        } else {
            this.level = "normal";
        }
    }

    info(message: string): void {
        if (this.level === "silent") return;
        console.error(`ℹ ${message}`);
    }

    verbose(message: string): void {
        if (this.level !== "verbose") return;
        console.error(`  ${dim(message)}`);
    }

    success(message: string): void {
        if (this.level === "silent") return;
        console.error(`✅ ${message}`);
    }

    warn(message: string): void {
        if (this.level === "silent") return;
        console.error(`⚠️  ${message}`);
    }

    error(message: string): void {
        console.error(`❌ ${message}`);
    }
}

export class Spinner {
    private frame = 0;
    private timer: ReturnType<typeof setInterval> | null = null;
    private message: string;
    private stream: NodeJS.WriteStream;
    private active = false;

    constructor(message: string) {
        this.message = message;
        this.stream = process.stderr;
    }

    start(): void {
        if (!this.stream.isTTY) return;
        this.active = true;
        this.render();
        this.timer = setInterval(() => this.render(), SPINNER_INTERVAL);
    }

    update(message: string): void {
        this.message = message;
    }

    stop(finalMessage?: string): void {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
        if (this.active) {
            this.clearLine();
            if (finalMessage) {
                this.stream.write(`${finalMessage}\n`);
            }
        }
        this.active = false;
    }

    private render(): void {
        const symbol = SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length];
        this.frame += 1;
        this.clearLine();
        this.stream.write(`${symbol} ${this.message}`);
    }

    private clearLine(): void {
        this.stream.write("\r\x1b[K");
    }
}

/**
 * Format duration in human-readable form.
 */
export function formatDuration(ms: number): string {
    if (ms < 1000) return `${Math.round(ms)}ms`;
    const seconds = ms / 1000;
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.round(seconds % 60);
    return `${minutes}m ${remainingSeconds}s`;
}

/**
 * Format a count with plural suffix.
 */
export function pluralize(count: number, singular: string, plural?: string): string {
    return count === 1 ? `${count} ${singular}` : `${count} ${plural ?? singular + "s"}`;
}

/**
 * Dim text using ANSI escape codes (stderr only).
 */
function dim(text: string): string {
    return `\x1b[2m${text}\x1b[0m`;
}

/**
 * Bold text using ANSI escape codes.
 */
export function bold(text: string): string {
    return `\x1b[1m${text}\x1b[0m`;
}

/**
 * Colored severity label.
 */
export function severityColor(severity: string): string {
    switch (severity) {
        case "critical":
            return `\x1b[31m${severity.toUpperCase()}\x1b[0m`; // red
        case "high":
            return `\x1b[33m${severity.toUpperCase()}\x1b[0m`; // yellow
        case "medium":
            return `\x1b[36m${severity.toUpperCase()}\x1b[0m`; // cyan
        case "low":
            return `\x1b[34m${severity.toUpperCase()}\x1b[0m`; // blue
        default:
            return severity.toUpperCase();
    }
}
