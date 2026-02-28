import os from "node:os";
import { loadGlobalConfig, saveGlobalConfig, type GlobalConfig } from "./config.js";

export type TelemetryEvent = {
    event: string;
    properties?: Record<string, string | number | boolean>;
    timestamp: string;
};

export type TelemetryConfig = {
    enabled: boolean;
    endpoint?: string;
};

const DEFAULT_ENDPOINT = "https://telemetry.opensecurity.dev/v1/events";

/**
 * Check if telemetry is enabled.
 * Respects:
 *   1. OPENSECURITY_TELEMETRY env var (0/false to disable, 1/true to enable)
 *   2. Global config `telemetry.enabled` field
 *   3. Defaults to false (opt-in)
 */
export function isTelemetryEnabled(
    config: GlobalConfig,
    env = process.env
): boolean {
    const envVal = env.OPENSECURITY_TELEMETRY?.trim().toLowerCase();
    if (envVal === "0" || envVal === "false") return false;
    if (envVal === "1" || envVal === "true") return true;
    return (config as any).telemetry?.enabled === true;
}

/**
 * Enable or disable telemetry in the global config.
 */
export async function setTelemetryEnabled(
    enabled: boolean,
    env = process.env
): Promise<void> {
    const config = await loadGlobalConfig(env);
    const updated = {
        ...config,
        telemetry: { ...((config as any).telemetry ?? {}), enabled }
    };
    await saveGlobalConfig(updated, env);
}

/**
 * Build a telemetry event with system-level (non-identifying) metadata.
 */
export function createEvent(
    event: string,
    properties: Record<string, string | number | boolean> = {}
): TelemetryEvent {
    return {
        event,
        properties: {
            ...properties,
            os: process.platform,
            arch: process.arch,
            nodeVersion: process.version,
            cliVersion: "0.1.0"
        },
        timestamp: new Date().toISOString()
    };
}

/**
 * Send a telemetry event. No-ops if telemetry is disabled.
 * Never throws — all errors are silently swallowed to avoid
 * impacting the user experience.
 */
export async function sendEvent(
    event: TelemetryEvent,
    config: GlobalConfig,
    env = process.env
): Promise<void> {
    if (!isTelemetryEnabled(config, env)) return;

    const endpoint = (config as any).telemetry?.endpoint ?? DEFAULT_ENDPOINT;

    try {
        await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(event),
            signal: AbortSignal.timeout(3000)
        });
    } catch {
        // Silently ignore — telemetry must never interrupt the user
    }
}

/**
 * Convenience: create + send in one call.
 */
export async function trackEvent(
    eventName: string,
    properties: Record<string, string | number | boolean> = {},
    config: GlobalConfig,
    env = process.env
): Promise<void> {
    const event = createEvent(eventName, properties);
    await sendEvent(event, config, env);
}
