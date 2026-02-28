import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
    isTelemetryEnabled,
    setTelemetryEnabled,
    createEvent
} from "../src/telemetry.js";
import { loadGlobalConfig } from "../src/config.js";

describe("telemetry", () => {
    let tmpDir: string;
    let env: Record<string, string>;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "telemetry-test-"));
        env = { OPENSECURITY_CONFIG_HOME: tmpDir };
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("defaults to disabled (opt-in)", async () => {
        const config = await loadGlobalConfig(env);
        expect(isTelemetryEnabled(config, env)).toBe(false);
    });

    it("respects OPENSECURITY_TELEMETRY env var", async () => {
        const config = await loadGlobalConfig(env);
        expect(isTelemetryEnabled(config, { ...env, OPENSECURITY_TELEMETRY: "1" })).toBe(true);
        expect(isTelemetryEnabled(config, { ...env, OPENSECURITY_TELEMETRY: "false" })).toBe(false);
    });

    it("enables via setTelemetryEnabled", async () => {
        await setTelemetryEnabled(true, env);
        const config = await loadGlobalConfig(env);
        expect(isTelemetryEnabled(config, env)).toBe(true);
    });

    it("disables via setTelemetryEnabled", async () => {
        await setTelemetryEnabled(true, env);
        await setTelemetryEnabled(false, env);
        const config = await loadGlobalConfig(env);
        expect(isTelemetryEnabled(config, env)).toBe(false);
    });

    it("createEvent includes system metadata", () => {
        const event = createEvent("test_event", { custom: "value" });
        expect(event.event).toBe("test_event");
        expect(event.properties?.custom).toBe("value");
        expect(event.properties?.os).toBe(process.platform);
        expect(event.properties?.arch).toBe(process.arch);
        expect(event.properties?.cliVersion).toBe("0.1.0");
        expect(event.timestamp).toBeTruthy();
    });
});
