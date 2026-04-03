import {
  attachConsole,
  debug,
  error,
  info,
  trace,
  warn,
} from "@tauri-apps/plugin-log";
import { isTauriRuntime } from "@/lib/tauri";

let consoleAttached = false;

export async function setupLogging() {
  if (consoleAttached || !isTauriRuntime()) {
    return;
  }

  try {
    await attachConsole();
    consoleAttached = true;
  } catch (err) {
    // If attachConsole fails, log to regular console as fallback
    console.error("Failed to attach console to logging plugin:", err);
  }
}

export const logger = {
  error: (message: string, ...args: unknown[]) => {
    if (!isTauriRuntime()) {
      console.error(message, ...args);
      return;
    }
    error(`${message} ${args.map((arg) => JSON.stringify(arg)).join(" ")}`);
  },
  warn: (message: string, ...args: unknown[]) => {
    if (!isTauriRuntime()) {
      console.warn(message, ...args);
      return;
    }
    warn(`${message} ${args.map((arg) => JSON.stringify(arg)).join(" ")}`);
  },
  info: (message: string, ...args: unknown[]) => {
    if (!isTauriRuntime()) {
      console.info(message, ...args);
      return;
    }
    info(`${message} ${args.map((arg) => JSON.stringify(arg)).join(" ")}`);
  },
  debug: (message: string, ...args: unknown[]) => {
    if (!isTauriRuntime()) {
      console.debug(message, ...args);
      return;
    }
    debug(`${message} ${args.map((arg) => JSON.stringify(arg)).join(" ")}`);
  },
  log: (message: string, ...args: unknown[]) => {
    if (!isTauriRuntime()) {
      console.log(message, ...args);
      return;
    }
    trace(`${message} ${args.map((arg) => JSON.stringify(arg)).join(" ")}`);
  },
};
