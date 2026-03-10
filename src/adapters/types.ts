import type { Finding } from "../core/scan.js";

export type AdapterContext = {
  cwd: string;
  targetPaths: string[];
  relPaths: string[];
  onWarning?: (message: string) => void;
};

export type Adapter = {
  id: string;
  name: string;
  languages: string[];
  matchFile: (filePath: string) => boolean;
  isAvailable: () => Promise<boolean>;
  run: (context: AdapterContext) => Promise<Finding[]>;
};
