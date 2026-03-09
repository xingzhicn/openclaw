import fs from "node:fs";
import path from "node:path";
import { openBoundaryFile, type BoundaryFileOpenResult } from "../../infra/boundary-file-read.js";
import type { PathAliasPolicy } from "../../infra/path-alias-guards.js";
import type { SafeOpenSyncAllowedType } from "../../infra/safe-open-sync.js";
import type { SandboxResolvedFsPath, SandboxFsMount } from "./fs-paths.js";
import { isPathInsideContainerRoot, normalizeContainerPath } from "./path-utils.js";

// Blacklist files for security
const BLACKLIST_FILES = [
  '.openclaw.json',
  'openclaw-cfg',
  '.bashrc',
  '.bash_profile',
  '.profile',
  '.zshrc',
  '.bash_login'
];

export type PathSafetyOptions = {
  action: string;
  aliasPolicy?: PathAliasPolicy;
  requireWritable?: boolean;
  allowedType?: SafeOpenSyncAllowedType;
};

export type PathSafetyCheck = {
  target: SandboxResolvedFsPath;
  options: PathSafetyOptions;
};

export type AnchoredSandboxEntry = {
  canonicalParentPath: string;
  basename: string;
};

type RunCommand = (
  script: string,
  options?: {
    args?: string[];
    stdin?: Buffer | string;
    allowFailure?: boolean;
    signal?: AbortSignal;
  },
) => Promise<{ stdout: Buffer }>;

export class SandboxFsPathGuard {
  private readonly mountsByContainer: SandboxFsMount[];
  private readonly runCommand: RunCommand;

  constructor(params: { mountsByContainer: SandboxFsMount[]; runCommand: RunCommand }) {
    this.mountsByContainer = params.mountsByContainer;
    this.runCommand = params.runCommand;
  }

  private validateFileAccess(filePath: string): void {
    const basename = path.basename(filePath);
    const dirname = path.dirname(filePath);

    for (const blacklisted of BLACKLIST_FILES) {
      if (basename === blacklisted || basename.includes(blacklisted)) {
        throw new Error(
          `为保护 Agent 环境完整性，禁止修改系统关键文件: ${basename}`
        );
      }
    }

    if (dirname.includes('openclaw-cfg') || filePath.includes('openclaw-cfg')) {
      throw new Error('禁止访问 OpenClaw 配置目录');
    }
  }

  async assertPathChecks(checks: PathSafetyCheck[]): Promise<void> {
    for (const check of checks) {
      await this.assertPathSafety(check.target, check.options);
    }
  }

  async assertPathSafety(target: SandboxResolvedFsPath, options: PathSafetyOptions) {
    if (options.requireWritable) {
      this.validateFileAccess(target.containerPath);
    }
    const guarded = await this.openBoundaryWithinRequiredMount(target, options.action, {
      aliasPolicy: options.aliasPolicy,
      allowedType: options.allowedType,
    });
    await this.assertGuardedPathSafety(target, options, guarded);
  }

  async openReadableFile(
    target: SandboxResolvedFsPath,
  ): Promise<BoundaryFileOpenResult & { ok: true }> {
    const opened = await this.openBoundaryWithinRequiredMount(target, "read files");
    if (!opened.ok) {
      throw opened.error instanceof Error
        ? opened.error
        : new Error(`Sandbox boundary checks failed; cannot read files: ${target.containerPath}`);
    }
    return opened;
  }

  private resolveRequiredMount(containerPath: string, action: string): SandboxFsMount {
    const lexicalMount = this.resolveMountByContainerPath(containerPath);
    if (!lexicalMount) {
      throw new Error(`Sandbox path escapes allowed mounts; cannot ${action}: ${containerPath}`);
    }
    return lexicalMount;
  }

  private async assertGuardedPathSafety(
    target: SandboxResolvedFsPath,
    options: PathSafetyOptions,
    guarded: BoundaryFileOpenResult,
  ) {
    if (!guarded.ok) {
      if (guarded.reason !== "path") {
        const canFallbackToDirectoryStat =
          options.allowedType === "directory" && this.pathIsExistingDirectory(target.hostPath);
        if (!canFallbackToDirectoryStat) {
          throw guarded.error instanceof Error
            ? guarded.error
            : new Error(
                `Sandbox boundary checks failed; cannot ${options.action}: ${target.containerPath}`,
              );
        }
      }
    } else {
      fs.closeSync(guarded.fd);
    }

    const canonicalContainerPath = await this.resolveCanonicalContainerPath({
      containerPath: target.containerPath,
      allowFinalSymlinkForUnlink: options.aliasPolicy?.allowFinalSymlinkForUnlink === true,
    });
    const canonicalMount = this.resolveRequiredMount(canonicalContainerPath, options.action);
    if (options.requireWritable && !canonicalMount.writable) {
      throw new Error(
        `Sandbox path is read-only; cannot ${options.action}: ${target.containerPath}`,
      );
    }
  }

  private async openBoundaryWithinRequiredMount(
    target: SandboxResolvedFsPath,
    action: string,
    options?: {
      aliasPolicy?: PathAliasPolicy;
      allowedType?: SafeOpenSyncAllowedType;
    },
  ): Promise<BoundaryFileOpenResult> {
    const lexicalMount = this.resolveRequiredMount(target.containerPath, action);
    const guarded = await openBoundaryFile({
      absolutePath: target.hostPath,
      rootPath: lexicalMount.hostRoot,
      boundaryLabel: "sandbox mount root",
      aliasPolicy: options?.aliasPolicy,
      allowedType: options?.allowedType,
    });
    return guarded;
  }

  async resolveAnchoredSandboxEntry(target: SandboxResolvedFsPath): Promise<AnchoredSandboxEntry> {
    const basename = path.posix.basename(target.containerPath);
    if (!basename || basename === "." || basename === "/") {
      throw new Error(`Invalid sandbox entry target: ${target.containerPath}`);
    }
    const parentPath = normalizeContainerPath(path.posix.dirname(target.containerPath));
    const canonicalParentPath = await this.resolveCanonicalContainerPath({
      containerPath: parentPath,
      allowFinalSymlinkForUnlink: false,
    });
    return {
      canonicalParentPath,
      basename,
    };
  }

  private pathIsExistingDirectory(hostPath: string): boolean {
    try {
      return fs.statSync(hostPath).isDirectory();
    } catch {
      return false;
    }
  }

  private resolveMountByContainerPath(containerPath: string): SandboxFsMount | null {
    const normalized = normalizeContainerPath(containerPath);
    for (const mount of this.mountsByContainer) {
      if (isPathInsideContainerRoot(normalizeContainerPath(mount.containerRoot), normalized)) {
        return mount;
      }
    }
    return null;
  }

  private async resolveCanonicalContainerPath(params: {
    containerPath: string;
    allowFinalSymlinkForUnlink: boolean;
  }): Promise<string> {
    const script = [
      "set -eu",
      'target="$1"',
      'allow_final="$2"',
      'suffix=""',
      'probe="$target"',
      'if [ "$allow_final" = "1" ] && [ -L "$target" ]; then probe=$(dirname -- "$target"); fi',
      'cursor="$probe"',
      'while [ ! -e "$cursor" ] && [ ! -L "$cursor" ]; do',
      '  parent=$(dirname -- "$cursor")',
      '  if [ "$parent" = "$cursor" ]; then break; fi',
      '  base=$(basename -- "$cursor")',
      '  suffix="/$base$suffix"',
      '  cursor="$parent"',
      "done",
      'canonical=$(readlink -f -- "$cursor")',
      'printf "%s%s\\n" "$canonical" "$suffix"',
    ].join("\n");
    const result = await this.runCommand(script, {
      args: [params.containerPath, params.allowFinalSymlinkForUnlink ? "1" : "0"],
    });
    const canonical = result.stdout.toString("utf8").trim();
    if (!canonical.startsWith("/")) {
      throw new Error(`Failed to resolve canonical sandbox path: ${params.containerPath}`);
    }
    return normalizeContainerPath(canonical);
  }
}
