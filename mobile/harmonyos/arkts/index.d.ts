/**
 * VP_Core 纯血鸿蒙 (HarmonyOS NEXT / OpenHarmony) 类型定义声明
 */

export interface TrafficStats {
  uploadBytes: number;
  downloadBytes: number;
}

export declare function initLogger(level?: string): number;
export declare function validateConfig(config: string): string | null;
export declare function start(config: string, tunFd?: number): number;
export declare function stop(): number;
export declare function reload(config: string): number;
export declare function isRunning(): boolean;
export declare function getStats(): TrafficStats;
export declare function lastError(): string | null;
export declare function version(): string;
