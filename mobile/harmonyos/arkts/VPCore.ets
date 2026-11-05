/**
 * @file VPCore.ets
 * @brief VP_Core 纯血鸿蒙 (HarmonyOS NEXT) ArkTS 面向对象高层封装
 */

import vpcore from 'libvpcore_napi.so';
import { TrafficStats } from './index';

export class VPCore {

  /**
   * 初始化内核全局日志输出级别
   * @param level "trace" | "debug" | "info" | "warn" | "error"
   */
  public static initLogger(level: string = 'info'): boolean {
    return vpcore.initLogger(level) === 0;
  }

  /**
   * 获取内核版本号
   */
  public static get version(): string {
    return vpcore.version();
  }

  /**
   * 查询内核是否正在运行中
   */
  public static get isRunning(): boolean {
    return vpcore.isRunning();
  }

  /**
   * 获取最后一次发生的错误描述信息
   */
  public static get lastError(): string | null {
    return vpcore.lastError();
  }

  /**
   * 校验 YAML / JSON 格式配置文本合法性
   * @return 若通过返回 null，若失败返回详细错误描述
   */
  public static validateConfig(config: string): string | null {
    return vpcore.validateConfig(config);
  }

  /**
   * 启动 VP_Core 内核并托管网络
   * @param config 完整配置文本
   * @param tunFd 由 @ohos.net.vpn 建立并注入的网卡句柄，未注入传 -1
   */
  public static start(config: string, tunFd: number = -1): number {
    return vpcore.start(config, tunFd);
  }

  /**
   * 停止当前运行中的内核并释放资源
   */
  public static stop(): number {
    return vpcore.stop();
  }

  /**
   * 平滑热重载配置（不断开已有网络流）
   */
  public static reload(config: string): number {
    return vpcore.reload(config);
  }

  /**
   * 查询当前内核累计上传/下载流量统计
   */
  public static getStats(): TrafficStats {
    return vpcore.getStats();
  }
}
