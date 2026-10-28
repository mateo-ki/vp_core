using System.Diagnostics;
using System.Text.RegularExpressions;

namespace VpConfig;
static class LogText {
    // TextBox is not a terminal. Also accept coloured output from older cores.
    static readonly Regex Ansi = new(@"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1B]*(?:\x07|\x1B\\))", RegexOptions.Compiled);
    public static string Plain(string text) => Ansi.Replace(text, "");
}
sealed partial class MainForm {
    async Task TestLogEncoding() {
        if (LogText.Plain("\u001b[2m时间\u001b[0m \u001b[32mINFO\u001b[0m 配置已重载") != "时间 INFO 配置已重载")
            throw new Exception("ANSI colour removal failed");
        if (LogText.Plain("\u001b]0;title\u0007中文✓") != "中文✓")
            throw new Exception("ANSI title removal failed");
        async Task<(int Code, string Out, string Error)> Capture(bool stop, params string[] args) {
            using var process = Process.Start(Info(args)) ?? throw new Exception("Failed to start encoding test");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (stop) { await process.StandardInput.WriteLineAsync("stop"); await process.StandardInput.FlushAsync(); }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch { process.Kill(true); throw; }
            return (process.ExitCode, await stdout, await stderr);
        }
        var valid = await Capture(false, "validate", "-c", Config);
        if (valid.Code != 0 || !valid.Out.Contains("✓ 配置有效") || valid.Out.Contains('\uFFFD'))
            throw new Exception("UTF-8 validation stdout was corrupted");
        var missing = await Capture(false, "validate", "-c", Path.Combine(root, "不存在的配置.yaml"));
        if (missing.Code == 0 || !missing.Error.Contains("读取") || !missing.Error.Contains("不存在的配置.yaml") || missing.Error.Contains('\uFFFD'))
            throw new Exception("UTF-8 error stderr was corrupted");
        var running = await Capture(true, "run", "-c", Config, "-d", root, "--managed-stdin");
        if (running.Code != 0 || !running.Out.Contains("已启动") || (running.Out + running.Error).Contains('\u001b'))
            throw new Exception("Redirected core output contains ANSI or failed to start");
        // Flush the UI's posted log updates before checking what the user sees.
        await Task.Delay(50);
        if (!logs.Text.Contains("✓ 配置有效") || !logs.Text.Contains("已启动") || logs.Text.Contains('\u001b') || logs.Text.Contains('\uFFFD'))
            throw new Exception("Displayed log text was corrupted");
    }
}
