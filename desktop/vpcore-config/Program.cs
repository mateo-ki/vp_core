using System.Diagnostics;
using Microsoft.Win32;
using YamlDotNet.RepresentationModel;

namespace VpConfig;
static class Program {
    [STAThread] static void Main(string[] args) {
        using var mutex = new Mutex(true, @"Local\VpcoreConfig", out var first);
        if (!first) { MessageBox.Show("配置工具已运行，请从系统托盘打开。"); return; }
        ApplicationConfiguration.Initialize();
        if (args.Contains("--self-test")) {
            var testRoot = Path.Combine(Path.GetTempPath(), "vpcore-test-" + Guid.NewGuid());
            using var form = new MainForm(false, testRoot);
            form.Shown += async (_, _) => {
                try { await form.SelfTest(); File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "gui-self-test.txt"), "PASS: YAML preservation, validation, managed start/stop"); }
                catch (Exception e) { Environment.ExitCode = 1; File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "gui-self-test.txt"), e.ToString()); }
                finally { form.ExitTest(); }
            };
            Application.Run(form);
        } else Application.Run(new MainForm(args.Contains("--background")));
    }
}
sealed class MainForm : Form {
    readonly string root;
    string Config => Path.Combine(root, "config.yaml");
    string Core => Path.Combine(AppContext.BaseDirectory, "vpcore.exe");
    readonly TextBox yaml = new() { Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 11) };
    readonly TextBox logs = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    readonly Label status = new() { AutoSize = true, Text = "内核未运行", Padding = new Padding(10) };
    readonly Dictionary<string, Control> fields = new();
    readonly NotifyIcon tray = new() { Icon = SystemIcons.Application, Text = "VP_Core 配置工具", Visible = true };
    readonly CheckBox autoRun = new() { Text = "打开工具后自动启动内核", AutoSize = true };
    readonly CheckBox startup = new() { Text = "登录 Windows 后后台启动", AutoSize = true };
    Process? core;
    bool exiting, busy;
    public MainForm(bool background, string? dataRoot = null) {
        root = dataRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VP_Core");
        Text = "VP_Core · 配置与运行"; Width = 1000; Height = 740; MinimumSize = new Size(780, 580);
        Directory.CreateDirectory(root);
        if (!File.Exists(Config)) File.WriteAllText(Config, "mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\nipv6: false\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n");
        yaml.Text = File.ReadAllText(Config);
        var tabs = new TabControl { Dock = DockStyle.Fill };
        var basic = new TabPage("可视化配置"); var advanced = new TabPage("完整 YAML / 节点与规则"); var logging = new TabPage("运行日志");
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(18) };
        basic.Controls.Add(panel); advanced.Controls.Add(yaml); logging.Controls.Add(logs); tabs.TabPages.AddRange([basic, advanced, logging]);
        foreach(var (key,label) in new[]{("mixed-port","混合端口"),("port","HTTP 端口（0 禁用）"),("socks-port","SOCKS 端口（0 禁用）"),("mode","模式：rule / global / direct"),("log-level","日志级别"),("external-controller","控制器地址（空为禁用）"),("secret","控制器密钥")}) {
            var row = new FlowLayoutPanel { Width = 820, Height = 34 };
            row.Controls.Add(new Label { Text = label, Width = 250, Padding = new Padding(0,6,0,0) });
            var input = new TextBox { Width = 430, UseSystemPasswordChar = key == "secret" }; fields[key]=input; row.Controls.Add(input); panel.Controls.Add(row);
        }
        foreach(var (key,label) in new[]{("allow-lan","允许局域网访问"),("ipv6","启用 IPv6")}) { var c = new CheckBox { Text = label, AutoSize=true }; fields[key]=c; panel.Controls.Add(c); }
        panel.Controls.Add(new Label { Text = "DNS、TUN、节点、策略组和规则可在完整 YAML 页编辑。TUN 需以管理员身份运行。", AutoSize=true });
        panel.Controls.Add(autoRun); panel.Controls.Add(startup);
        autoRun.Checked = File.Exists(Path.Combine(root,"autorun"));
        using(var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")) startup.Checked = k?.GetValue("VpcoreConfig") != null;
        autoRun.CheckedChanged += (_,_) => Guard(() => { if(autoRun.Checked) File.WriteAllText(Path.Combine(root,"autorun"),""); else File.Delete(Path.Combine(root,"autorun")); });
        startup.CheckedChanged += (_,_) => Guard(() => {
            using var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if(startup.Checked) k.SetValue("VpcoreConfig", $"\"{Environment.ProcessPath}\" --background"); else k.DeleteValue("VpcoreConfig",false);
        });
        var buttons = new FlowLayoutPanel { Dock=DockStyle.Top, Height=48, Padding=new Padding(6) };
        void Button(string text, Func<Task> action) { var b=new Button { Text=text, AutoSize=true }; b.Click += async (_,_) => { if(busy)return; busy=true; try { await action(); } catch(Exception e){ MessageBox.Show(e.Message,"操作失败"); } finally { busy=false; } }; buttons.Controls.Add(b); }
        Button("导入配置",async()=>{ using var d=new OpenFileDialog { Filter="YAML|*.yaml;*.yml|所有文件|*.*" }; if(d.ShowDialog()==DialogResult.OK){ yaml.Text=await File.ReadAllTextAsync(d.FileName); LoadFields(); tabs.SelectedTab=advanced; }});
        Button("保存并校验", Save);
        Button("启动内核",Start);
        Button("停止内核",Stop);
        Button("重启内核",async()=>{await Stop(); await Start();});
        Button("打开配置目录",()=>{Process.Start(new ProcessStartInfo(root){UseShellExecute=true});return Task.CompletedTask;});
        buttons.Controls.Add(status); Controls.Add(tabs); Controls.Add(buttons);
        tabs.Deselecting += (_,e)=>{if(e.TabPage==basic)try{ApplyFields();}catch(Exception x){e.Cancel=true;MessageBox.Show(x.Message);}};
        tabs.Selecting += (_,e)=>{if(e.TabPage==basic)try{LoadFields();}catch(Exception x){e.Cancel=true;MessageBox.Show(x.Message);}};
        var menu = new ContextMenuStrip(); menu.Items.Add("打开配置",null,(_,_)=>{Show();WindowState=FormWindowState.Normal;Activate();});
        menu.Items.Add("退出并停止内核",null,async(_,_)=>{try {await Stop();exiting=true;Close();}catch(Exception e){MessageBox.Show(e.Message);}}); tray.ContextMenuStrip=menu;
        tray.DoubleClick+=(_,_)=>{Show();WindowState=FormWindowState.Normal;Activate();};
        FormClosing+=(_,e)=>{if(!exiting && e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();tray.ShowBalloonTip(2000,"VP_Core","已进入后台，从托盘打开或退出。",ToolTipIcon.Info);}};
        FormClosed+=(_,_)=>{tray.Dispose();if(core is { HasExited:false })core.StandardInput.Close();};
        Shown+=async(_,_)=>{if(background)Hide(); if(autoRun.Checked)try{await Start();}catch(Exception e){Log(e.Message);tray.ShowBalloonTip(5000,"内核启动失败",e.Message,ToolTipIcon.Error);}};
        LoadFields();
    }
    public async Task SelfTest() {
        yaml.Text = "mixed-port: 0\nmode: rule\nrules: [MATCH,DIRECT]\nx-custom:\n  preserved: yes\n";
        // MATCH,DIRECT is one scalar rule, not two entries.
        yaml.Text = yaml.Text.Replace("[MATCH,DIRECT]", "[\"MATCH,DIRECT\"]");
        LoadFields(); fields["mode"].Text = "direct"; ApplyFields();
        var node = (YamlMappingNode)Parse().Documents[0].RootNode;
        if (!node.Children.ContainsKey(new YamlScalarNode("x-custom"))) throw new Exception("Unknown configuration was lost");
        if (node.Children[new YamlScalarNode("mode")].ToString() != "direct") throw new Exception("Mode edit failed");
        fields["mixed-port"].Text = "99999";
        bool rejected = false; try { ApplyFields(); } catch { rejected = true; }
        if (!rejected) throw new Exception("Invalid port was accepted");
        fields["mixed-port"].Text = "0";
        await Save(); await Start(); await Stop();
    }
    public void ExitTest() { exiting=true; Close(); }
    void Guard(Action action){try{action();}catch(Exception e){MessageBox.Show(e.Message);}}
    YamlStream Parse(){var s=new YamlStream();s.Load(new StringReader(yaml.Text));if(s.Documents.Count!=1||s.Documents[0].RootNode is not YamlMappingNode)throw new Exception("配置必须为单个 YAML 对象。");return s;}
    void LoadFields(){var m=(YamlMappingNode)Parse().Documents[0].RootNode;foreach(var (k,c) in fields){var value=m.Children.TryGetValue(new YamlScalarNode(k),out var v)?v.ToString(): k is "mode"?"rule":k is "log-level"?"info":k.EndsWith("port")?"0":"";if(c is CheckBox b)b.Checked=value=="true";else c.Text=value;}}
    void ApplyFields(){var s=Parse();var m=(YamlMappingNode)s.Documents[0].RootNode;foreach(var(k,c)in fields){var value=c is CheckBox b?b.Checked.ToString().ToLowerInvariant():c.Text.Trim();if(k.EndsWith("port")&&(!ushort.TryParse(value,out _)))throw new Exception("端口范围必须为 0–65535。");if(k=="mode"&&!new[]{"rule","global","direct"}.Contains(value))throw new Exception("运行模式无效。");if((k=="external-controller"&&value=="") || (k.EndsWith("port") && value=="0")){m.Children.Remove(new YamlScalarNode(k));continue;}m.Children[new YamlScalarNode(k)]=new YamlScalarNode(value);}using var w=new StringWriter();s.Save(w,false);yaml.Text=w.ToString();}
    ProcessStartInfo Info(params string[] args){var i=new ProcessStartInfo(Core){WorkingDirectory=root,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=true};foreach(var a in args)i.ArgumentList.Add(a);return i;}
    async Task Save(){if(((TabControl)Controls[0]).SelectedIndex==0)ApplyFields();Parse();var tmp=Path.Combine(root,"validate-"+Guid.NewGuid()+".yaml");try{await File.WriteAllTextAsync(tmp,yaml.Text);using var p=Process.Start(Info("validate","-c",tmp))??throw new Exception("无法启动校验器");var stdout=p.StandardOutput.ReadToEndAsync();var stderr=p.StandardError.ReadToEndAsync();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(30));try{await p.WaitForExitAsync(timeout.Token);}catch{p.Kill(true);throw;}var result=(await stdout)+(await stderr);if(p.ExitCode!=0)throw new Exception(result);if(File.Exists(Config))File.Copy(Config,Config+".bak",true);File.Move(tmp,Config,true);Log("配置已保存；运行中的内核会自动检测并重载。"+result);}finally{if(File.Exists(tmp))File.Delete(tmp);}}
    async Task Start(){if(core is {HasExited:false})return;await Save();core=new Process {StartInfo=Info("run","-c",Config,"-d",root,"--managed-stdin"),EnableRaisingEvents=true};core.OutputDataReceived+=(_,e)=>{if(e.Data!=null)Log(e.Data);};core.ErrorDataReceived+=(_,e)=>{if(e.Data!=null)Log(e.Data);};core.Exited+=(_,_)=>{if(!IsDisposed&&IsHandleCreated)BeginInvoke((Action)(()=>status.Text="内核已退出"));};core.Start();core.BeginOutputReadLine();core.BeginErrorReadLine();status.Text="内核进程运行中";await Task.Delay(500);if(core.HasExited)throw new Exception("内核启动后退出，请查看运行日志。");}
    async Task Stop(){if(core is not {HasExited:false})return;await core.StandardInput.WriteLineAsync("stop");await core.StandardInput.FlushAsync();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));try{await core.WaitForExitAsync(timeout.Token);}catch(OperationCanceledException){throw new Exception("内核未在 20 秒内退出。请查看日志；未强制结束，以便保留 TUN 路由清理机会。");}core.Dispose();core=null;status.Text="内核已停止";}
    void Log(string text){if(IsDisposed||!IsHandleCreated)return;BeginInvoke((Action)(()=>{if(logs.TextLength>200000)logs.Clear();logs.AppendText(text+Environment.NewLine);}));}
}
