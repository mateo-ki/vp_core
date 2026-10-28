using System.Diagnostics;
using YamlDotNet.RepresentationModel;

namespace VpConfig;
sealed partial class MainForm {
    readonly ListBox nodeList=new(){Dock=DockStyle.Fill,DisplayMember="Label"};
    record NodeItem(string Label,int Index);
    TabPage CreateNodePage(){var page=new TabPage("节点管理 / 剪贴板导入");var bar=new FlowLayoutPanel{Dock=DockStyle.Top,Height=80};
        void Button(string label,Func<Task> action){var b=new Button{Text=label,AutoSize=true};b.Click+=async(_,_)=>{if(busy)return;busy=true;try{await action();}catch(Exception e){MessageBox.Show(e.Message,"节点操作失败");}finally{busy=false;}};bar.Controls.Add(b);}
        Button("添加节点",async()=>{using var editor=new NodeEditor();if(editor.ShowDialog(this)!=DialogResult.OK)return;var s=Parse();Nodes.Merge((YamlMappingNode)s.Documents[0].RootNode,new YamlSequenceNode(editor.Result));WriteYaml(s);RefreshNodes();await Save();});
        Button("编辑节点",async()=>{var item=SelectedNode();var s=Parse();var seq=Nodes.Sequence((YamlMappingNode)s.Documents[0].RootNode,"proxies");using var editor=new NodeEditor(Nodes.Clone((YamlMappingNode)seq.Children[item.Index]));if(editor.ShowDialog(this)!=DialogResult.OK)return;seq.Children[item.Index]=editor.Result;WriteYaml(s);RefreshNodes();await Save();});
        Button("剪贴板导入",async()=>{if(!Clipboard.ContainsText())throw new Exception("剪贴板中没有文本");await ImportNodes(Clipboard.GetText(),true);});
        Button("删除节点",async()=>{var item=SelectedNode();var s=Parse();var root=(YamlMappingNode)s.Documents[0].RootNode;var seq=Nodes.Sequence(root,"proxies");var name=Nodes.Get((YamlMappingNode)seq.Children[item.Index],"name");
            var other=Nodes.Clone(root);Nodes.Sequence(other,"proxies").Children.RemoveAt(item.Index);var remaining=new YamlStream(new YamlDocument(other));using var writer=new StringWriter();remaining.Save(writer,false);if(writer.ToString().Contains(name,StringComparison.Ordinal))throw new Exception("该节点可能仍被策略组、规则或链式代理引用，请先移除引用再删除。");
            if(MessageBox.Show("删除节点："+name+"？","确认删除",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;seq.Children.RemoveAt(item.Index);WriteYaml(s);RefreshNodes();await Save();});
        Button("设为兜底出口",async()=>{var item=SelectedNode();var s=Parse();var root=(YamlMappingNode)s.Documents[0].RootNode;var seq=Nodes.Sequence(root,"proxies");var name=Nodes.Get((YamlMappingNode)seq.Children[item.Index],"name");if(name.Contains(','))throw new Exception("名称含逗号，不能直接用作规则目标");var rules=Nodes.Sequence(root,"rules");for(int i=rules.Children.Count-1;i>=0;i--)if(rules.Children[i].ToString().StartsWith("MATCH,",StringComparison.OrdinalIgnoreCase))rules.Children.RemoveAt(i);rules.Add(new YamlScalarNode("MATCH,"+name));root.Children[new YamlScalarNode("mode")]=new YamlScalarNode("rule");WriteYaml(s);LoadFields();await Save();});
        bar.Controls.Add(new Label{Text="支持全部内核节点类型；导入后可编辑参数。导入不会自动改变现有分流规则。",AutoSize=true});page.Controls.Add(nodeList);page.Controls.Add(bar);return page;
    }
    NodeItem SelectedNode()=>nodeList.SelectedItem as NodeItem??throw new Exception("请先选择节点");
    void RefreshNodes(){var root=(YamlMappingNode)Parse().Documents[0].RootNode;nodeList.Items.Clear();if(root.Children.TryGetValue(new YamlScalarNode("proxies"),out var v)&&v is YamlSequenceNode seq)for(int i=0;i<seq.Children.Count;i++){if(seq.Children[i] is YamlMappingNode n)nodeList.Items.Add(new NodeItem($"{Nodes.Get(n,"name")}    [{Nodes.Get(n,"type")}]    {Nodes.Get(n,"server")}:{Nodes.Get(n,"port")}",i));}}
    void WriteYaml(YamlStream stream){using var writer=new StringWriter();stream.Save(writer,false);yaml.Text=writer.ToString();}
    async Task ImportNodes(string text,bool preview){
        if(text.Length>4*1024*1024)throw new Exception("导入文本不能超过 4 MB");
        YamlSequenceNode incoming;
        if(text.TrimStart().StartsWith("proxies:")||text.TrimStart().StartsWith("- ")){var s=new YamlStream();s.Load(new StringReader(text));if(s.Documents.Count!=1)throw new Exception("只接受单个 YAML 文档");incoming=s.Documents[0].RootNode is YamlSequenceNode list?list:Nodes.Sequence((YamlMappingNode)s.Documents[0].RootNode,"proxies");}
        else {
            var input=Path.Combine(root,"links-"+Guid.NewGuid()+".txt");var output=input+".yaml";
            try{await File.WriteAllTextAsync(input,text);using var p=Process.Start(Info("import-links","-i",input,"-o",output))??throw new Exception("无法启动内核解析器");var stdout=p.StandardOutput.ReadToEndAsync();var stderr=p.StandardError.ReadToEndAsync();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(30));try{await p.WaitForExitAsync(timeout.Token);}catch{p.Kill(true);throw;}await stdout;var error=await stderr;if(p.ExitCode!=0)throw new Exception(error);var s=new YamlStream();s.Load(new StringReader(await File.ReadAllTextAsync(output)));incoming=Nodes.Sequence((YamlMappingNode)s.Documents[0].RootNode,"proxies");}
            finally{File.Delete(input);File.Delete(output);}
        }
        if(incoming.Children.Count==0||incoming.Children.Any(n=>n is not YamlMappingNode))throw new Exception("剪贴板中没有有效的节点列表");
        if(preview){var summary=string.Join(Environment.NewLine,incoming.OfType<YamlMappingNode>().Take(20).Select(n=>$"{Nodes.Get(n,"name")} [{Nodes.Get(n,"type")}]: {Nodes.Get(n,"server")}"));if(MessageBox.Show($"导入 {incoming.Children.Count} 个节点？同名节点将自动重命名。\n\n"+summary,"导入预览",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;}
        var original=yaml.Text;
        try{var config=Parse();Nodes.Merge((YamlMappingNode)config.Documents[0].RootNode,incoming);WriteYaml(config);LoadFields();await Save();RefreshNodes();Log($"已导入 {incoming.Children.Count} 个节点。");}
        catch{yaml.Text=original;LoadFields();RefreshNodes();throw;}
    }
}
