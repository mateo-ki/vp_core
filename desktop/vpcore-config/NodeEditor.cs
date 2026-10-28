using System.Text.Json;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Core;

namespace VpConfig;
record NodeField(string Path, string Kind, bool Required, string Value);
static class Nodes {
    public static readonly Dictionary<string, List<NodeField>> Catalog = Load();
    static Dictionary<string,List<NodeField>> Load() {
        using var stream=typeof(Nodes).Assembly.GetManifestResourceStream("vpcore-config.node-fields.json")
            ?? typeof(Nodes).Assembly.GetManifestResourceNames().Where(n=>n.EndsWith("node-fields.json")).Select(n=>typeof(Nodes).Assembly.GetManifestResourceStream(n)!).First();
        return JsonSerializer.Deserialize<Dictionary<string,List<NodeField>>>(stream)!;
    }
    public static string Get(YamlMappingNode node,string key)=>node.Children.TryGetValue(new YamlScalarNode(key),out var v)?v.ToString():"";
    public static YamlMappingNode Clone(YamlMappingNode node) {var s=new YamlStream(new YamlDocument(node));using var w=new StringWriter();s.Save(w,false);var r=new YamlStream();r.Load(new StringReader(w.ToString()));return (YamlMappingNode)r.Documents[0].RootNode;}
    public static YamlSequenceNode Sequence(YamlMappingNode root,string key){if(!root.Children.TryGetValue(new YamlScalarNode(key),out var n)){n=new YamlSequenceNode();root.Add(key,n);}return n as YamlSequenceNode??throw new Exception(key+" 必须为列表");}
    public static void Set(YamlMappingNode root,string path,YamlNode value){var parts=path.Split('/');for(int i=0;i<parts.Length-1;i++){var k=new YamlScalarNode(parts[i]);if(!root.Children.TryGetValue(k,out var n))root.Children[k]=n=new YamlMappingNode();root=n as YamlMappingNode??throw new Exception(path+" 参数结构冲突");}root.Children[new YamlScalarNode(parts[^1])]=value;}
    public static YamlNode Scalar(string value,string kind) {
        if(kind=="bool" && !bool.TryParse(value,out _))throw new Exception("布尔值请填写 true 或 false");
        if(kind=="number" && !ulong.TryParse(value,out _))throw new Exception("数值必须为非负整数");
        return new YamlScalarNode(kind=="bool"?value.ToLowerInvariant():value){Style=kind=="text"?ScalarStyle.DoubleQuoted:ScalarStyle.Plain};
    }
    public static IEnumerable<(string Path,YamlNode Node)> Flatten(YamlMappingNode m,string prefix="") {foreach(var (k,v) in m.Children){var path=prefix+k;if(v is YamlMappingNode child){foreach(var pair in Flatten(child,path+"/"))yield return pair;}else yield return(path,v);}}
    public static void Merge(YamlMappingNode root,YamlSequenceNode incoming){var dest=Sequence(root,"proxies");var names=dest.OfType<YamlMappingNode>().Select(n=>Get(n,"name")).ToHashSet();foreach(var node in incoming.OfType<YamlMappingNode>()){var kind=Get(node,"type");if(!Catalog.ContainsKey(kind))throw new Exception("不支持的节点类型："+kind);var name=Get(node,"name");if(string.IsNullOrWhiteSpace(name))name=kind+"-"+Get(node,"server");var unique=name;int suffix=2;while(!names.Add(unique))unique=name+" ("+(suffix++)+")";node.Children[new YamlScalarNode("name")]=new YamlScalarNode(unique);dest.Add(node);}}
}
sealed class NodeEditor : Form {
    readonly DataGridView grid=new(){Dock=DockStyle.Fill,AllowUserToAddRows=false,AllowUserToDeleteRows=false,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,RowHeadersVisible=false};
    readonly ComboBox protocol=new(){DropDownStyle=ComboBoxStyle.DropDownList,Width=160};
    readonly bool editing;
    public YamlMappingNode Result {get;private set;}=new();
    public NodeEditor(YamlMappingNode? original=null){
        editing=original!=null;Text=editing?"编辑节点":"添加节点";Width=940;Height=700;StartPosition=FormStartPosition.CenterParent;
        grid.Columns.Add(new DataGridViewCheckBoxColumn{Name="enabled",HeaderText="启用",FillWeight=12});
        grid.Columns.Add("path","参数（/ 表示子参数）");grid.Columns[1].ReadOnly=true;grid.Columns[1].FillWeight=40;
        grid.Columns.Add("value","值");grid.Columns[2].FillWeight=65;
        grid.Columns.Add("kind","类型");grid.Columns[3].ReadOnly=true;grid.Columns[3].FillWeight=14;
        var top=new FlowLayoutPanel{Dock=DockStyle.Top,Height=78};top.Controls.Add(new Label{Text="协议",AutoSize=true,Padding=new Padding(0,8,0,0)});top.Controls.Add(protocol);
        top.Controls.Add(new Label{Text="勾选要设置的参数；密码等敏感字段仅在此编辑窗口显示。\nMieru 当前仅 TCP；复杂列表/对象双击值单元格打开结构编辑器。",AutoSize=true});
        protocol.Items.AddRange(Nodes.Catalog.Keys.Cast<object>().ToArray());
        var bottom=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=42,FlowDirection=FlowDirection.RightToLeft};var ok=new Button{Text="确定"};var cancel=new Button{Text="取消",DialogResult=DialogResult.Cancel};bottom.Controls.AddRange([cancel,ok]);
        ok.Click+=(_,_)=>{try{Result=Build();DialogResult=DialogResult.OK;}catch(Exception e){MessageBox.Show(e.Message);}};
        Controls.Add(grid);Controls.Add(top);Controls.Add(bottom);CancelButton=cancel;
        protocol.SelectedIndexChanged+=(_,_)=>Fill(original);protocol.SelectedItem=original==null?"vless":Nodes.Get(original,"type");protocol.Enabled=!editing;
        grid.CellDoubleClick+=(_,e)=>{if(e.RowIndex<0||e.ColumnIndex!=2)return;var row=grid.Rows[e.RowIndex];var kind=(string)row.Cells[3].Value;if(kind is "map" or "list"){using var editor=new StructureEditor((YamlNode?)row.Tag??(kind=="map"?new YamlMappingNode():new YamlSequenceNode()));if(editor.ShowDialog(this)==DialogResult.OK){row.Tag=editor.Result;row.Cells[2].Value="已设置（双击编辑）";row.Cells[0].Value=true;}}};
    }
    void Fill(YamlMappingNode? original){grid.Rows.Clear();var type=protocol.Text;if(!Nodes.Catalog.TryGetValue(type,out var specs))return;var existing=original==null?new Dictionary<string,YamlNode>():Nodes.Flatten(original).Where(p=>p.Path!="type").ToDictionary(p=>p.Path,p=>p.Node);
        foreach(var f in specs){var key=existing.Keys.FirstOrDefault(k=>k==f.Path||k.Replace('_','-')==f.Path.Replace('_','-')||(f.Path=="servername"&&k is "sni" or "server_name" or "server-name"));YamlNode? value=null;if(key!=null){value=existing[key];existing.Remove(key);}Add(f.Path,f.Kind,value!=null||(!editing&&f.Required),value,f.Value,f.Required);}
        foreach(var (k,v)in existing)Add(k,v is YamlSequenceNode?"list":v is YamlMappingNode?"map":"text",true,v,"",false);
    }
    void Add(string path,string kind,bool enabled,YamlNode? node,string fallback,bool required){int i=grid.Rows.Add(enabled,path,node is YamlScalarNode scalar?scalar.Value:node==null?fallback:"已设置（双击编辑）",kind);grid.Rows[i].Tag=node;if(required)grid.Rows[i].Cells[1].ToolTipText="必需参数";if(editing&&path=="name"){grid.Rows[i].ReadOnly=true;grid.Rows[i].Cells[1].ToolTipText="已存在节点名称固定，避免破坏策略组和规则引用";}}
    YamlMappingNode Build(){grid.EndEdit();var root=new YamlMappingNode{{"type",protocol.Text}};foreach(DataGridViewRow row in grid.Rows){if(row.Cells[0].Value is not true)continue;var path=(string)row.Cells[1].Value;var value=Convert.ToString(row.Cells[2].Value)??"";var kind=(string)row.Cells[3].Value;if(path is "name" or "server"&&string.IsNullOrWhiteSpace(value))throw new Exception(path+" 不能为空");if(path=="port"&&(!ushort.TryParse(value,out var port)||port==0))throw new Exception("节点端口必须为 1–65535");Nodes.Set(root,path,kind is "map" or "list"?(YamlNode?)row.Tag??(kind=="map"?new YamlMappingNode():new YamlSequenceNode()):Nodes.Scalar(value,kind));}foreach(var f in Nodes.Catalog[protocol.Text].Where(f=>f.Required&&!f.Path.Contains('/')))if(!root.Children.ContainsKey(new YamlScalarNode(f.Path)) || (f.Kind=="text" && string.IsNullOrWhiteSpace(Nodes.Get(root,f.Path))))throw new Exception("缺少必需参数："+f.Path);return root;}
}
// A structural editor: users edit maps, lists and individual values without writing YAML/JSON.
sealed class StructureEditor : Form {
    readonly TreeView tree=new(){Dock=DockStyle.Fill};readonly TextBox key=new(){Width=180};readonly TextBox value=new(){Width=250};readonly ComboBox kind=new(){Width=100,DropDownStyle=ComboBoxStyle.DropDownList};
    public YamlNode Result{get;private set;}
    public StructureEditor(YamlNode source){Result=source;Text="列表 / 对象编辑";Width=780;Height=550;StartPosition=FormStartPosition.CenterParent;
        var top=new FlowLayoutPanel{Dock=DockStyle.Top,Height=80};kind.Items.AddRange(["text","bool","number","map","list"]);kind.SelectedIndex=0;
        top.Controls.AddRange([new Label{Text="字段名",AutoSize=true},key,new Label{Text="值",AutoSize=true},value,kind]);
        void Button(string label,Action action){var b=new Button{Text=label,AutoSize=true};b.Click+=(_,_)=>{try{action();}catch(Exception e){MessageBox.Show(e.Message);}};top.Controls.Add(b);}
        tree.Nodes.Add(Render("根",source));tree.ExpandAll();tree.AfterSelect+=(_,e)=>{if(e.Node==null)return;key.Text=e.Node.Text;var n=(YamlNode)e.Node.Tag!;value.Text=n is YamlScalarNode s?s.Value:"";kind.SelectedItem=n is YamlMappingNode?"map":n is YamlSequenceNode?"list":"text";};
        Button("添加子项",()=>{var parent=tree.SelectedNode??tree.Nodes[0];if(parent.Tag is YamlScalarNode)throw new Exception("请选择一个对象或列表后添加");if(parent.Tag is YamlMappingNode&&string.IsNullOrWhiteSpace(key.Text))throw new Exception("请输入字段名");parent.Nodes.Add(Render(parent.Tag is YamlSequenceNode?"项":key.Text,NewNode()));parent.Expand();});
        Button("更新选中项",()=>{var n=tree.SelectedNode??throw new Exception("请选择一项");if(n.Parent==null)throw new Exception("根结构不可替换");if(n.Tag is YamlScalarNode){n.Tag=NewNode();n.Nodes.Clear();}n.Text=key.Text;});
        Button("删除选中项",()=>{if(tree.SelectedNode?.Parent!=null)tree.SelectedNode.Remove();});
        Button("确定",()=>{Result=Read(tree.Nodes[0]);DialogResult=DialogResult.OK;});var cancel=new Button{Text="取消",DialogResult=DialogResult.Cancel};top.Controls.Add(cancel);Controls.Add(tree);Controls.Add(top);
    }
    YamlNode NewNode()=>kind.Text=="map"?new YamlMappingNode():kind.Text=="list"?new YamlSequenceNode():Nodes.Scalar(value.Text,kind.Text);
    static TreeNode Render(string label,YamlNode n){var t=new TreeNode(label){Tag=n};if(n is YamlMappingNode m)foreach(var(k,v)in m.Children)t.Nodes.Add(Render(k.ToString(),v));else if(n is YamlSequenceNode s)foreach(var v in s)t.Nodes.Add(Render("项",v));return t;}
    static YamlNode Read(TreeNode t){if(t.Tag is YamlMappingNode){var m=new YamlMappingNode();foreach(TreeNode c in t.Nodes)m.Add(c.Text,Read(c));return m;}if(t.Tag is YamlSequenceNode){var s=new YamlSequenceNode();foreach(TreeNode c in t.Nodes)s.Add(Read(c));return s;}return (YamlNode)t.Tag!;}
}
