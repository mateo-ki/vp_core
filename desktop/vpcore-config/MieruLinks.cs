using System.Text;
using YamlDotNet.RepresentationModel;

namespace VpConfig;
// Field numbers follow the public mieru ClientConfig/ClientProfile/ServerEndpoint
// and User/PortBinding wire format. This is a bounded wire reader, not a protocol implementation.
// https://github.com/enfein/mieru/tree/main/pkg/appctl/proto
static class MieruLinks {
    public static bool IsOfficial(string line)=>line.StartsWith("mierus://",StringComparison.OrdinalIgnoreCase)||(line.StartsWith("mieru://",StringComparison.OrdinalIgnoreCase)&&!line.Contains('@'));
    public static YamlSequenceNode Parse(string line,List<string> warnings){
        var output=new YamlSequenceNode();
        if(line.StartsWith("mierus://",StringComparison.OrdinalIgnoreCase)) {
            var u=new Uri(line);var credentials=u.UserInfo.Split(':',2);if(credentials.Length!=2)throw new Exception("Mieru 简单链接缺少用户名或密码");
            var query=u.Query.TrimStart('?').Split('&',StringSplitOptions.RemoveEmptyEntries).Select(s=>s.Split('=',2)).GroupBy(p=>Uri.UnescapeDataString(p[0])).ToDictionary(g=>g.Key,g=>g.Select(p=>p.Length==2?Uri.UnescapeDataString(p[1]):"").ToArray());
            if(!query.TryGetValue("port",out var ports)||!query.TryGetValue("protocol",out var protocols)||ports.Length!=protocols.Length)throw new Exception("Mieru 的 port 和 protocol 必须成对出现");
            foreach(var key in query.Keys.Where(k=>k is not "port" and not "protocol" and not "profile"))warnings.Add("Mieru 参数未应用："+key);
            string name=query.GetValueOrDefault("profile")?.FirstOrDefault()??"mieru";
            for(int i=0;i<ports.Length;i++){if(!protocols[i].Equals("TCP",StringComparison.OrdinalIgnoreCase)){warnings.Add("已跳过非 TCP 的 Mieru 端口");continue;}output.Add(Node(name,u.Host,Port(ports[i],warnings),Uri.UnescapeDataString(credentials[0]),Uri.UnescapeDataString(credentials[1])));}
        } else {
            var encoded=Uri.UnescapeDataString(line[8..].Split('#')[0]).Replace('-','+').Replace('_','/');encoded=encoded.PadRight((encoded.Length+3)/4*4,'=');
            var config=Read(Convert.FromBase64String(encoded));
            foreach(var profileBytes in Bytes(config,1)){
                var profile=Read(profileBytes);var user=Read(Bytes(profile,2).FirstOrDefault()??[]);var name=Text(profile,1);var username=Text(user,1);var password=Text(user,2);
                if(string.IsNullOrEmpty(password))throw new Exception("Mieru 配置没有明文密码（仅哈希凭据无法导入当前内核）");
                if(profile.Keys.Any(k=>k>=4))warnings.Add("Mieru 的 MTU、复用、握手、流量模式或前置代理设置未应用，使用内核默认行为");
                foreach(var serverBytes in Bytes(profile,3)){var server=Read(serverBytes);var host=Text(server,2);if(host=="")host=Text(server,1);
                    foreach(var bindingBytes in Bytes(server,3)){var binding=Read(bindingBytes);if(Number(binding,2)!=2){warnings.Add("已跳过非 TCP 的 Mieru 端口");continue;}var range=Text(binding,3);var port=range!=""?Port(range,warnings):checked((int)Number(binding,1));output.Add(Node(name,host,port,username,password));}
                }
            }
            warnings.Add("仅导入 Mieru 服务器节点，不覆盖本地监听端口和系统设置");
        }
        if(output.Children.Count==0)throw new Exception("链接中没有当前内核可用的 Mieru TCP 节点");return output;
    }
    static int Port(string value,List<string> warnings){var parts=value.Split('-',2);if(!int.TryParse(parts[0],out var port))throw new Exception("Mieru 端口无效");if(parts.Length==2){if(!int.TryParse(parts[1],out var end)||end<port||end>65535)throw new Exception("Mieru 端口范围无效");warnings.Add("Mieru 端口范围仅使用首个端口："+port);}return port;}
    static YamlMappingNode Node(string name,string host,int port,string user,string password){if(port<1||port>65535||string.IsNullOrWhiteSpace(host)||string.IsNullOrEmpty(user)||string.IsNullOrEmpty(password))throw new Exception("Mieru 节点缺少有效服务器、端口或凭据");return new YamlMappingNode{{"name",Nodes.Scalar((name==""?"mieru":name)+"-"+host+"-"+port,"text")},{"type","mieru"},{"server",Nodes.Scalar(host,"text")},{"port",Nodes.Scalar(port.ToString(),"number")},{"username",Nodes.Scalar(user,"text")},{"password",Nodes.Scalar(password,"text")}};}
    record Field(ulong Number,byte[]? Data);
    static IEnumerable<byte[]> Bytes(Dictionary<int,List<Field>> d,int n)=>d.GetValueOrDefault(n)?.Where(f=>f.Data!=null).Select(f=>f.Data!)??Enumerable.Empty<byte[]>();
    static string Text(Dictionary<int,List<Field>> d,int n)=>Encoding.UTF8.GetString(Bytes(d,n).FirstOrDefault()??[]);
    static ulong Number(Dictionary<int,List<Field>> d,int n)=>d.GetValueOrDefault(n)?.FirstOrDefault()?.Number??0;
    static Dictionary<int,List<Field>> Read(byte[] data){if(data.Length>4*1024*1024)throw new Exception("Mieru 配置过大");var result=new Dictionary<int,List<Field>>();int pos=0;
        ulong Varint(){ulong v=0;for(int shift=0;shift<70;shift+=7){if(pos>=data.Length)throw new Exception("Mieru 配置截断");byte b=data[pos++];if(shift==63&&b>1)throw new Exception("Mieru 整数溢出");v|=(ulong)(b&127)<<shift;if((b&128)==0)return v;}throw new Exception("Mieru 整数无效");}
        while(pos<data.Length){ulong tag=Varint();int field=checked((int)(tag>>3));if(field==0)throw new Exception("Mieru 字段无效");Field value;
            switch(tag&7){case 0:value=new Field(Varint(),null);break;case 2:int len=checked((int)Varint());if(len>data.Length-pos)throw new Exception("Mieru 字段截断");value=new Field(0,data.AsSpan(pos,len).ToArray());pos+=len;break;case 1:case 5:int skip=(tag&7)==1?8:4;if(skip>data.Length-pos)throw new Exception("Mieru 字段截断");pos+=skip;continue;default:throw new Exception("Mieru protobuf 编码不支持");}
            if(!result.TryGetValue(field,out var list))result[field]=list=[];list.Add(value);
        }return result;
    }
}
