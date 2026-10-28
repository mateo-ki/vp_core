import re,json,pathlib
root=pathlib.Path(__file__).resolve().parents[2]
s=(root/'crates/vp-config/src/model.rs').read_text()
structs=dict(re.findall(r'pub struct (\w+)\s*\{(.*?)^}',s,re.S|re.M))
kinds=re.search(r'pub enum ProxyKind\s*\{(.*?)^}',s,re.S|re.M).group(1)
def fields(name,prefix='',optional=False):
    result=[]; body=structs[name]; last=0
    for m in re.finditer(r'pub (\w+): ([^\n]+),',body):
        attr=body[last:m.start()];last=m.end(); key,typ=m.groups()
        aliases=re.findall(r'alias\s*=\s*"([^"]+)"',attr)
        key=(aliases[0] if aliases else key);path=prefix+key
        opt=optional or 'default' in attr or typ.startswith('Option<')
        inner=typ[7:-1] if typ.startswith('Option<') else typ
        if inner in structs: result+=fields(inner,path+'/',opt);continue
        kind='bool' if inner=='bool' else 'number' if re.fullmatch(r'[ui]\d+|usize',inner) else 'list' if inner=='Vec<String>' else 'map' if inner.startswith('HashMap') else 'text'
        value='false' if kind=='bool' else '443' if key=='port' else '0' if kind=='number' else ''
        result.append(dict(Path=path,Kind=kind,Required=not opt,Value=value))
    return result
catalog={}
for name,struct in re.findall(r'(\w+)(?:\((\w+)\))?,',kinds):
    fs=[dict(Path='name',Kind='text',Required=True,Value='新节点')]
    if struct:fs+=fields(struct)
    fs += [dict(Path='dialer-proxy',Kind='text',Required=False,Value=''),dict(Path='udp_over_tcp',Kind='bool',Required=False,Value='false')]+fields('SmuxConfig','smux/',True)
    catalog[name.lower()]=fs
(root/'desktop/vpcore-config/node-fields.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2))
print('Generated',len(catalog),'protocol schemas')
