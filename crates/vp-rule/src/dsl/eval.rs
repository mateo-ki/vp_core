use std::net::IpAddr;
use std::sync::Arc;

use super::ast::{BinOp, Expr};
use crate::domain::DomainTrie;
use crate::ipset::{self, IpIntervalSet};
use crate::{CompileEnv, MatchCtx, Net};

#[derive(Clone)]
pub enum CompiledExpr {
    True,
    False,

    // 端口
    DstPortEq(u16),
    DstPortNe(u16),
    DstPortLt(u16),
    DstPortLe(u16),
    DstPortGt(u16),
    DstPortGe(u16),
    DstPortIn(Arc<[u16]>),
    SrcPortEq(u16),
    SrcPortIn(Arc<[u16]>),

    // 协议
    NetworkEq(Net),

    // 入站
    InboundEq(Arc<str>),
    InboundIn(Arc<[Arc<str>]>),
    InboundPortEq(u16),
    InboundPortIn(Arc<[u16]>),
    InboundUserEq(Arc<str>),

    // 进程
    ProcessNameEq(Arc<str>),
    ProcessNameIn(Arc<[Arc<str>]>),
    ProcessPathEndsWith(Arc<str>),
    ProcessPathContains(Arc<str>),

    // 目标域名
    HostEq(Arc<str>),
    HostNe(Arc<str>),
    HostSuffix(Arc<DomainTrie>),
    HostStartsWith(Arc<str>),
    HostContains(Arc<str>),
    #[cfg(feature = "regex-rules")]
    HostRegex(Arc<regex::Regex>),
    HostIn(Arc<DomainTrie>),

    // 目标与源 IP
    DstIpIn(Arc<IpIntervalSet>),
    SrcIpIn(Arc<IpIntervalSet>),
    DstIpEq(IpAddr),
    SrcIpEq(IpAddr),

    // GeoIP
    #[cfg(feature = "geoip")]
    DstGeoIpEq(Arc<crate::geoip::GeoIpMatcher>),
    #[cfg(feature = "geoip")]
    DstGeoIpNe(Arc<crate::geoip::GeoIpMatcher>),
    #[cfg(feature = "geoip")]
    DstGeoIpIn(Arc<[crate::geoip::GeoIpMatcher]>),

    // 复合短路逻辑
    And(Arc<[CompiledExpr]>),
    Or(Arc<[CompiledExpr]>),
    Not(Arc<CompiledExpr>),
}

impl CompiledExpr {
    /// 计算开销评估（越小越早求值，用于 And 连词自动重排优化）
    pub fn cost(&self) -> u8 {
        match self {
            CompiledExpr::True | CompiledExpr::False => 0,
            CompiledExpr::DstPortEq(_)
            | CompiledExpr::DstPortNe(_)
            | CompiledExpr::DstPortLt(_)
            | CompiledExpr::DstPortLe(_)
            | CompiledExpr::DstPortGt(_)
            | CompiledExpr::DstPortGe(_)
            | CompiledExpr::DstPortIn(_)
            | CompiledExpr::SrcPortEq(_)
            | CompiledExpr::SrcPortIn(_)
            | CompiledExpr::NetworkEq(_) => 0, // Cost 0: 整数/枚举比较，1 个 CPU 周期

            CompiledExpr::InboundEq(_)
            | CompiledExpr::InboundIn(_)
            | CompiledExpr::InboundPortEq(_)
            | CompiledExpr::InboundPortIn(_)
            | CompiledExpr::InboundUserEq(_) => 1, // Cost 1: 短字符串引用比较

            CompiledExpr::ProcessNameEq(_)
            | CompiledExpr::ProcessNameIn(_)
            | CompiledExpr::ProcessPathEndsWith(_)
            | CompiledExpr::ProcessPathContains(_) => 2, // Cost 2: 进程名字段比对

            CompiledExpr::HostEq(_)
            | CompiledExpr::HostNe(_)
            | CompiledExpr::HostSuffix(_)
            | CompiledExpr::HostStartsWith(_)
            | CompiledExpr::HostContains(_)
            | CompiledExpr::HostIn(_)
            | CompiledExpr::DstIpIn(_)
            | CompiledExpr::SrcIpIn(_)
            | CompiledExpr::DstIpEq(_)
            | CompiledExpr::SrcIpEq(_) => 3, // Cost 3: Trie 树检索与 IP 区间二分查找

            #[cfg(feature = "regex-rules")]
            CompiledExpr::HostRegex(_) => 4, // Cost 4: 正则表达式求值

            #[cfg(feature = "geoip")]
            CompiledExpr::DstGeoIpEq(_)
            | CompiledExpr::DstGeoIpNe(_)
            | CompiledExpr::DstGeoIpIn(_) => 5, // Cost 5: GeoIP 数据库查找

            CompiledExpr::Not(sub) => sub.cost(),
            CompiledExpr::And(subs) | CompiledExpr::Or(subs) => {
                subs.iter().map(|s| s.cost()).max().unwrap_or(0)
            }
        }
    }

    /// 热路径零分配短路求值
    pub fn eval(&self, ctx: &MatchCtx) -> bool {
        match self {
            CompiledExpr::True => true,
            CompiledExpr::False => false,

            CompiledExpr::DstPortEq(p) => ctx.dst_port == *p,
            CompiledExpr::DstPortNe(p) => ctx.dst_port != *p,
            CompiledExpr::DstPortLt(p) => ctx.dst_port < *p,
            CompiledExpr::DstPortLe(p) => ctx.dst_port <= *p,
            CompiledExpr::DstPortGt(p) => ctx.dst_port > *p,
            CompiledExpr::DstPortGe(p) => ctx.dst_port >= *p,
            CompiledExpr::DstPortIn(list) => list.contains(&ctx.dst_port),

            CompiledExpr::SrcPortEq(p) => ctx.src_port == *p,
            CompiledExpr::SrcPortIn(list) => list.contains(&ctx.src_port),

            CompiledExpr::NetworkEq(n) => ctx.network == *n,

            CompiledExpr::InboundEq(s) => ctx.inbound == s.as_ref(),
            CompiledExpr::InboundIn(list) => list.iter().any(|s| ctx.inbound == s.as_ref()),
            CompiledExpr::InboundPortEq(p) => ctx.inbound_port == Some(*p),
            CompiledExpr::InboundPortIn(list) => {
                ctx.inbound_port.is_some_and(|p| list.contains(&p))
            }
            CompiledExpr::InboundUserEq(u) => ctx
                .inbound_user
                .is_some_and(|user| user.eq_ignore_ascii_case(u)),

            CompiledExpr::ProcessNameEq(n) => ctx.process.is_some_and(|p| match_process_name(p, n)),
            CompiledExpr::ProcessNameIn(list) => ctx
                .process
                .is_some_and(|p| list.iter().any(|n| match_process_name(p, n))),
            CompiledExpr::ProcessPathEndsWith(s) => {
                ctx.process.is_some_and(|p| p.ends_with(s.as_ref()))
            }
            CompiledExpr::ProcessPathContains(s) => {
                ctx.process.is_some_and(|p| p.contains(s.as_ref()))
            }

            CompiledExpr::HostEq(h) => ctx.host.is_some_and(|host| host.eq_ignore_ascii_case(h)),
            CompiledExpr::HostNe(h) => ctx.host.is_some_and(|host| !host.eq_ignore_ascii_case(h)),
            CompiledExpr::HostSuffix(trie) => ctx.host.is_some_and(|host| trie.is_match(host)),
            CompiledExpr::HostStartsWith(prefix) => ctx
                .host
                .is_some_and(|host| host.starts_with(prefix.as_ref())),
            CompiledExpr::HostContains(sub) => ctx
                .host
                .is_some_and(|host| host.to_ascii_lowercase().contains(sub.as_ref())),
            #[cfg(feature = "regex-rules")]
            CompiledExpr::HostRegex(re) => ctx.host.is_some_and(|host| re.is_match(host)),
            CompiledExpr::HostIn(trie) => ctx.host.is_some_and(|host| trie.is_exact_match(host)),

            CompiledExpr::DstIpIn(set) => ctx.dst_ip.is_some_and(|ip| set.contains(ip)),
            CompiledExpr::SrcIpIn(set) => ctx.src_ip.is_some_and(|ip| set.contains(ip)),
            CompiledExpr::DstIpEq(ip) => ctx.dst_ip == Some(*ip),
            CompiledExpr::SrcIpEq(ip) => ctx.src_ip == Some(*ip),

            #[cfg(feature = "geoip")]
            CompiledExpr::DstGeoIpEq(g) => ctx.dst_ip.is_some_and(|ip| g.matches(ip)),
            #[cfg(feature = "geoip")]
            CompiledExpr::DstGeoIpNe(g) => ctx.dst_ip.is_some_and(|ip| !g.matches(ip)),
            #[cfg(feature = "geoip")]
            CompiledExpr::DstGeoIpIn(list) => ctx
                .dst_ip
                .is_some_and(|ip| list.iter().any(|g| g.matches(ip))),

            CompiledExpr::And(subs) => subs.iter().all(|sub| sub.eval(ctx)),
            CompiledExpr::Or(subs) => subs.iter().any(|sub| sub.eval(ctx)),
            CompiledExpr::Not(sub) => !sub.eval(ctx),
        }
    }

    /// 静态推导：子表达式是否需要目标 IP（若无需 IP，域名访问不会触发惰性 DNS 解析）
    pub fn needs_dst_ip(&self) -> bool {
        match self {
            CompiledExpr::DstIpIn(_) | CompiledExpr::DstIpEq(_) => true,
            #[cfg(feature = "geoip")]
            CompiledExpr::DstGeoIpEq(_)
            | CompiledExpr::DstGeoIpNe(_)
            | CompiledExpr::DstGeoIpIn(_) => true,
            CompiledExpr::And(subs) | CompiledExpr::Or(subs) => {
                subs.iter().any(|s| s.needs_dst_ip())
            }
            CompiledExpr::Not(sub) => sub.needs_dst_ip(),
            _ => false,
        }
    }

    /// 静态推导：子表达式是否依赖进程名称/路径探测
    pub fn needs_process(&self) -> bool {
        match self {
            CompiledExpr::ProcessNameEq(_)
            | CompiledExpr::ProcessNameIn(_)
            | CompiledExpr::ProcessPathEndsWith(_)
            | CompiledExpr::ProcessPathContains(_) => true,
            CompiledExpr::And(subs) | CompiledExpr::Or(subs) => {
                subs.iter().any(|s| s.needs_process())
            }
            CompiledExpr::Not(sub) => sub.needs_process(),
            _ => false,
        }
    }
}

fn match_process_name(process: &str, target: &str) -> bool {
    if process.eq_ignore_ascii_case(target) {
        return true;
    }
    let base = process.rsplit(['/', '\\']).next().unwrap_or(process);
    base.eq_ignore_ascii_case(target)
        || base
            .strip_suffix(".exe")
            .is_some_and(|s| s.eq_ignore_ascii_case(target))
}

pub fn compile_expr(input: &str, env: &CompileEnv) -> Result<CompiledExpr, String> {
    let ast = super::parser::Parser::parse(input)?;
    compile_ast(&ast, env)
}

fn compile_ast(ast: &Expr, env: &CompileEnv) -> Result<CompiledExpr, String> {
    match ast {
        Expr::Bool(b) => Ok(if *b {
            CompiledExpr::True
        } else {
            CompiledExpr::False
        }),
        Expr::Not(inner) => {
            let compiled = compile_ast(inner, env)?;
            Ok(match compiled {
                CompiledExpr::True => CompiledExpr::False,
                CompiledExpr::False => CompiledExpr::True,
                CompiledExpr::Not(sub) => (*sub).clone(),
                other => CompiledExpr::Not(Arc::new(other)),
            })
        }
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
        } => {
            let c_left = compile_ast(left, env)?;
            let c_right = compile_ast(right, env)?;

            let mut subs = Vec::new();
            flatten_and(c_left, &mut subs);
            flatten_and(c_right, &mut subs);

            if subs.iter().any(|s| matches!(s, CompiledExpr::False)) {
                return Ok(CompiledExpr::False);
            }
            subs.retain(|s| !matches!(s, CompiledExpr::True));

            if subs.is_empty() {
                return Ok(CompiledExpr::True);
            }
            if subs.len() == 1 {
                return Ok(subs.remove(0));
            }

            // 核心短路优化：按计算开销升序排列（整数比较排在最前，DNS/IP排在后，GeoIP排在最后）
            subs.sort_by_key(|e| e.cost());
            Ok(CompiledExpr::And(subs.into()))
        }
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
        } => {
            let c_left = compile_ast(left, env)?;
            let c_right = compile_ast(right, env)?;

            let mut subs = Vec::new();
            flatten_or(c_left, &mut subs);
            flatten_or(c_right, &mut subs);

            if subs.iter().any(|s| matches!(s, CompiledExpr::True)) {
                return Ok(CompiledExpr::True);
            }
            subs.retain(|s| !matches!(s, CompiledExpr::False));

            if subs.is_empty() {
                return Ok(CompiledExpr::False);
            }
            if subs.len() == 1 {
                return Ok(subs.remove(0));
            }

            Ok(CompiledExpr::Or(subs.into()))
        }
        Expr::MethodCall {
            target,
            method,
            args,
        } => compile_method_call(target, method, args),

        Expr::Binary { op, left, right } => {
            // 支持字面量在左侧的反向语法（如 "curl" == process.name）
            if matches!(left.as_ref(), Expr::Str(_) | Expr::Int(_) | Expr::List(_))
                && matches!(right.as_ref(), Expr::Ident(_))
            {
                let flipped_op = match op {
                    BinOp::Eq => BinOp::Eq,
                    BinOp::Ne => BinOp::Ne,
                    BinOp::Lt => BinOp::Gt,
                    BinOp::Le => BinOp::Ge,
                    BinOp::Gt => BinOp::Lt,
                    BinOp::Ge => BinOp::Le,
                    _ => return Err("操作数顺序不支持翻转".into()),
                };
                return compile_comparison(right, flipped_op, left, env);
            }
            compile_comparison(left, *op, right, env)
        }
        other => Err(format!("不支持的顶层表达式结构: {other:?}")),
    }
}

fn flatten_and(expr: CompiledExpr, out: &mut Vec<CompiledExpr>) {
    match expr {
        CompiledExpr::And(subs) => {
            for sub in subs.iter() {
                flatten_and(sub.clone(), out);
            }
        }
        other => out.push(other),
    }
}

fn flatten_or(expr: CompiledExpr, out: &mut Vec<CompiledExpr>) {
    match expr {
        CompiledExpr::Or(subs) => {
            for sub in subs.iter() {
                flatten_or(sub.clone(), out);
            }
        }
        other => out.push(other),
    }
}

fn compile_method_call(target: &Expr, method: &str, args: &[Expr]) -> Result<CompiledExpr, String> {
    let Expr::Ident(ident) = target else {
        return Err(format!("方法调用目标必须为标识符，实际为: {target:?}"));
    };

    let target_key = ident.to_ascii_lowercase();

    if target_key == "host" || target_key == "domain" {
        match method {
            "endsWith" => {
                let suffix = expect_single_str_arg("endsWith", args)?;
                let mut trie = DomainTrie::new();
                trie.insert_suffix_all(&suffix);
                Ok(CompiledExpr::HostSuffix(Arc::new(trie)))
            }
            "startsWith" => {
                let prefix = expect_single_str_arg("startsWith", args)?;
                Ok(CompiledExpr::HostStartsWith(prefix.into()))
            }
            "contains" => {
                let sub = expect_single_str_arg("contains", args)?;
                Ok(CompiledExpr::HostContains(sub.to_ascii_lowercase().into()))
            }
            "matches" => {
                #[cfg(feature = "regex-rules")]
                {
                    let pat = expect_single_str_arg("matches", args)?;
                    let re = regex::Regex::new(&format!("(?i){pat}"))
                        .map_err(|e| format!("matches 正则语法非法 {pat:?}: {e}"))?;
                    Ok(CompiledExpr::HostRegex(Arc::new(re)))
                }
                #[cfg(not(feature = "regex-rules"))]
                {
                    let _ = args;
                    Err("当前构建未启用 regex-rules 特性，无法使用 .matches()".into())
                }
            }
            other => Err(format!(
                "host 对象不支持方法 .{other}()，支持: endsWith, startsWith, contains, matches"
            )),
        }
    } else if target_key == "process.path" {
        match method {
            "endsWith" => {
                let s = expect_single_str_arg("endsWith", args)?;
                Ok(CompiledExpr::ProcessPathEndsWith(s.into()))
            }
            "contains" => {
                let s = expect_single_str_arg("contains", args)?;
                Ok(CompiledExpr::ProcessPathContains(s.into()))
            }
            other => Err(format!("process.path 对象不支持方法 .{other}()")),
        }
    } else {
        Err(format!("标识符 {ident:?} 不支持方法调用 .{method}()"))
    }
}

fn compile_comparison(
    left: &Expr,
    op: BinOp,
    right: &Expr,
    env: &CompileEnv,
) -> Result<CompiledExpr, String> {
    let Expr::Ident(ident) = left else {
        return Err(format!("比较操作左操作数必须为标识符，实际为: {left:?}"));
    };

    let key = ident.to_ascii_lowercase();

    match key.as_str() {
        "host" | "domain" => match op {
            BinOp::Eq => Ok(CompiledExpr::HostEq(eval_str(right)?.into())),
            BinOp::Ne => Ok(CompiledExpr::HostNe(eval_str(right)?.into())),
            BinOp::In => {
                let list = eval_str_list(right)?;
                let mut trie = DomainTrie::new();
                for h in list {
                    trie.insert_exact(&h);
                }
                Ok(CompiledExpr::HostIn(Arc::new(trie)))
            }
            BinOp::NotIn => {
                let list = eval_str_list(right)?;
                let mut trie = DomainTrie::new();
                for h in list {
                    trie.insert_exact(&h);
                }
                Ok(CompiledExpr::Not(Arc::new(CompiledExpr::HostIn(Arc::new(
                    trie,
                )))))
            }
            _ => Err(format!("host 不支持比较操作符 {op:?}")),
        },

        "dst.port" => match op {
            BinOp::Eq => Ok(CompiledExpr::DstPortEq(eval_u16(right)?)),
            BinOp::Ne => Ok(CompiledExpr::DstPortNe(eval_u16(right)?)),
            BinOp::Lt => Ok(CompiledExpr::DstPortLt(eval_u16(right)?)),
            BinOp::Le => Ok(CompiledExpr::DstPortLe(eval_u16(right)?)),
            BinOp::Gt => Ok(CompiledExpr::DstPortGt(eval_u16(right)?)),
            BinOp::Ge => Ok(CompiledExpr::DstPortGe(eval_u16(right)?)),
            BinOp::In => Ok(CompiledExpr::DstPortIn(eval_u16_list(right)?.into())),
            BinOp::NotIn => Ok(CompiledExpr::Not(Arc::new(CompiledExpr::DstPortIn(
                eval_u16_list(right)?.into(),
            )))),
            _ => Err(format!("dst.port 不支持操作符 {op:?}")),
        },

        "src.port" => match op {
            BinOp::Eq => Ok(CompiledExpr::SrcPortEq(eval_u16(right)?)),
            BinOp::In => Ok(CompiledExpr::SrcPortIn(eval_u16_list(right)?.into())),
            BinOp::NotIn => Ok(CompiledExpr::Not(Arc::new(CompiledExpr::SrcPortIn(
                eval_u16_list(right)?.into(),
            )))),
            _ => Err(format!("src.port 不支持操作符 {op:?}")),
        },

        "net" | "network" => {
            let s = eval_str(right)?.to_ascii_lowercase();
            let net = match s.as_str() {
                "tcp" => Net::Tcp,
                "udp" => Net::Udp,
                other => return Err(format!("无效的协议类型: {other:?}，仅支持 tcp 或 udp")),
            };
            match op {
                BinOp::Eq => Ok(CompiledExpr::NetworkEq(net)),
                BinOp::Ne => Ok(CompiledExpr::NetworkEq(match net {
                    Net::Tcp => Net::Udp,
                    Net::Udp => Net::Tcp,
                })),
                _ => Err(format!("network 不支持操作符 {op:?}")),
            }
        }

        "process.name" => match op {
            BinOp::Eq => Ok(CompiledExpr::ProcessNameEq(eval_str(right)?.into())),
            BinOp::Ne => Ok(CompiledExpr::Not(Arc::new(CompiledExpr::ProcessNameEq(
                eval_str(right)?.into(),
            )))),
            BinOp::In => {
                let list: Vec<Arc<str>> =
                    eval_str_list(right)?.into_iter().map(Into::into).collect();
                Ok(CompiledExpr::ProcessNameIn(list.into()))
            }
            BinOp::NotIn => {
                let list: Vec<Arc<str>> =
                    eval_str_list(right)?.into_iter().map(Into::into).collect();
                Ok(CompiledExpr::Not(Arc::new(CompiledExpr::ProcessNameIn(
                    list.into(),
                ))))
            }
            _ => Err(format!("process.name 不支持操作符 {op:?}")),
        },

        "inbound" => match op {
            BinOp::Eq => Ok(CompiledExpr::InboundEq(eval_str(right)?.into())),
            BinOp::In => {
                let list: Vec<Arc<str>> =
                    eval_str_list(right)?.into_iter().map(Into::into).collect();
                Ok(CompiledExpr::InboundIn(list.into()))
            }
            _ => Err(format!("inbound 不支持操作符 {op:?}")),
        },

        "inbound.port" => match op {
            BinOp::Eq => Ok(CompiledExpr::InboundPortEq(eval_u16(right)?)),
            BinOp::In => Ok(CompiledExpr::InboundPortIn(eval_u16_list(right)?.into())),
            _ => Err(format!("inbound.port 不支持操作符 {op:?}")),
        },

        "inbound.user" => match op {
            BinOp::Eq => Ok(CompiledExpr::InboundUserEq(eval_str(right)?.into())),
            _ => Err(format!("inbound.user 不支持操作符 {op:?}")),
        },

        "dst.ip" | "src.ip" => {
            let is_dst = key == "dst.ip";
            match op {
                BinOp::In | BinOp::NotIn => {
                    let mut b = ipset::IpIntervalSetBuilder::new();
                    let cidrs = match right {
                        Expr::Str(s) => vec![s.clone()],
                        Expr::List(_) => eval_str_list(right)?,
                        _ => return Err("ip in 应后接 CIDR 字符串或列表".into()),
                    };
                    for cidr in cidrs {
                        b.insert_cidr(cidr.trim())
                            .map_err(|e| format!("解析 CIDR {cidr:?} 失败: {e}"))?;
                    }
                    let set = Arc::new(b.build());
                    let inner = if is_dst {
                        CompiledExpr::DstIpIn(set)
                    } else {
                        CompiledExpr::SrcIpIn(set)
                    };
                    if op == BinOp::NotIn {
                        Ok(CompiledExpr::Not(Arc::new(inner)))
                    } else {
                        Ok(inner)
                    }
                }
                BinOp::Eq | BinOp::Ne => {
                    let ip_str = eval_str(right)?;
                    let ip = ip_str
                        .parse::<IpAddr>()
                        .map_err(|e| format!("解析 IP {ip_str:?} 失败: {e}"))?;
                    let inner = if is_dst {
                        CompiledExpr::DstIpEq(ip)
                    } else {
                        CompiledExpr::SrcIpEq(ip)
                    };
                    if op == BinOp::Ne {
                        Ok(CompiledExpr::Not(Arc::new(inner)))
                    } else {
                        Ok(inner)
                    }
                }
                _ => Err(format!("{key} 不支持操作符 {op:?}")),
            }
        }

        "geoip" => {
            #[cfg(feature = "geoip")]
            {
                let db = match env.geoip.as_ref() {
                    Some(db) => db,
                    None => {
                        tracing::warn!("未加载 GeoIP 数据库，规则中 geoip 条件将视为 false");
                        return Ok(CompiledExpr::False);
                    }
                };

                match op {
                    BinOp::Eq => {
                        let code = eval_str(right)?;
                        let m = db
                            .matcher(code.clone())
                            .ok_or_else(|| format!("非法或不支持的国家代码: {code:?}"))?;
                        Ok(CompiledExpr::DstGeoIpEq(Arc::new(m)))
                    }
                    BinOp::Ne => {
                        let code = eval_str(right)?;
                        let m = db
                            .matcher(code.clone())
                            .ok_or_else(|| format!("非法或不支持的国家代码: {code:?}"))?;
                        Ok(CompiledExpr::DstGeoIpNe(Arc::new(m)))
                    }
                    BinOp::In => {
                        let codes = eval_str_list(right)?;
                        let mut matchers = Vec::new();
                        for c in codes {
                            if let Some(m) = db.matcher(c) {
                                matchers.push(m);
                            }
                        }
                        Ok(CompiledExpr::DstGeoIpIn(matchers.into()))
                    }
                    BinOp::NotIn => {
                        let codes = eval_str_list(right)?;
                        let mut matchers = Vec::new();
                        for c in codes {
                            if let Some(m) = db.matcher(c) {
                                matchers.push(m);
                            }
                        }
                        Ok(CompiledExpr::Not(Arc::new(CompiledExpr::DstGeoIpIn(
                            matchers.into(),
                        ))))
                    }
                    _ => Err(format!("geoip 不支持操作符 {op:?}")),
                }
            }
            #[cfg(not(feature = "geoip"))]
            {
                let _ = (env, right);
                tracing::warn!("当前构建未启用 geoip 特性，geoip 判定一律为 false");
                Ok(CompiledExpr::False)
            }
        }

        other => Err(format!(
            "未识别的 CEL 上下文标识符: {other:?}，支持: host, domain, dst.port, src.port, dst.ip, src.ip, net, network, process.name, process.path, inbound, inbound.port, inbound.user, geoip"
        )),
    }
}

fn expect_single_str_arg(method: &str, args: &[Expr]) -> Result<String, String> {
    if args.len() != 1 {
        return Err(format!(
            "方法 .{method}() 期待 1 个字符串参数，实际获得 {} 个",
            args.len()
        ));
    }
    eval_str(&args[0])
}

fn eval_str(expr: &Expr) -> Result<String, String> {
    match expr {
        Expr::Str(s) => Ok(s.clone()),
        other => Err(format!("期待字符串字面量，实际为: {other:?}")),
    }
}

fn eval_u16(expr: &Expr) -> Result<u16, String> {
    match expr {
        Expr::Int(n) => {
            if *n <= 65535 {
                Ok(*n as u16)
            } else {
                Err(format!("端口号数值超出 u16 范围 (0-65535): {n}"))
            }
        }
        other => Err(format!("期待整数端口字面量，实际为: {other:?}")),
    }
}

fn eval_str_list(expr: &Expr) -> Result<Vec<String>, String> {
    match expr {
        Expr::List(list) => {
            let mut out = Vec::with_capacity(list.len());
            for item in list {
                out.push(eval_str(item)?);
            }
            Ok(out)
        }
        other => Err(format!(
            "期待字符串列表字面量 [\"...\", ...], 实际为: {other:?}"
        )),
    }
}

fn eval_u16_list(expr: &Expr) -> Result<Vec<u16>, String> {
    match expr {
        Expr::List(list) => {
            let mut out = Vec::with_capacity(list.len());
            for item in list {
                out.push(eval_u16(item)?);
            }
            Ok(out)
        }
        other => Err(format!(
            "期待数字端口列表字面量 [80, 443], 实际为: {other:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_env<'a>(known: &'a (dyn Fn(&str) -> bool + Send + Sync)) -> CompileEnv<'a> {
        static PROVIDERS: std::sync::LazyLock<
            HashMap<String, (crate::provider::Behavior, Vec<u8>)>,
        > = std::sync::LazyLock::new(HashMap::new);
        static SUB_RULES: std::sync::LazyLock<HashMap<String, Vec<String>>> =
            std::sync::LazyLock::new(HashMap::new);
        CompileEnv {
            is_known_target: known,
            geosite: &None,
            #[cfg(feature = "geoip")]
            geoip: &None,
            #[cfg(feature = "geoip")]
            asn: &None,
            providers: &PROVIDERS,
            sub_rules: &SUB_RULES,
        }
    }

    #[test]
    fn test_cost_based_conjunction_reordering() {
        let known = |_s: &str| true;
        let env = empty_env(&known);

        // 故意让开销大的 dst.ip in CIDR 写在前面，开销为 0 的 dst.port == 22 写在后面
        let compiled = compile_expr("dst.ip in '10.0.0.0/8' && dst.port == 22", &env).unwrap();

        if let CompiledExpr::And(subs) = compiled {
            assert_eq!(subs.len(), 2);
            // 验证重排后：首个必须是 cost 0 的 DstPortEq！
            assert!(matches!(subs[0], CompiledExpr::DstPortEq(22)));
            // 第二个才是 cost 3 的 DstIpIn！
            assert!(matches!(subs[1], CompiledExpr::DstIpIn(_)));
        } else {
            panic!("期待 CompiledExpr::And");
        }
    }

    #[test]
    fn test_eval_short_circuit_and_correctness() {
        let known = |_s: &str| true;
        let env = empty_env(&known);

        let expr = compile_expr(
            "process.name == 'curl' && dst.port in [80, 443] && host.endsWith('.google.com')",
            &env,
        )
        .unwrap();

        let ctx_hit = MatchCtx {
            host: Some("mail.google.com"),
            dst_ip: None,
            src_ip: None,
            dst_port: 443,
            src_port: 54321,
            network: Net::Tcp,
            process: Some("C:\\Windows\\System32\\curl.exe"),
            inbound: "mixed",
            inbound_port: None,
            inbound_user: None,
            cache: Default::default(),
        };
        assert!(expr.eval(&ctx_hit));

        // 端口不匹配 -> 立即短路
        let ctx_wrong_port = MatchCtx {
            dst_port: 22,
            ..ctx_hit.clone()
        };
        assert!(!expr.eval(&ctx_wrong_port));

        // 域名不匹配 -> 失败
        let ctx_wrong_host = MatchCtx {
            host: Some("github.com"),
            ..ctx_hit.clone()
        };
        assert!(!expr.eval(&ctx_wrong_host));
    }
}
