use crate::ast::*;
use crate::token::{Token, TokenKind};

pub struct Parser<'a> {
    input: &'a str,
    tokens: Vec<Token>,
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a str, tokens: Vec<Token>) -> Self {
        Self {
            input,
            tokens,
            pos: 0,
        }
    }

    fn peek(&self) -> &TokenKind {
        self.tokens
            .get(self.pos)
            .map(|t| &t.kind)
            .unwrap_or(&TokenKind::Eof)
    }

    fn peek_token(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn bump(&mut self) -> Token {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            tok
        } else {
            Token {
                kind: TokenKind::Eof,
                span: (self.input.len(), self.input.len()),
            }
        }
    }

    fn expect(&mut self, expected: TokenKind) -> Result<Token, String> {
        let tok = self.bump();
        if tok.kind == expected {
            Ok(tok)
        } else {
            Err(format!(
                "语法错误: 期望 {expected:?}, 实际遇到 {:?} (位于字节偏移 {})",
                tok.kind, tok.span.0
            ))
        }
    }

    pub fn parse_all(&mut self) -> Result<Vec<Block>, String> {
        let mut blocks = Vec::new();
        while self.peek() != &TokenKind::Eof {
            // Skip any stray semicolons or commas at top level
            if matches!(self.peek(), TokenKind::Semicolon | TokenKind::Comma) {
                self.bump();
                continue;
            }
            blocks.push(self.parse_block()?);
        }
        Ok(blocks)
    }

    fn parse_block(&mut self) -> Result<Block, String> {
        let tok = self.bump();
        let keyword = match tok.kind {
            TokenKind::Ident(s) => s.to_ascii_lowercase(),
            other => {
                return Err(format!(
                    "语法错误: 顶层块期望关键字 (如 inbound, node, group, route 等)，实际遇到 {other:?}"
                ));
            }
        };

        match keyword.as_str() {
            "inbound" => self.parse_inbound_block(),
            "node" | "outbound" => self.parse_node_block(),
            "group" | "proxy_group" | "proxy-group" => self.parse_group_block(),
            "dns" => self.parse_dns_block(),
            "services" | "system" | "config" => self.parse_services_block(),
            "security" => self.parse_security_block(),
            "route" => self.parse_route_block(None),
            "sub_rule" | "sub-rule" => {
                let name = self.parse_ident_or_str("sub_rule 必须指定子规则名称")?;
                self.parse_route_block(Some(name))
            }
            other => Err(format!("未知的配置块类型: '{other}'")),
        }
    }

    fn parse_ident_or_str(&mut self, err_msg: &str) -> Result<String, String> {
        let tok = self.bump();
        match tok.kind {
            TokenKind::Ident(s) | TokenKind::Str(s) => Ok(s),
            _ => Err(err_msg.to_string()),
        }
    }

    fn parse_inbound_block(&mut self) -> Result<Block, String> {
        let kind = self.parse_ident_or_str("inbound 块必须指定类型 (如 mixed, tun, server)")?;
        let mut name = None;
        let mut sub_kind = None;

        if kind.eq_ignore_ascii_case("server") {
            // inbound server "name" <protocol> { ... }
            name = Some(self.parse_ident_or_str("server 入站必须指定标识名")?);
            sub_kind = Some(
                self.parse_ident_or_str("server 入站必须指定协议类型 (如 shadowsocks, vless)")?,
            );
        } else if self.peek() != &TokenKind::LBrace {
            // optional name for non-server inbounds: inbound mixed "my-mixed" { ... }
            name = Some(self.parse_ident_or_str("期望标识名")?);
        }

        self.expect(TokenKind::LBrace)?;
        let props = self.parse_props()?;
        self.expect(TokenKind::RBrace)?;

        Ok(Block::Inbound {
            kind,
            name,
            sub_kind,
            props,
        })
    }

    fn parse_node_block(&mut self) -> Result<Block, String> {
        let name = self.parse_ident_or_str("节点块必须指定节点名称")?;
        let kind = self.parse_ident_or_str("节点块必须指定协议类型 (如 vless, vmess, ss)")?;

        self.expect(TokenKind::LBrace)?;
        let props = self.parse_props()?;
        self.expect(TokenKind::RBrace)?;

        Ok(Block::Node { name, kind, props })
    }

    fn parse_group_block(&mut self) -> Result<Block, String> {
        let name = self.parse_ident_or_str("策略组必须指定组名")?;
        let kind = self.parse_ident_or_str("策略组必须指定类型 (如 select, url_test, fallback)")?;

        self.expect(TokenKind::LBrace)?;
        let props = self.parse_props()?;
        self.expect(TokenKind::RBrace)?;

        Ok(Block::Group { name, kind, props })
    }

    fn parse_dns_block(&mut self) -> Result<Block, String> {
        self.expect(TokenKind::LBrace)?;
        let props = self.parse_props()?;
        self.expect(TokenKind::RBrace)?;
        Ok(Block::Dns { props })
    }

    fn parse_services_block(&mut self) -> Result<Block, String> {
        self.expect(TokenKind::LBrace)?;
        let props = self.parse_props()?;
        self.expect(TokenKind::RBrace)?;
        Ok(Block::Services { props })
    }

    fn parse_security_block(&mut self) -> Result<Block, String> {
        self.expect(TokenKind::LBrace)?;
        let props = self.parse_props()?;
        self.expect(TokenKind::RBrace)?;
        Ok(Block::Security { props })
    }

    fn parse_route_block(&mut self, sub_rule_name: Option<String>) -> Result<Block, String> {
        let name = if sub_rule_name.is_some() {
            sub_rule_name
        } else if self.peek() != &TokenKind::LBrace {
            Some(self.parse_ident_or_str("路由块名称")?)
        } else {
            None
        };

        self.expect(TokenKind::LBrace)?;
        let mut rules = Vec::new();

        while self.peek() != &TokenKind::RBrace && self.peek() != &TokenKind::Eof {
            if matches!(self.peek(), TokenKind::Semicolon | TokenKind::Comma) {
                self.bump();
                continue;
            }

            let start_tok = self.peek_token().cloned().ok_or("非预期的文件结束")?;
            let mut end_span_byte = start_tok.span.1;
            let mut arrow_found = false;

            // Collect condition tokens up to `=>`
            let cond_start_byte = start_tok.span.0;
            while let Some(tok) = self.peek_token() {
                if tok.kind == TokenKind::Arrow {
                    arrow_found = true;
                    self.bump(); // consume Arrow
                    break;
                }
                if tok.kind == TokenKind::RBrace || tok.kind == TokenKind::Eof {
                    break;
                }
                end_span_byte = tok.span.1;
                self.bump();
            }

            if !arrow_found {
                return Err(format!(
                    "路由规则缺少指向箭头 '=>' (位于字节偏移 {cond_start_byte})"
                ));
            }

            let cond_raw = self.input[cond_start_byte..end_span_byte]
                .trim()
                .to_string();

            // Next is target
            let target = self.parse_ident_or_str("路由规则必须指定目标策略组或出站节点")?;

            // Optional options: [no-resolve] or (no-resolve) or `no-resolve`
            let mut no_resolve = false;
            if self.peek() == &TokenKind::LBracket {
                self.bump();
                let opt = self.parse_ident_or_str("选项名")?;
                if opt.eq_ignore_ascii_case("no-resolve") {
                    no_resolve = true;
                }
                self.expect(TokenKind::RBracket)?;
            } else if self.peek() == &TokenKind::LParen {
                self.bump();
                let opt = self.parse_ident_or_str("选项名")?;
                if opt.eq_ignore_ascii_case("no-resolve") {
                    no_resolve = true;
                }
                self.expect(TokenKind::RParen)?;
            } else if let TokenKind::Ident(opt) = self.peek() {
                if opt.eq_ignore_ascii_case("no-resolve") {
                    self.bump();
                    no_resolve = true;
                }
            }

            // Optional trailing comma or semicolon
            if matches!(self.peek(), TokenKind::Comma | TokenKind::Semicolon) {
                self.bump();
            }

            rules.push(RouteRuleAst {
                condition: cond_raw,
                target,
                no_resolve,
            });
        }

        self.expect(TokenKind::RBrace)?;
        Ok(Block::Route { name, rules })
    }

    fn parse_props(&mut self) -> Result<Vec<(String, DslValue)>, String> {
        let mut props = Vec::new();
        while self.peek() != &TokenKind::RBrace && self.peek() != &TokenKind::Eof {
            if matches!(self.peek(), TokenKind::Semicolon | TokenKind::Comma) {
                self.bump();
                continue;
            }

            let key_tok = self.bump();
            let key = match key_tok.kind {
                TokenKind::Ident(s) | TokenKind::Str(s) => s,
                other => {
                    return Err(format!(
                        "属性键必须为标识符或字符串，实际遇到 {other:?} (位于字节偏移 {})",
                        key_tok.span.0
                    ));
                }
            };

            // Can be followed by `:` or `=` or directly `{` (block as prop)
            let val = if self.peek() == &TokenKind::LBrace {
                self.bump();
                let inner = self.parse_props()?;
                self.expect(TokenKind::RBrace)?;
                DslValue::Map(inner)
            } else {
                if matches!(self.peek(), TokenKind::Colon | TokenKind::Eq) {
                    self.bump();
                }
                self.parse_value()?
            };

            props.push((key, val));

            // Optional separator
            if matches!(self.peek(), TokenKind::Comma | TokenKind::Semicolon) {
                self.bump();
            }
        }
        Ok(props)
    }

    fn parse_value(&mut self) -> Result<DslValue, String> {
        let tok = self.bump();
        match tok.kind {
            TokenKind::Str(s) => Ok(DslValue::Str(s)),
            TokenKind::Int(i) => Ok(DslValue::Int(i)),
            TokenKind::Duration { val, unit } => Ok(DslValue::Duration { val, unit }),
            TokenKind::Bool(b) => Ok(DslValue::Bool(b)),
            TokenKind::Ident(s) => {
                // If followed by `{`, e.g. `tls: reality { ... }`
                if self.peek() == &TokenKind::LBrace {
                    self.bump();
                    let mut inner = self.parse_props()?;
                    self.expect(TokenKind::RBrace)?;
                    inner.insert(0, ("__type".into(), DslValue::Str(s)));
                    Ok(DslValue::Map(inner))
                } else {
                    Ok(DslValue::Str(s))
                }
            }
            TokenKind::LBracket => {
                // List: [ item, item, ... ]
                let mut list = Vec::new();
                while self.peek() != &TokenKind::RBracket && self.peek() != &TokenKind::Eof {
                    list.push(self.parse_value()?);
                    if self.peek() == &TokenKind::Comma {
                        self.bump();
                    }
                }
                self.expect(TokenKind::RBracket)?;
                Ok(DslValue::List(list))
            }
            TokenKind::LBrace => {
                // Map: { key: value, ... }
                let map = self.parse_props()?;
                self.expect(TokenKind::RBrace)?;
                Ok(DslValue::Map(map))
            }
            other => Err(format!(
                "非法的属性值: {other:?} (位于字节偏移 {})",
                tok.span.0
            )),
        }
    }
}
