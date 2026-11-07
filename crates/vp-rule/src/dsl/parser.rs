use super::ast::{BinOp, Expr};
use super::lexer::{Lexer, Token};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse(input: &str) -> Result<Expr, String> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize()?;
        let mut parser = Parser::new(tokens);
        let expr = parser.parse_expr(0)?;
        if let Some(tok) = parser.peek() {
            return Err(format!("表达式末尾有未消费的多余 Token: {tok:?}"));
        }
        Ok(expr)
    }

    pub fn parse_expr(&mut self, min_prec: u8) -> Result<Expr, String> {
        let mut left = self.parse_prefix()?;

        while let Some(op) = self.peek_bin_op() {
            let prec = op.precedence();
            if prec < min_prec {
                break;
            }
            self.pos += 1; // 消费二元操作符

            let next_prec = prec + 1; // 左结合
            let right = self.parse_expr(next_prec)?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_prefix(&mut self) -> Result<Expr, String> {
        let tok = self
            .next_token()
            .ok_or_else(|| "表达式提前结束，缺少操作数".to_string())?;

        let mut expr = match tok {
            Token::LParen => {
                let inner = self.parse_expr(0)?;
                self.expect(&Token::RParen)?;
                inner
            }
            Token::Not => {
                let operand = self.parse_expr(40)?;
                Expr::Not(Box::new(operand))
            }
            Token::LBracket => {
                let mut list = Vec::new();
                if self.peek() != Some(&Token::RBracket) {
                    loop {
                        list.push(self.parse_expr(0)?);
                        if self.peek() == Some(&Token::Comma) {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                }
                self.expect(&Token::RBracket)?;
                Expr::List(list)
            }
            Token::Str(s) => Expr::Str(s),
            Token::Int(n) => Expr::Int(n),
            Token::Bool(b) => Expr::Bool(b),
            Token::Ident(name) => Expr::Ident(name),
            other => return Err(format!("语法错误: 未预期的前缀 Token: {other:?}")),
        };

        // 处理后续的点号访问与方法调用（如 a.b 或 a.endsWith(...)）
        while let Some(&Token::Dot) = self.peek() {
            self.pos += 1; // 消费 '.'
            let member = self.expect_ident()?;
            if let Some(&Token::LParen) = self.peek() {
                self.pos += 1; // 消费 '('
                let mut args = Vec::new();
                if self.peek() != Some(&Token::RParen) {
                    loop {
                        args.push(self.parse_expr(0)?);
                        if self.peek() == Some(&Token::Comma) {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                }
                self.expect(&Token::RParen)?;
                expr = Expr::MethodCall {
                    target: Box::new(expr),
                    method: member,
                    args,
                };
            } else if let Expr::Ident(ref mut s) = expr {
                s.push('.');
                s.push_str(&member);
            } else {
                return Err(format!("不支持在非标识符对象上进行字段访问: .{member}"));
            }
        }

        Ok(expr)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<(), String> {
        let tok = self.next_token();
        if tok.as_ref() == Some(expected) {
            Ok(())
        } else {
            Err(format!(
                "语法错误: 期待 Token {expected:?}，实际获得: {tok:?}"
            ))
        }
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        match self.next_token() {
            Some(Token::Ident(s)) => Ok(s),
            other => Err(format!("语法错误: 期待标识符，实际获得: {other:?}")),
        }
    }

    fn peek_bin_op(&self) -> Option<BinOp> {
        match self.peek()? {
            Token::And => Some(BinOp::And),
            Token::Or => Some(BinOp::Or),
            Token::Eq => Some(BinOp::Eq),
            Token::Ne => Some(BinOp::Ne),
            Token::Lt => Some(BinOp::Lt),
            Token::Le => Some(BinOp::Le),
            Token::Gt => Some(BinOp::Gt),
            Token::Ge => Some(BinOp::Ge),
            Token::In => Some(BinOp::In),
            Token::NotIn => Some(BinOp::NotIn),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_precedence() {
        let expr = Parser::parse("process.name == \"curl\" && dst.port in [80, 443]").unwrap();
        assert_eq!(
            expr,
            Expr::Binary {
                op: BinOp::And,
                left: Box::new(Expr::Binary {
                    op: BinOp::Eq,
                    left: Box::new(Expr::Ident("process.name".into())),
                    right: Box::new(Expr::Str("curl".into())),
                }),
                right: Box::new(Expr::Binary {
                    op: BinOp::In,
                    left: Box::new(Expr::Ident("dst.port".into())),
                    right: Box::new(Expr::List(vec![Expr::Int(80), Expr::Int(443)])),
                }),
            }
        );
    }

    #[test]
    fn test_parser_method_call() {
        let expr = Parser::parse("host.endsWith(\".google.com\") || geoip == 'CN'").unwrap();
        assert_eq!(
            expr,
            Expr::Binary {
                op: BinOp::Or,
                left: Box::new(Expr::MethodCall {
                    target: Box::new(Expr::Ident("host".into())),
                    method: "endsWith".into(),
                    args: vec![Expr::Str(".google.com".into())],
                }),
                right: Box::new(Expr::Binary {
                    op: BinOp::Eq,
                    left: Box::new(Expr::Ident("geoip".into())),
                    right: Box::new(Expr::Str("CN".into())),
                }),
            }
        );
    }
}
