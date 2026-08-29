use crate::token::{Token, TokenKind};
use jocky_ast::*;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("Unexpected end of input, expected {expected}")]
    UnexpectedEof { expected: String },
    #[error("Expected {expected}, found {found:?} at line {line}, column {column}")]
    ExpectedToken {
        expected: String,
        found: TokenKind,
        line: usize,
        column: usize,
    },
    #[error("Invalid syntax at line {line}, column {column}: {message}")]
    Custom {
        message: String,
        line: usize,
        column: usize,
    },
}

pub struct Parser {
    tokens: Vec<Token>,
    current: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, current: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.current]
    }

    fn previous(&self) -> &Token {
        &self.tokens[self.current - 1]
    }

    fn is_at_end(&self) -> bool {
        self.peek().kind == TokenKind::Eof
    }

    fn advance(&mut self) -> &Token {
        if !self.is_at_end() {
            self.current += 1;
        }
        self.previous()
    }

    fn check(&self, kind: &TokenKind) -> bool {
        if self.is_at_end() {
            false
        } else {
            &self.peek().kind == kind
        }
    }

    fn match_token(&mut self, kind: &TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn consume(&mut self, kind: &TokenKind, expected: &str) -> Result<&Token, ParseError> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            let peek = self.peek();
            Err(ParseError::ExpectedToken {
                expected: expected.to_string(),
                found: peek.kind.clone(),
                line: peek.span.line,
                column: peek.span.column,
            })
        }
    }

    pub fn parse_program(&mut self) -> Result<Program, ParseError> {
        let start_span = self.peek().span;
        let case_header = self.parse_case_header()?;
        let capabilities = self.parse_capability_block()?;
        let imports = self.parse_imports()?;
        let statements = self.parse_statements()?;

        let end_span = self.previous().span;
        Ok(Program {
            case_header,
            capabilities,
            imports,
            statements,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_case_header(&mut self) -> Result<CaseHeader, ParseError> {
        let start = self.consume(&TokenKind::Case, "'case'")?.span;
        let case_id = match self.peek().kind.clone() {
            TokenKind::StringLit(s) => {
                self.advance();
                s
            }
            _ => {
                let p = self.peek();
                return Err(ParseError::ExpectedToken {
                    expected: "case identifier string".to_string(),
                    found: p.kind.clone(),
                    line: p.span.line,
                    column: p.span.column,
                });
            }
        };

        let mut description = None;
        if self.match_token(&TokenKind::Description) {
            if let TokenKind::StringLit(desc) = self.peek().kind.clone() {
                self.advance();
                description = Some(desc);
            } else {
                let p = self.peek();
                return Err(ParseError::ExpectedToken {
                    expected: "case description string".to_string(),
                    found: p.kind.clone(),
                    line: p.span.line,
                    column: p.span.column,
                });
            }
        }

        self.consume(&TokenKind::Semi, "';' after case header")?;
        let end = self.previous().span;

        Ok(CaseHeader {
            case_id,
            description,
            span: Span::new(start.start, end.end, start.line, start.column),
        })
    }

    fn parse_capability_block(&mut self) -> Result<CapabilityBlock, ParseError> {
        let start = self.consume(&TokenKind::Capabilities, "'capabilities'")?.span;
        self.consume(&TokenKind::LBrace, "'{' after capabilities")?;

        let mut grants = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
            let grant_start = self.consume(&TokenKind::Grant, "'grant'")?.span;
            let cap_path = self.parse_dotted_identifier()?;
            self.consume(&TokenKind::Semi, "';' after capability grant")?;
            let grant_end = self.previous().span;

            grants.push(CapabilityDecl {
                capability: Capability::from_str_path(&cap_path),
                span: Span::new(grant_start.start, grant_end.end, grant_start.line, grant_start.column),
            });
        }

        self.consume(&TokenKind::RBrace, "'}' after capabilities block")?;
        let end = self.previous().span;

        Ok(CapabilityBlock {
            grants,
            span: Span::new(start.start, end.end, start.line, start.column),
        })
    }

    fn parse_dotted_identifier(&mut self) -> Result<String, ParseError> {
        let mut parts = Vec::new();
        parts.push(self.parse_identifier_name()?);

        while self.match_token(&TokenKind::Dot) {
            parts.push(self.parse_identifier_name()?);
        }

        Ok(parts.join("."))
    }

    fn parse_identifier_name(&mut self) -> Result<String, ParseError> {
        let p = self.peek();
        match &p.kind {
            TokenKind::Ident(name) => {
                let res = name.clone();
                self.advance();
                Ok(res)
            }
            TokenKind::Export => { self.advance(); Ok("export".to_string()) }
            TokenKind::Format => { self.advance(); Ok("format".to_string()) }
            TokenKind::Destination => { self.advance(); Ok("destination".to_string()) }
            TokenKind::Technique => { self.advance(); Ok("technique".to_string()) }
            TokenKind::Severity => { self.advance(); Ok("severity".to_string()) }
            TokenKind::Condition => { self.advance(); Ok("condition".to_string()) }
            TokenKind::Rationale => { self.advance(); Ok("rationale".to_string()) }
            TokenKind::Streams => { self.advance(); Ok("streams".to_string()) }
            TokenKind::Window => { self.advance(); Ok("window".to_string()) }
            TokenKind::JoinOn => { self.advance(); Ok("join_on".to_string()) }
            TokenKind::Emit => { self.advance(); Ok("emit".to_string()) }
            TokenKind::Case => { self.advance(); Ok("case".to_string()) }
            TokenKind::Description => { self.advance(); Ok("description".to_string()) }
            TokenKind::Query => { self.advance(); Ok("query".to_string()) }
            TokenKind::Detect => { self.advance(); Ok("detect".to_string()) }
            TokenKind::Correlate => { self.advance(); Ok("correlate".to_string()) }
            TokenKind::Evidence => { self.advance(); Ok("evidence".to_string()) }
            TokenKind::In => { self.advance(); Ok("in".to_string()) }
            TokenKind::On => { self.advance(); Ok("on".to_string()) }
            TokenKind::As => { self.advance(); Ok("as".to_string()) }
            TokenKind::Let => { self.advance(); Ok("let".to_string()) }
            TokenKind::Grant => { self.advance(); Ok("grant".to_string()) }
            TokenKind::Capabilities => { self.advance(); Ok("capabilities".to_string()) }
            _ => Err(ParseError::ExpectedToken {
                expected: "identifier".to_string(),
                found: p.kind.clone(),
                line: p.span.line,
                column: p.span.column,
            }),
        }
    }

    fn parse_imports(&mut self) -> Result<Vec<ImportDecl>, ParseError> {
        let mut imports = Vec::new();
        while self.match_token(&TokenKind::Import) {
            let start = self.previous().span;
            let mut path = Vec::new();
            path.push(self.parse_identifier_name()?);

            while self.match_token(&TokenKind::Dot) {
                path.push(self.parse_identifier_name()?);
            }

            let mut alias = None;
            if self.match_token(&TokenKind::As) {
                alias = Some(self.parse_identifier_name()?);
            }

            self.consume(&TokenKind::Semi, "';' after import")?;
            let end = self.previous().span;

            imports.push(ImportDecl {
                module_path: path,
                alias,
                span: Span::new(start.start, end.end, start.line, start.column),
            });
        }
        Ok(imports)
    }

    fn parse_statements(&mut self) -> Result<Vec<Statement>, ParseError> {
        let mut statements = Vec::new();
        while !self.is_at_end() {
            statements.push(self.parse_statement()?);
        }
        Ok(statements)
    }

    fn parse_statement(&mut self) -> Result<Statement, ParseError> {
        let peek = self.peek();
        match peek.kind {
            TokenKind::Let => self.parse_let_statement(),
            TokenKind::Query => self.parse_query_statement(),
            TokenKind::Detect => self.parse_detect_statement(),
            TokenKind::Correlate => self.parse_correlate_statement(),
            TokenKind::Evidence => self.parse_export_statement(),
            _ => Err(ParseError::ExpectedToken {
                expected: "statement ('let', 'query', 'detect', 'correlate', 'evidence.export')".to_string(),
                found: peek.kind.clone(),
                line: peek.span.line,
                column: peek.span.column,
            }),
        }
    }

    fn parse_let_statement(&mut self) -> Result<Statement, ParseError> {
        let start = self.consume(&TokenKind::Let, "'let'")?.span;
        let name = self.parse_identifier_name()?;

        let mut type_ann = None;
        if self.match_token(&TokenKind::Colon) {
            type_ann = Some(self.parse_type_annotation()?);
        }

        self.consume(&TokenKind::Assign, "'='")?;
        let value = self.parse_expression()?;
        self.consume(&TokenKind::Semi, "';'")?;
        let end = self.previous().span;

        Ok(Statement::Let {
            name,
            type_ann,
            value,
            span: Span::new(start.start, end.end, start.line, start.column),
        })
    }

    fn parse_type_annotation(&mut self) -> Result<TypeAnnotation, ParseError> {
        let ident = self.parse_identifier_name()?;
        match ident.as_str() {
            "Int" => Ok(TypeAnnotation::Int),
            "Float" => Ok(TypeAnnotation::Float),
            "String" => Ok(TypeAnnotation::Str),
            "Bool" => Ok(TypeAnnotation::Bool),
            "Timestamp" => Ok(TypeAnnotation::Timestamp),
            "Duration" => Ok(TypeAnnotation::Duration),
            "Hash" => Ok(TypeAnnotation::Hash),
            "Process" => Ok(TypeAnnotation::Process),
            "Module" => Ok(TypeAnnotation::Module),
            "Socket" => Ok(TypeAnnotation::Socket),
            "EventRecord" => Ok(TypeAnnotation::EventRecord),
            "FileRecord" => Ok(TypeAnnotation::FileRecord),
            "MemoryRegion" => Ok(TypeAnnotation::MemoryRegion),
            "DriverRecord" => Ok(TypeAnnotation::DriverRecord),
            "EvidencePackage" => Ok(TypeAnnotation::EvidencePackage),
            "List" => {
                self.consume(&TokenKind::Lt, "'<'")?;
                let inner = self.parse_type_annotation()?;
                self.consume(&TokenKind::Gt, "'>'")?;
                Ok(TypeAnnotation::List(Box::new(inner)))
            }
            "Stream" => {
                self.consume(&TokenKind::Lt, "'<'")?;
                let inner = self.parse_type_annotation()?;
                self.consume(&TokenKind::Gt, "'>'")?;
                Ok(TypeAnnotation::Stream(Box::new(inner)))
            }
            other => Err(ParseError::Custom {
                message: format!("Unknown type '{}'", other),
                line: self.previous().span.line,
                column: self.previous().span.column,
            }),
        }
    }

    fn parse_query_statement(&mut self) -> Result<Statement, ParseError> {
        let start = self.consume(&TokenKind::Query, "'query'")?.span;
        let name = self.parse_identifier_name()?;
        self.consume(&TokenKind::Assign, "'='")?;

        let source = self.parse_source_expr()?;

        let mut pipes = Vec::new();
        while self.match_token(&TokenKind::Pipe) {
            let pipe_start = self.previous().span;
            let op_name = self.parse_identifier_name()?;
            let op = match op_name.as_str() {
                "filter" => PipeOp::Filter,
                "map" => PipeOp::Map,
                "where" => PipeOp::Where,
                "sort" => PipeOp::Sort,
                "window" => PipeOp::Window,
                "join" => PipeOp::Join,
                "dedup" => PipeOp::Dedup,
                "limit" => PipeOp::Limit,
                "take" => PipeOp::Take,
                other => {
                    return Err(ParseError::Custom {
                        message: format!("Unknown pipe operator '{}'", other),
                        line: pipe_start.line,
                        column: pipe_start.column,
                    });
                }
            };

            self.consume(&TokenKind::LParen, "'('")?;
            let args = self.parse_arg_list()?;
            self.consume(&TokenKind::RParen, "')'")?;
            let pipe_end = self.previous().span;

            pipes.push(PipeStage {
                op,
                args,
                span: Span::new(pipe_start.start, pipe_end.end, pipe_start.line, pipe_start.column),
            });
        }

        self.consume(&TokenKind::Semi, "';' after query")?;
        let end = self.previous().span;

        Ok(Statement::Query {
            name,
            source,
            pipes,
            span: Span::new(start.start, end.end, start.line, start.column),
        })
    }

    fn parse_source_expr(&mut self) -> Result<SourceExpr, ParseError> {
        let start = self.peek().span;
        let root = self.parse_identifier_name()?;
        self.consume(&TokenKind::Dot, "'.' after source domain")?;
        let entity = self.parse_identifier_name()?;

        self.consume(&TokenKind::LParen, "'('")?;
        let args = self.parse_arg_list()?;
        self.consume(&TokenKind::RParen, "')'")?;
        let end = self.previous().span;
        let span = Span::new(start.start, end.end, start.line, start.column);

        match root.as_str() {
            "host" => Ok(SourceExpr::Host { entity, args, span }),
            "process" => Ok(SourceExpr::Process { entity, args, span }),
            "filesystem" => Ok(SourceExpr::Filesystem { entity, args, span }),
            "memory" => Ok(SourceExpr::Memory { entity, args, span }),
            "eventlog" => Ok(SourceExpr::Eventlog { entity, args, span }),
            "network" => Ok(SourceExpr::Network { entity, args, span }),
            "registry" => Ok(SourceExpr::Registry { entity, args, span }),
            "lab" => Ok(SourceExpr::Lab { entity, args, span }),
            other => Err(ParseError::Custom {
                message: format!("Unknown forensic source root '{}'", other),
                line: start.line,
                column: start.column,
            }),
        }
    }

    fn parse_detect_statement(&mut self) -> Result<Statement, ParseError> {
        let start = self.consume(&TokenKind::Detect, "'detect'")?.span;
        let name = self.parse_identifier_name()?;
        self.consume(&TokenKind::On, "'on'")?;
        let target = self.parse_expression()?;

        self.consume(&TokenKind::LBrace, "'{'")?;

        let mut technique = String::new();
        let mut severity = SeverityLevel::Medium;
        let mut condition = None;
        let mut rationale = String::new();

        while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
            let field = self.parse_identifier_name()?;
            self.consume(&TokenKind::Colon, "':'")?;

            match field.as_str() {
                "technique" => {
                    if let TokenKind::StringLit(s) = self.peek().kind.clone() {
                        self.advance();
                        technique = s;
                    }
                }
                "severity" => {
                    let sev_tok = self.advance();
                    severity = match sev_tok.kind {
                        TokenKind::Informational => SeverityLevel::Informational,
                        TokenKind::Low => SeverityLevel::Low,
                        TokenKind::Medium => SeverityLevel::Medium,
                        TokenKind::High => SeverityLevel::High,
                        TokenKind::Critical => SeverityLevel::Critical,
                        _ => SeverityLevel::Medium,
                    };
                }
                "condition" => {
                    condition = Some(self.parse_expression()?);
                }
                "rationale" => {
                    if let TokenKind::StringLit(s) = self.peek().kind.clone() {
                        self.advance();
                        rationale = s;
                    }
                }
                other => {
                    return Err(ParseError::Custom {
                        message: format!("Unexpected field in detect block: {}", other),
                        line: self.previous().span.line,
                        column: self.previous().span.column,
                    });
                }
            }

            self.match_token(&TokenKind::Comma);
        }

        self.consume(&TokenKind::RBrace, "'}' after detect block")?;
        let end = self.previous().span;

        let condition = condition.ok_or_else(|| ParseError::Custom {
            message: "Missing 'condition' field in detect block".to_string(),
            line: start.line,
            column: start.column,
        })?;

        Ok(Statement::Detect {
            name,
            target,
            technique,
            severity,
            condition,
            rationale,
            span: Span::new(start.start, end.end, start.line, start.column),
        })
    }

    fn parse_correlate_statement(&mut self) -> Result<Statement, ParseError> {
        let start = self.consume(&TokenKind::Correlate, "'correlate'")?.span;
        let name = self.parse_identifier_name()?;
        self.consume(&TokenKind::LBrace, "'{'")?;

        let mut streams = Vec::new();
        let mut window_ms = 0;
        let mut join_on = None;
        let mut emit = None;

        while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
            let field = self.parse_identifier_name()?;
            self.consume(&TokenKind::Colon, "':'")?;

            match field.as_str() {
                "streams" => {
                    self.consume(&TokenKind::LBracket, "'['")?;
                    while !self.check(&TokenKind::RBracket) && !self.is_at_end() {
                        streams.push(self.parse_expression()?);
                        self.match_token(&TokenKind::Comma);
                    }
                    self.consume(&TokenKind::RBracket, "']'")?;
                }
                "window" => {
                    if let TokenKind::DurationLit(ms) = self.peek().kind {
                        self.advance();
                        window_ms = ms;
                    } else {
                        return Err(ParseError::Custom {
                            message: "Expected duration literal (e.g. 30m, 1h)".to_string(),
                            line: self.peek().span.line,
                            column: self.peek().span.column,
                        });
                    }
                }
                "join_on" => {
                    join_on = Some(self.parse_expression()?);
                }
                "emit" => {
                    emit = Some(self.parse_expression()?);
                }
                other => {
                    return Err(ParseError::Custom {
                        message: format!("Unexpected field in correlate block: {}", other),
                        line: self.previous().span.line,
                        column: self.previous().span.column,
                    });
                }
            }

            self.match_token(&TokenKind::Comma);
        }

        self.consume(&TokenKind::RBrace, "'}' after correlate block")?;
        let end = self.previous().span;

        Ok(Statement::Correlate {
            name,
            streams,
            window_ms,
            join_on: join_on.unwrap_or_else(|| Expr::Literal(Literal::Bool(true), Span::dummy())),
            emit: emit.unwrap_or_else(|| Expr::Literal(Literal::Bool(true), Span::dummy())),
            span: Span::new(start.start, end.end, start.line, start.column),
        })
    }

    fn parse_export_statement(&mut self) -> Result<Statement, ParseError> {
        let start = self.consume(&TokenKind::Evidence, "'evidence'")?.span;
        self.consume(&TokenKind::Dot, "'.' after evidence")?;
        self.consume(&TokenKind::Export, "'export'")?;
        self.consume(&TokenKind::LParen, "'('")?;

        let expr = self.parse_expression()?;
        self.consume(&TokenKind::Comma, "','")?;
        self.consume(&TokenKind::Format, "'format'")?;
        self.consume(&TokenKind::Assign, "'='")?;

        let format_tok = self.advance();
        let format = match format_tok.kind {
            TokenKind::Stix => ExportFormat::Stix,
            TokenKind::CaseJsonLd => ExportFormat::CaseJsonLd,
            TokenKind::RawParquet => ExportFormat::RawParquet,
            TokenKind::Csv => ExportFormat::Csv,
            _ => {
                return Err(ParseError::Custom {
                    message: "Expected export format (STIX, CASE_JSON_LD, RAW_PARQUET, CSV)".to_string(),
                    line: format_tok.span.line,
                    column: format_tok.span.column,
                });
            }
        };

        let mut destination = None;
        if self.match_token(&TokenKind::Comma) {
            if self.match_token(&TokenKind::Destination) {
                self.consume(&TokenKind::Assign, "'='")?;
                if let TokenKind::StringLit(dest) = self.peek().kind.clone() {
                    self.advance();
                    destination = Some(dest);
                }
            }
        }

        self.consume(&TokenKind::RParen, "')'")?;
        self.consume(&TokenKind::Semi, "';'")?;
        let end = self.previous().span;

        Ok(Statement::Export {
            expr,
            format,
            destination,
            span: Span::new(start.start, end.end, start.line, start.column),
        })
    }

    fn parse_arg_list(&mut self) -> Result<Vec<Arg>, ParseError> {
        let mut args = Vec::new();
        if self.check(&TokenKind::RParen) {
            return Ok(args);
        }

        loop {
            // Check named argument: ident = expr OR ident: expr
            if let TokenKind::Ident(id) = self.peek().kind.clone() {
                let next_kind = self.tokens.get(self.current + 1).map(|t| &t.kind);
                if next_kind == Some(&TokenKind::Assign) || next_kind == Some(&TokenKind::Colon) {
                    let start = self.peek().span;
                    self.advance(); // consume ident
                    self.advance(); // consume '=' or ':'
                    let val = self.parse_expression()?;
                    let end = self.previous().span;
                    args.push(Arg {
                        name: Some(id),
                        value: val,
                        span: Span::new(start.start, end.end, start.line, start.column),
                    });
                    if !self.match_token(&TokenKind::Comma) {
                        break;
                    }
                    continue;
                }
            }

            let val = self.parse_expression()?;
            let span = val.span();
            args.push(Arg {
                name: None,
                value: val,
                span,
            });

            if !self.match_token(&TokenKind::Comma) {
                break;
            }
        }

        Ok(args)
    }

    pub fn parse_expression(&mut self) -> Result<Expr, ParseError> {
        self.parse_lambda()
    }

    fn parse_lambda(&mut self) -> Result<Expr, ParseError> {
        if let TokenKind::Ident(param) = self.peek().kind.clone() {
            if self.tokens.get(self.current + 1).map(|t| &t.kind) == Some(&TokenKind::FatArrow) {
                let start = self.peek().span;
                self.advance(); // param
                self.advance(); // =>
                let body = self.parse_expression()?;
                let end = body.span();
                return Ok(Expr::Lambda {
                    param,
                    body: Box::new(body),
                    span: Span::new(start.start, end.end, start.line, start.column),
                });
            }
        }
        self.parse_logical_or()
    }

    fn parse_logical_or(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_logical_and()?;

        while self.match_token(&TokenKind::Or) {
            let op = BinaryOp::Or;
            let right = self.parse_logical_and()?;
            let span = Span::new(expr.span().start, right.span().end, expr.span().line, expr.span().column);
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_logical_and(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_equality()?;

        while self.match_token(&TokenKind::And) {
            let op = BinaryOp::And;
            let right = self.parse_equality()?;
            let span = Span::new(expr.span().start, right.span().end, expr.span().line, expr.span().column);
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_equality(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_relational()?;

        while let Some(op) = match self.peek().kind {
            TokenKind::Eq => Some(BinaryOp::Eq),
            TokenKind::Neq => Some(BinaryOp::Neq),
            TokenKind::RegexMatch => Some(BinaryOp::RegexMatch),
            TokenKind::RegexNotMatch => Some(BinaryOp::RegexNotMatch),
            _ => None,
        } {
            self.advance();
            let right = self.parse_relational()?;
            let span = Span::new(expr.span().start, right.span().end, expr.span().line, expr.span().column);
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_relational(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_additive()?;

        while let Some(op) = match self.peek().kind {
            TokenKind::Lt => Some(BinaryOp::Lt),
            TokenKind::Lte => Some(BinaryOp::Lte),
            TokenKind::Gt => Some(BinaryOp::Gt),
            TokenKind::Gte => Some(BinaryOp::Gte),
            TokenKind::In => Some(BinaryOp::In),
            TokenKind::NotIn => Some(BinaryOp::NotIn),
            _ => None,
        } {
            self.advance();
            let right = self.parse_additive()?;
            let span = Span::new(expr.span().start, right.span().end, expr.span().line, expr.span().column);
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_additive(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_multiplicative()?;

        while let Some(op) = match self.peek().kind {
            TokenKind::Plus => Some(BinaryOp::Add),
            TokenKind::Minus => Some(BinaryOp::Sub),
            _ => None,
        } {
            self.advance();
            let right = self.parse_multiplicative()?;
            let span = Span::new(expr.span().start, right.span().end, expr.span().line, expr.span().column);
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_unary()?;

        while let Some(op) = match self.peek().kind {
            TokenKind::Star => Some(BinaryOp::Mul),
            TokenKind::Slash => Some(BinaryOp::Div),
            TokenKind::Percent => Some(BinaryOp::Mod),
            _ => None,
        } {
            self.advance();
            let right = self.parse_unary()?;
            let span = Span::new(expr.span().start, right.span().end, expr.span().line, expr.span().column);
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
                span,
            };
        }

        Ok(expr)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if self.match_token(&TokenKind::Not) {
            let start = self.previous().span;
            let operand = self.parse_unary()?;
            let end = operand.span();
            return Ok(Expr::Unary {
                op: UnaryOp::Not,
                operand: Box::new(operand),
                span: Span::new(start.start, end.end, start.line, start.column),
            });
        }
        if self.match_token(&TokenKind::Minus) {
            let start = self.previous().span;
            let operand = self.parse_unary()?;
            let end = operand.span();
            return Ok(Expr::Unary {
                op: UnaryOp::Neg,
                operand: Box::new(operand),
                span: Span::new(start.start, end.end, start.line, start.column),
            });
        }

        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;

        loop {
            if self.match_token(&TokenKind::Dot) {
                let member = self.parse_identifier_name()?;
                let end = self.previous().span;
                expr = Expr::MemberAccess {
                    object: Box::new(expr),
                    member,
                    span: Span::new(self.peek().span.start, end.end, end.line, end.column),
                };
            } else if self.match_token(&TokenKind::LParen) {
                let args = self.parse_arg_list()?;
                self.consume(&TokenKind::RParen, "')'")?;
                let end = self.previous().span;
                expr = Expr::Call {
                    callee: Box::new(expr),
                    args,
                    span: Span::new(self.peek().span.start, end.end, end.line, end.column),
                };
            } else if self.match_token(&TokenKind::LBracket) {
                let index = self.parse_expression()?;
                self.consume(&TokenKind::RBracket, "']'")?;
                let end = self.previous().span;
                expr = Expr::Index {
                    target: Box::new(expr),
                    index: Box::new(index),
                    span: Span::new(self.peek().span.start, end.end, end.line, end.column),
                };
            } else {
                break;
            }
        }

        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let p = self.peek();
        match p.kind.clone() {
            TokenKind::True => {
                let span = self.advance().span;
                Ok(Expr::Literal(Literal::Bool(true), span))
            }
            TokenKind::False => {
                let span = self.advance().span;
                Ok(Expr::Literal(Literal::Bool(false), span))
            }
            TokenKind::IntLit(val) => {
                let span = self.advance().span;
                Ok(Expr::Literal(Literal::Int(val), span))
            }
            TokenKind::FloatLit(val) => {
                let span = self.advance().span;
                Ok(Expr::Literal(Literal::Float(val), span))
            }
            TokenKind::StringLit(s) => {
                let span = self.advance().span;
                Ok(Expr::Literal(Literal::Str(s), span))
            }
            TokenKind::DurationLit(d) => {
                let span = self.advance().span;
                Ok(Expr::Literal(Literal::Duration(d), span))
            }
            TokenKind::HashLit(h) => {
                let span = self.advance().span;
                Ok(Expr::Literal(Literal::Hash(h), span))
            }
            TokenKind::Ident(name) => {
                let span = self.advance().span;
                Ok(Expr::Identifier(name, span))
            }
            TokenKind::LParen => {
                self.advance();
                let inner = self.parse_expression()?;
                self.consume(&TokenKind::RParen, "')'")?;
                Ok(inner)
            }
            TokenKind::LBracket => {
                let start = self.advance().span;
                let mut items = Vec::new();
                while !self.check(&TokenKind::RBracket) && !self.is_at_end() {
                    items.push(self.parse_expression()?);
                    self.match_token(&TokenKind::Comma);
                }
                self.consume(&TokenKind::RBracket, "']'")?;
                let end = self.previous().span;
                Ok(Expr::List {
                    items,
                    span: Span::new(start.start, end.end, start.line, start.column),
                })
            }
            TokenKind::LBrace => {
                let start = self.advance().span;
                let mut fields = Vec::new();
                while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
                    let field_name = self.parse_identifier_name()?;
                    self.consume(&TokenKind::Colon, "':'")?;
                    let val = self.parse_expression()?;
                    fields.push((field_name, val));
                    self.match_token(&TokenKind::Comma);
                }
                self.consume(&TokenKind::RBrace, "'}'")?;
                let end = self.previous().span;
                Ok(Expr::Object {
                    fields,
                    span: Span::new(start.start, end.end, start.line, start.column),
                })
            }
            _ => Err(ParseError::ExpectedToken {
                expected: "expression".to_string(),
                found: p.kind.clone(),
                line: p.span.line,
                column: p.span.column,
            }),
        }
    }
}
