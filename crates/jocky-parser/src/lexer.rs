use crate::token::{Token, TokenKind};
use jocky_ast::Span;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum LexError {
    #[error("Unterminated string at line {line}, column {column}")]
    UnterminatedString { line: usize, column: usize },
    #[error("Unexpected character '{ch}' at line {line}, column {column}")]
    UnexpectedChar { ch: char, line: usize, column: usize },
}

pub struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    col: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            chars: source.chars().collect(),
            pos: 0,
            line: 1,
            col: 1,
            _marker: std::marker::PhantomData,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.pos + 1).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied()?;
        self.pos += 1;
        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();

        loop {
            self.skip_whitespace_and_comments();

            let start_pos = self.pos;
            let start_line = self.line;
            let start_col = self.col;

            let ch = match self.peek() {
                Some(c) => c,
                None => {
                    tokens.push(Token {
                        kind: TokenKind::Eof,
                        span: Span::new(start_pos, start_pos, start_line, start_col),
                    });
                    break;
                }
            };

            let kind = match ch {
                ';' => { self.advance(); TokenKind::Semi }
                '{' => { self.advance(); TokenKind::LBrace }
                '}' => { self.advance(); TokenKind::RBrace }
                '(' => { self.advance(); TokenKind::LParen }
                ')' => { self.advance(); TokenKind::RParen }
                '[' => { self.advance(); TokenKind::LBracket }
                ']' => { self.advance(); TokenKind::RBracket }
                ',' => { self.advance(); TokenKind::Comma }
                ':' => { self.advance(); TokenKind::Colon }
                '.' => { self.advance(); TokenKind::Dot }
                '|' => { self.advance(); TokenKind::Pipe }
                '+' => { self.advance(); TokenKind::Plus }
                '*' => { self.advance(); TokenKind::Star }
                '/' => { self.advance(); TokenKind::Slash }
                '%' => { self.advance(); TokenKind::Percent }

                '-' => {
                    self.advance();
                    TokenKind::Minus
                }

                '=' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        TokenKind::Eq
                    } else if self.peek() == Some('>') {
                        self.advance();
                        TokenKind::FatArrow
                    } else if self.peek() == Some('~') {
                        self.advance();
                        TokenKind::RegexMatch
                    } else {
                        TokenKind::Assign
                    }
                }

                '!' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        TokenKind::Neq
                    } else if self.peek() == Some('~') {
                        self.advance();
                        TokenKind::RegexNotMatch
                    } else if self.check_keyword("in") {
                        self.pos += 2;
                        self.col += 2;
                        TokenKind::NotIn
                    } else {
                        return Err(LexError::UnexpectedChar { ch: '!', line: start_line, column: start_col });
                    }
                }

                '<' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        TokenKind::Lte
                    } else {
                        TokenKind::Lt
                    }
                }

                '>' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        TokenKind::Gte
                    } else {
                        TokenKind::Gt
                    }
                }

                '"' => self.lex_string(start_line, start_col)?,

                c if c.is_ascii_digit() => self.lex_number()?,

                c if c.is_ascii_alphabetic() || c == '_' => self.lex_ident_or_keyword(),

                other => {
                    return Err(LexError::UnexpectedChar {
                        ch: other,
                        line: start_line,
                        column: start_col,
                    });
                }
            };

            let end_pos = self.pos;
            tokens.push(Token {
                kind,
                span: Span::new(start_pos, end_pos, start_line, start_col),
            });
        }

        Ok(tokens)
    }

    fn check_keyword(&self, kw: &str) -> bool {
        let kw_chars: Vec<char> = kw.chars().collect();
        for (i, c) in kw_chars.iter().enumerate() {
            if self.chars.get(self.pos + i) != Some(c) {
                return false;
            }
        }
        let next_char = self.chars.get(self.pos + kw_chars.len());
        match next_char {
            Some(c) if c.is_ascii_alphanumeric() || *c == '_' => false,
            _ => true,
        }
    }

    fn skip_whitespace_and_comments(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else if c == '/' && self.peek_next() == Some('/') {
                // Line comment
                while let Some(ch) = self.advance() {
                    if ch == '\n' {
                        break;
                    }
                }
            } else if c == '/' && self.peek_next() == Some('*') {
                // Block comment
                self.advance();
                self.advance();
                while let Some(ch) = self.advance() {
                    if ch == '*' && self.peek() == Some('/') {
                        self.advance();
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn lex_string(&mut self, start_line: usize, start_col: usize) -> Result<TokenKind, LexError> {
        self.advance(); // consume opening quote
        let mut s = String::new();

        while let Some(ch) = self.advance() {
            match ch {
                '"' => return Ok(TokenKind::StringLit(s)),
                '\\' => {
                    if let Some(esc) = self.advance() {
                        match esc {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '\\' => s.push('\\'),
                            '"' => s.push('"'),
                            other => s.push(other),
                        }
                    }
                }
                other => s.push(other),
            }
        }

        Err(LexError::UnterminatedString {
            line: start_line,
            column: start_col,
        })
    }

    fn lex_number(&mut self) -> Result<TokenKind, LexError> {
        let mut text = String::new();
        let mut is_float = false;

        // Check hex 0x
        if self.peek() == Some('0') && (self.peek_next() == Some('x') || self.peek_next() == Some('X')) {
            self.advance();
            self.advance();
            let mut hex_text = String::new();
            while let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() {
                    hex_text.push(c);
                    self.advance();
                } else {
                    break;
                }
            }
            let val = i64::from_str_radix(&hex_text, 16).unwrap_or(0);
            return Ok(TokenKind::IntLit(val));
        }

        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                text.push(c);
                self.advance();
            } else if c == '.' && self.peek_next().map_or(false, |next| next.is_ascii_digit()) {
                is_float = true;
                text.push(c);
                self.advance();
            } else {
                break;
            }
        }

        // Check for duration suffixes: ms, s, m, h, d
        if !is_float {
            if let Some(c) = self.peek() {
                let num: u64 = text.parse().unwrap_or(0);
                if c == 'm' && self.peek_next() == Some('s') {
                    self.advance();
                    self.advance();
                    return Ok(TokenKind::DurationLit(num));
                } else if c == 's' {
                    self.advance();
                    return Ok(TokenKind::DurationLit(num * 1000));
                } else if c == 'm' {
                    self.advance();
                    return Ok(TokenKind::DurationLit(num * 60 * 1000));
                } else if c == 'h' {
                    self.advance();
                    return Ok(TokenKind::DurationLit(num * 3600 * 1000));
                } else if c == 'd' {
                    self.advance();
                    return Ok(TokenKind::DurationLit(num * 86400 * 1000));
                }
            }
        }

        if is_float {
            let val: f64 = text.parse().unwrap_or(0.0);
            Ok(TokenKind::FloatLit(val))
        } else {
            let val: i64 = text.parse().unwrap_or(0);
            Ok(TokenKind::IntLit(val))
        }
    }

    fn lex_ident_or_keyword(&mut self) -> TokenKind {
        let mut text = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                text.push(c);
                self.advance();
            } else if c == ':' && (text == "sha256" || text == "blake3") {
                // Hash literal
                text.push(c);
                self.advance();
                while let Some(hc) = self.peek() {
                    if hc.is_ascii_hexdigit() {
                        text.push(hc);
                        self.advance();
                    } else {
                        break;
                    }
                }
                return TokenKind::HashLit(text);
            } else {
                break;
            }
        }

        match text.as_str() {
            "case" => TokenKind::Case,
            "description" => TokenKind::Description,
            "capabilities" => TokenKind::Capabilities,
            "grant" => TokenKind::Grant,
            "import" => TokenKind::Import,
            "as" => TokenKind::As,
            "let" => TokenKind::Let,
            "query" => TokenKind::Query,
            "detect" => TokenKind::Detect,
            "on" => TokenKind::On,
            "technique" => TokenKind::Technique,
            "severity" => TokenKind::Severity,
            "condition" => TokenKind::Condition,
            "rationale" => TokenKind::Rationale,
            "correlate" => TokenKind::Correlate,
            "streams" => TokenKind::Streams,
            "window" => TokenKind::Window,
            "join_on" => TokenKind::JoinOn,
            "emit" => TokenKind::Emit,
            "evidence" => TokenKind::Evidence,
            "export" => TokenKind::Export,
            "format" => TokenKind::Format,
            "destination" => TokenKind::Destination,
            "if" => TokenKind::If,
            "else" => TokenKind::Else,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "or" => TokenKind::Or,
            "and" => TokenKind::And,
            "not" => TokenKind::Not,
            "in" => TokenKind::In,

            // Severities
            "INFORMATIONAL" => TokenKind::Informational,
            "LOW" => TokenKind::Low,
            "MEDIUM" => TokenKind::Medium,
            "HIGH" => TokenKind::High,
            "CRITICAL" => TokenKind::Critical,

            // Formats
            "STIX" => TokenKind::Stix,
            "CASE_JSON_LD" => TokenKind::CaseJsonLd,
            "RAW_PARQUET" => TokenKind::RawParquet,
            "CSV" => TokenKind::Csv,

            _ => TokenKind::Ident(text),
        }
    }
}
