//! JOCKY Parser: Tokenizer, Pratt expression parser, and AST builder.

pub mod token;
pub mod lexer;
pub mod parser;

pub use token::{Token, TokenKind};
pub use lexer::{Lexer, LexError};
pub use parser::{Parser, ParseError};
use jocky_ast::Program;

/// Helper function to tokenize and parse a JOCKY source string into a Program AST.
pub fn parse_source(source: &str) -> Result<Program, String> {
    let mut lexer = Lexer::new(source);
    let tokens = lexer.tokenize().map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens);
    parser.parse_program().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_program() {
        let code = r#"
            case "INC-2026-001" description "Test Case";

            capabilities {
                grant process.read;
                grant driver.read;
            }

            import std.forensics.windows;

            query drivers = host.drivers()
                | filter(d => d.is_whql == false);

            detect suspicious_driver on drivers {
                technique: "T1068",
                severity: HIGH,
                condition: drivers.count() > 0,
                rationale: "Unsigned driver detected"
            }

            evidence.export(drivers, format=STIX, destination="vault://evidence");
        "#;

        let program = parse_source(code).expect("Should parse successfully");
        assert_eq!(program.case_header.case_id, "INC-2026-001");
        assert_eq!(program.capabilities.grants.len(), 2);
        assert_eq!(program.imports.len(), 1);
        assert_eq!(program.statements.len(), 3);
    }
}
