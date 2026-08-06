//! Streaming TL prefix generator: one input line in, one Rust constant out.

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tl-prefix-gen: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(input_path) = arguments.next() else {
        return Err("usage: tl-prefix-gen INPUT.tl [OUTPUT.rs]".into());
    };
    let output_path = arguments.next();
    if arguments.next().is_some() {
        return Err("too many arguments".into());
    }

    let input = BufReader::new(File::open(&input_path)?);
    let source_name = Path::new(&input_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("schema.tl");

    match output_path {
        Some(path) => {
            let output = BufWriter::new(File::create(path)?);
            generate(input, output, source_name)
        }
        None => {
            let output = io::stdout().lock();
            generate(input, output, source_name)
        }
    }
}

fn generate<R: BufRead, W: Write>(
    mut input: R,
    mut output: W,
    source_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(output, "// @generated from {source_name}; do not edit.")?;
    writeln!(
        output,
        "//! Constructor prefixes emitted by the streaming `tl-prefix-gen` tool."
    )?;
    writeln!(output)?;
    writeln!(output, "use crate::tl::ConstructorId;")?;
    writeln!(output)?;

    let mut line = String::new();
    let mut line_number = 0u64;
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        line_number += 1;
        let declaration = line.split("//").next().unwrap_or("").trim();
        if declaration.is_empty() || declaration.starts_with("---") || !declaration.contains('=') {
            continue;
        }
        let Some(head) = declaration.split_ascii_whitespace().next() else {
            continue;
        };
        let Some((name, encoded_id)) = head.rsplit_once('#') else {
            continue;
        };
        if encoded_id.len() != 8 || !encoded_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("{source_name}:{line_number}: invalid constructor id").into());
        }
        let constant = rust_constant(name)?;
        writeln!(output, "/// TL constructor prefix for `{name}`.")?;
        writeln!(
            output,
            "pub const {constant}: ConstructorId = ConstructorId::new(0x{encoded_id});"
        )?;
    }
    output.flush()?;
    Ok(())
}

fn rust_constant(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    if name.is_empty() {
        return Err("empty constructor name".into());
    }
    let mut output = String::with_capacity(name.len() + 8);
    let mut previous_was_lower_or_digit = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase()
                && previous_was_lower_or_digit
                && !output.ends_with('_')
            {
                output.push('_');
            }
            output.push(character.to_ascii_uppercase());
            previous_was_lower_or_digit =
                character.is_ascii_lowercase() || character.is_ascii_digit();
        } else if !output.ends_with('_') {
            output.push('_');
            previous_was_lower_or_digit = false;
        }
    }
    while output.ends_with('_') {
        output.pop();
    }
    if output.is_empty() || output.as_bytes()[0].is_ascii_digit() {
        output.insert_str(0, "TL_");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::generate;

    #[test]
    fn emits_only_explicit_constructor_prefixes() {
        let input = b"// comment\npong#347773c5 msg_id:long ping_id:long = Pong;\n\
dummy = Dummy;\nauth.sendCode#a677244f flags:# = auth.SentCode;\n";
        let mut output = Vec::new();
        generate(&input[..], &mut output, "test.tl").expect("generate");
        let output = String::from_utf8(output).expect("utf8");
        assert!(output.contains("PONG"));
        assert!(output.contains("AUTH_SEND_CODE"));
        assert!(!output.contains("AUTH_SEND_C_ODE"));
        assert!(!output.contains("DUMMY:"));
    }
}
