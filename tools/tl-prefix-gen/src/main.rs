//! Streaming TL prefix generator: one input line in, one Rust constant out.

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
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
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.is_empty() {
        return Err(
            "usage: tl-prefix-gen INPUT.tl [OUTPUT.rs] | --output OUTPUT.rs INPUT.tl...".into(),
        );
    }

    if arguments
        .first()
        .is_some_and(|argument| argument == "--output")
    {
        let output_path = arguments.get(1).ok_or("--output requires a path")?;
        let inputs: Vec<PathBuf> = arguments[2..].iter().map(PathBuf::from).collect();
        if inputs.is_empty() {
            return Err("--output requires at least one input schema".into());
        }
        let output = BufWriter::new(File::create(output_path)?);
        return generate_paths(&inputs, output);
    }

    if arguments.len() > 2 {
        return Err("multiple schemas require --output OUTPUT.rs".into());
    }
    let input_path = PathBuf::from(&arguments[0]);
    let inputs = [input_path];
    match arguments.get(1) {
        Some(path) => generate_paths(&inputs, BufWriter::new(File::create(path)?)),
        None => generate_paths(&inputs, io::stdout().lock()),
    }
}

fn generate_paths<W: Write>(
    paths: &[PathBuf],
    mut output: W,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut source_names = String::new();
    for (index, path) in paths.iter().enumerate() {
        if index != 0 {
            source_names.push_str(", ");
        }
        source_names.push_str(
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("schema.tl"),
        );
    }
    write_header(&mut output, &source_names)?;
    for path in paths {
        let source_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("schema.tl");
        write_declarations(BufReader::new(File::open(path)?), &mut output, source_name)?;
    }
    output.flush()?;
    Ok(())
}

#[cfg(test)]
fn generate<R: BufRead, W: Write>(
    mut input: R,
    mut output: W,
    source_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    write_header(&mut output, source_name)?;
    write_declarations(&mut input, &mut output, source_name)?;
    output.flush()?;
    Ok(())
}

fn write_header<W: Write>(
    output: &mut W,
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
    Ok(())
}

fn write_declarations<R: BufRead, W: Write>(
    mut input: R,
    output: &mut W,
    source_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
