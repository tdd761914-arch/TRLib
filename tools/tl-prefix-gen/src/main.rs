//! Streaming TL schema generator: one input line in, Rust modules out.
//!
//! Emits per-namespace modules (mirroring TDLib's per-namespace
//! `telegram_api_*` classes), each gated by a matching `api-<namespace>`
//! cargo feature so a profile can disable e.g. `payments.*` entirely.

use std::collections::BTreeMap;
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

#[derive(Debug)]
struct Constructor {
    name: String,
    id: u32,
    result: String,
    fields: Vec<Field>,
    is_method: bool,
}

#[derive(Debug)]
struct Field {
    name: String,
    ty: String,
    flags_field: u8,
    flags_bit: u8,
}

#[derive(Default)]
struct Namespace {
    constructors: Vec<Constructor>,
    /// Mtproto-level core.tl declarations are always compiled, mirroring the
    /// pre-namespace generator output; telegram_api.tl namespaces are gated.
    gated: bool,
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
    let mut namespaces: BTreeMap<String, Namespace> = BTreeMap::new();
    for path in paths {
        let source_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("schema.tl");
        let flat_namespace = if source_name.starts_with("core.") {
            "core"
        } else {
            "common"
        };
        parse_schema(
            BufReader::new(File::open(path)?),
            &mut namespaces,
            source_name,
            flat_namespace,
        )?;
    }
    for (namespace, entries) in &mut namespaces {
        entries
            .constructors
            .sort_by(|left, right| left.id.cmp(&right.id));
        write_namespace_module(&mut output, namespace, entries)?;
    }
    write_top_level(&mut output, &namespaces)?;
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
    let mut namespaces: BTreeMap<String, Namespace> = BTreeMap::new();
    parse_schema(&mut input, &mut namespaces, source_name, "common")?;
    for (namespace, entries) in &mut namespaces {
        entries
            .constructors
            .sort_by(|left, right| left.id.cmp(&right.id));
        write_namespace_module(&mut output, namespace, entries)?;
    }
    write_top_level(&mut output, &namespaces)?;
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
        "//! Constructor prefixes and full schema tables emitted by the streaming `tl-prefix-gen` tool."
    )?;
    writeln!(
        output,
        "//! Namespaces mirror TDLib's generated `telegram_api_<namespace>` classes; each module is"
    )?;
    writeln!(
        output,
        "//! compiled only when its `api-<namespace>` cargo feature is enabled."
    )?;
    writeln!(output)?;
    writeln!(output, "use crate::tl::ConstructorId;")?;
    writeln!(output)?;
    Ok(())
}

fn parse_schema<R: BufRead>(
    mut input: R,
    namespaces: &mut BTreeMap<String, Namespace>,
    source_name: &str,
    flat_namespace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut line = String::new();
    let mut line_number = 0u64;
    let mut is_method = false;
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        line_number += 1;
        let declaration = line.split("//").next().unwrap_or("").trim();
        if declaration.is_empty() || declaration.starts_with("---") {
            if declaration.starts_with("---functions---") {
                is_method = true;
            } else if declaration.starts_with("---types---") {
                is_method = false;
            }
            continue;
        }
        if !declaration.contains('=') {
            continue;
        }
        let Some(head) = declaration.split_ascii_whitespace().next() else {
            continue;
        };
        let Some((name, encoded_id)) = head.rsplit_once('#') else {
            continue;
        };
        if name == "vector" {
            continue;
        }
        if encoded_id.is_empty()
            || encoded_id.len() > 8
            || !encoded_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!("{source_name}:{line_number}: invalid constructor id").into());
        }
        let id = u32::from_str_radix(encoded_id, 16)?;
        let namespace = name
            .rsplit_once('.')
            .map_or(flat_namespace, |(prefix, _)| prefix);
        let entry = namespaces.entry(namespace.to_owned()).or_default();
        entry.gated |= flat_namespace != "core";
        if entry
            .constructors
            .iter()
            .any(|existing| existing.name == name)
        {
            return Err(
                format!("{source_name}:{line_number}: duplicate constructor {name:?}").into(),
            );
        }
        entry.constructors.push(Constructor {
            name: name.to_owned(),
            id,
            result: parse_result(declaration)?,
            fields: parse_fields(declaration, head, source_name, line_number)?,
            is_method,
        });
    }
    Ok(())
}

fn parse_result(declaration: &str) -> Result<String, Box<dyn std::error::Error>> {
    let Some(result) = declaration.split('=').last() else {
        return Ok(String::new());
    };
    Ok(result.trim().trim_end_matches(';').trim().to_owned())
}

fn parse_fields(
    declaration: &str,
    head: &str,
    source_name: &str,
    line_number: u64,
) -> Result<Vec<Field>, Box<dyn std::error::Error>> {
    let body = declaration
        .split_once('=')
        .map_or(declaration, |(body, _)| body)
        .trim()
        .trim_start_matches(head)
        .trim();
    let mut fields = Vec::new();
    let mut flags_names: Vec<String> = Vec::new();
    for token in body.split_ascii_whitespace() {
        if token.starts_with('{') && token.ends_with('}') {
            continue;
        }
        let Some((name, ty)) = token.split_once(':') else {
            return Err(
                format!("{source_name}:{line_number}: cannot parse field {token:?}").into(),
            );
        };
        if ty == "#" {
            let index = flags_names.len();
            flags_names.push(name.to_owned());
            fields.push(Field {
                name: name.to_owned(),
                ty: ty.to_owned(),
                flags_field: index as u8,
                flags_bit: 0,
            });
            continue;
        }
        let mut field = Field {
            name: name.to_owned(),
            ty: ty.to_owned(),
            flags_field: 0xFF,
            flags_bit: 0,
        };
        if let Some((flags_reference, optional_ty)) = ty.split_once('?') {
            let (flags_name, bit) = flags_reference.rsplit_once('.').ok_or_else(|| {
                format!("{source_name}:{line_number}: malformed optional field {token:?}")
            })?;
            let index = flags_names
                .iter()
                .position(|candidate| candidate == flags_name)
                .ok_or_else(|| {
                    format!(
                        "{source_name}:{line_number}: unknown flags field {flags_name:?} in {token:?}"
                    )
                })?;
            let bit: u8 = bit
                .parse()
                .map_err(|_| format!("{source_name}:{line_number}: bad flags bit in {token:?}"))?;
            field.ty = optional_ty.to_owned();
            field.flags_field = index as u8;
            field.flags_bit = bit;
        }
        fields.push(field);
    }
    Ok(fields)
}

fn write_namespace_module<W: Write>(
    output: &mut W,
    namespace: &str,
    entries: &Namespace,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    writeln!(
        output,
        "/// `{namespace}` schema namespace, mirroring TDLib."
    )?;
    if entries.gated {
        writeln!(output, "#[cfg(feature = \"api-{namespace}\")]")?;
    }
    writeln!(output, "pub mod {namespace} {{")?;
    writeln!(output, "    use crate::tl::ConstructorId;")?;
    writeln!(output)?;

    let mut methods = Vec::new();
    let mut constants = Vec::new();
    for constructor in &entries.constructors {
        let constant = rust_constant(&constructor.name)?;
        constants.push(constant.clone());
        writeln!(
            output,
            "    /// TL constructor prefix for `{}`.",
            constructor.name
        )?;
        writeln!(
            output,
            "    pub const {constant}: ConstructorId = ConstructorId::new(0x{:08x});",
            constructor.id
        )?;
        if constructor.is_method {
            methods.push((constructor.name.clone(), constructor.id));
        }
    }
    writeln!(output)?;

    writeln!(
        output,
        "    /// Full schema of this namespace: every constructor with its result type and"
    )?;
    writeln!(output, "    /// field signature, sorted by constructor id.")?;
    writeln!(
        output,
        "    pub const SCHEMA: &[crate::tl::ConstructorMeta] = &["
    )?;
    for constructor in &entries.constructors {
        write_constructor_meta(output, constructor)?;
    }
    writeln!(output, "    ];")?;
    writeln!(output)?;

    writeln!(
        output,
        "    /// TL method names of this namespace, sorted lexicographically."
    )?;
    writeln!(
        output,
        "    pub const METHODS: &[(&'static str, ConstructorId)] = &["
    )?;
    let mut methods = methods;
    methods.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, id) in &methods {
        writeln!(
            output,
            "        (\"{name}\", ConstructorId::new(0x{id:08x})),"
        )?;
    }
    writeln!(output, "    ];")?;
    writeln!(output)?;
    writeln!(
        output,
        "    /// Binary-search lookup of a method by full name."
    )?;
    writeln!(
        output,
        "    pub fn find_method(name: &str) -> Option<ConstructorId> {{"
    )?;
    writeln!(
        output,
        "        let index = METHODS.partition_point(|entry| entry.0 < name);"
    )?;
    writeln!(
        output,
        "        METHODS.get(index).filter(|entry| entry.0 == name).map(|entry| entry.1)"
    )?;
    writeln!(output, "    }}")?;
    writeln!(output, "}}")?;
    writeln!(output)?;
    Ok(constants)
}

fn write_constructor_meta<W: Write>(
    output: &mut W,
    constructor: &Constructor,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(output, "        crate::tl::ConstructorMeta {{")?;
    writeln!(
        output,
        "            id: ConstructorId::new(0x{:08x}),",
        constructor.id
    )?;
    writeln!(output, "            name: \"{}\",", constructor.name)?;
    writeln!(output, "            result: \"{}\",", constructor.result)?;
    writeln!(output, "            fields: &[")?;
    for field in &constructor.fields {
        writeln!(
            output,
            "                crate::tl::FieldMeta {{ name: \"{}\", ty: \"{}\", flags_field: {}, flags_bit: {} }},",
            field.name, field.ty, field.flags_field, field.flags_bit
        )?;
    }
    writeln!(output, "            ],")?;
    writeln!(output, "        }},")?;
    Ok(())
}

fn write_top_level<W: Write>(
    output: &mut W,
    namespaces: &BTreeMap<String, Namespace>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (namespace, entries) in namespaces {
        let constants: Vec<String> = entries
            .constructors
            .iter()
            .map(|constructor| rust_constant(&constructor.name))
            .collect::<Result<Vec<_>, _>>()?;
        if entries.gated {
            writeln!(output, "#[cfg(feature = \"api-{namespace}\")]")?;
        }
        writeln!(output, "pub use self::{namespace}::{{")?;
        for constant in constants {
            writeln!(output, "    {constant},")?;
        }
        writeln!(output, "}};")?;
        writeln!(output)?;
    }
    writeln!(
        output,
        "/// Locates a TL method by its fully-qualified schema name across enabled namespaces."
    )?;
    writeln!(output, "#[inline]")?;
    writeln!(
        output,
        "pub fn find_method(name: &str) -> Option<ConstructorId> {{"
    )?;
    for (namespace, entries) in namespaces {
        if entries.gated {
            writeln!(output, "    #[cfg(feature = \"api-{namespace}\")]")?;
        }
        writeln!(output, "    {{")?;
        writeln!(
            output,
            "        if let Some(found) = self::{namespace}::find_method(name) {{"
        )?;
        writeln!(output, "            return Some(found);")?;
        writeln!(output, "        }}")?;
        writeln!(output, "    }}")?;
        writeln!(output)?;
    }
    writeln!(output, "    None")?;
    writeln!(output, "}}")?;
    writeln!(output)?;
    writeln!(
        output,
        "/// Locates constructor metadata by its boxed identifier across enabled namespaces."
    )?;
    writeln!(output, "#[inline]")?;
    writeln!(
        output,
        "pub fn lookup_schema(id: ConstructorId) -> Option<&'static crate::tl::ConstructorMeta> {{"
    )?;
    for (namespace, entries) in namespaces {
        if entries.gated {
            writeln!(output, "    #[cfg(feature = \"api-{namespace}\")]")?;
        }
        writeln!(output, "    {{")?;
        writeln!(
            output,
            "        let index = self::{namespace}::SCHEMA.partition_point("
        )?;
        writeln!(output, "            |meta| meta.id.get() < id.get(),")?;
        writeln!(output, "        );")?;
        writeln!(
            output,
            "        if let Some(meta) = self::{namespace}::SCHEMA.get(index) {{"
        )?;
        writeln!(output, "            if meta.id == id {{")?;
        writeln!(output, "                return Some(meta);")?;
        writeln!(output, "            }}")?;
        writeln!(output, "        }}")?;
        writeln!(output, "    }}")?;
        writeln!(output)?;
    }
    writeln!(output, "    None")?;
    writeln!(output, "}}")?;
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
    fn emits_namespace_modules_and_schema_tables() {
        let input = b"// comment\npong#347773c5 msg_id:long ping_id:long = Pong;\n\
                      dummy = Dummy;\nauth.sendCode#a677244f flags:# phone_number:string = auth.SentCode;\n\
                      auth.signIn#8d52a951 flags:# phone_number:string = auth.Authorization;\n\
                      messages.sendMessage#fef48f62 flags:# peer:InputPeer reply_to:flags.0?InputReplyTo message:string = Updates;\n";
        let mut output = Vec::new();
        generate(&input[..], &mut output, "test.tl").expect("generate");
        let output = String::from_utf8(output).expect("utf8");
        assert!(output.contains("pub mod common {"));
        assert!(output.contains("pub mod auth {"));
        assert!(output.contains("pub mod messages {"));
        assert!(output.contains("pub const PONG: ConstructorId"));
        assert!(output.contains("pub const AUTH_SEND_CODE: ConstructorId"));
        assert!(output.contains("pub const AUTH_SIGN_IN: ConstructorId"));
        assert!(output.contains("pub const MESSAGES_SEND_MESSAGE: ConstructorId"));
        assert!(output.contains("\"messages.sendMessage\""));
        assert!(output.contains("flags_field: 0, flags_bit: 0"));
        assert!(output.contains("fn find_method(name: &str)"));
        assert!(output.contains("#[cfg(feature = \"api-messages\")]"));
        assert!(!output.contains("DUMMY:"));
    }

    #[test]
    fn tracks_secondary_flags_field() {
        let input = b"channelFull#a04e8d3a flags:# flags2:# id:long flag_a:flags.0?int flag_b:flags2.3?int = ChatFull;\n";
        let mut output = Vec::new();
        generate(&input[..], &mut output, "flags.tl").expect("generate");
        let output = String::from_utf8(output).expect("utf8");
        assert!(output.contains("\"flag_a\", ty: \"int\", flags_field: 0, flags_bit: 0"));
        assert!(output.contains("\"flag_b\", ty: \"int\", flags_field: 1, flags_bit: 3"));
    }
}
