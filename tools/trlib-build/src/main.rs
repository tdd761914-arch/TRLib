//! Turns a tiny text config into a reproducible Cargo feature selection.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

#[derive(Debug)]
struct BuildConfig {
    package: String,
    release: bool,
    std: bool,
    service: bool,
    transport_abridged: bool,
    transport_intermediate: bool,
    crypto_rustcrypto: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            package: "trlib-core".into(),
            release: true,
            std: false,
            service: true,
            transport_abridged: false,
            transport_intermediate: true,
            crypto_rustcrypto: false,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("trlib-build: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut config_path = PathBuf::from("trlib.conf");
    let mut dry_run = false;
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--config" {
            config_path = arguments.next().ok_or("--config requires a path")?.into();
        } else if argument == "--dry-run" {
            dry_run = true;
        } else {
            return Err(format!("unknown argument: {}", argument.to_string_lossy()).into());
        }
    }

    let text = fs::read_to_string(&config_path)?;
    let config = parse_config(&text)?;
    let features = selected_features(&config);
    let mut command = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command
        .arg("build")
        .arg("--locked")
        .arg("--no-default-features");
    command.arg("--package").arg(&config.package);
    if config.release {
        command.arg("--release");
    }
    if !features.is_empty() {
        command.arg("--features").arg(features.join(","));
    }

    eprintln!(
        "TRLib build: package={} profile={} features={}",
        config.package,
        if config.release { "release" } else { "dev" },
        if features.is_empty() {
            "<none>".to_owned()
        } else {
            features.join(",")
        }
    );
    if dry_run {
        return Ok(ExitCode::SUCCESS);
    }
    let status = command.status()?;
    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn selected_features(config: &BuildConfig) -> Vec<&'static str> {
    let mut features = Vec::with_capacity(5);
    let prefix = if config.package == "trlib-core" {
        ""
    } else {
        "trlib-core/"
    };
    let mut add = |enabled: bool, name: &'static str, qualified: &'static str| {
        if enabled {
            features.push(if prefix.is_empty() { name } else { qualified });
        }
    };
    add(config.std, "std", "trlib-core/std");
    add(config.service, "service", "trlib-core/service");
    add(
        config.transport_abridged,
        "transport-abridged",
        "trlib-core/transport-abridged",
    );
    add(
        config.transport_intermediate,
        "transport-intermediate",
        "trlib-core/transport-intermediate",
    );
    add(
        config.crypto_rustcrypto,
        "crypto-rustcrypto",
        "trlib-core/crypto-rustcrypto",
    );
    features
}

fn parse_config(text: &str) -> Result<BuildConfig, Box<dyn std::error::Error>> {
    let mut config = BuildConfig::default();
    for (zero_indexed, source_line) in text.lines().enumerate() {
        let line_number = zero_indexed + 1;
        let line = source_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_number}: expected key = value"))?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "package" => {
                if value.is_empty()
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                {
                    return Err(format!("line {line_number}: invalid package name").into());
                }
                config.package = value.to_owned();
            }
            "release" => config.release = parse_bool(value, line_number)?,
            "std" => config.std = parse_bool(value, line_number)?,
            "service" => config.service = parse_bool(value, line_number)?,
            "transport_abridged" => config.transport_abridged = parse_bool(value, line_number)?,
            "transport_intermediate" => {
                config.transport_intermediate = parse_bool(value, line_number)?
            }
            "crypto_rustcrypto" => config.crypto_rustcrypto = parse_bool(value, line_number)?,
            _ => return Err(format!("line {line_number}: unknown key {key:?}").into()),
        }
    }
    Ok(config)
}

fn parse_bool(value: &str, line_number: usize) -> Result<bool, Box<dyn std::error::Error>> {
    match value {
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" => Ok(false),
        _ => Err(format!("line {line_number}: expected true/false, got {value:?}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_config, selected_features};

    #[test]
    fn text_config_selects_only_requested_modules() {
        let config = parse_config(
            "package = trlib-core\nservice = false\ntransport_abridged = true\n\
             transport_intermediate = false\ncrypto_rustcrypto = false\n",
        )
        .expect("parse");
        assert_eq!(selected_features(&config), ["transport-abridged"]);
    }
}
