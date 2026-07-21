use std::path::PathBuf;
use std::process::ExitCode;

use binary_filler_core::{
    cover_preset, ingest_file, preset_toml, security_directory, stamp_certificate_file, Budget,
    Corpus, FailPolicy, IngestOptions, PRESET_NAMES,
};
use clap::{Parser, Subcommand};
use object::pe::{IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_SUBSYSTEM_WINDOWS_GUI};
use object::read::pe::{PeFile, PeFile64};
use object::LittleEndian as LE;
use object::{Object, ObjectSection};

#[derive(Debug, Parser)]
#[command(name = "binary-filler", about = "Corpus and fill helpers for binary-filler")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Extract low-entropy chunks from goodware into a corpus component.
    Ingest {
        /// Goodware file (e.g. rufus-4.15.exe).
        #[arg(long, short = 's')]
        source: PathBuf,

        /// Corpus root directory (will create components/<id>/).
        #[arg(long, short = 'c', default_value = "corpus")]
        corpus: PathBuf,

        /// Component id (default: source file stem).
        #[arg(long)]
        id: Option<String>,

        /// Tags for cover matching (comma-separated).
        #[arg(long, default_value = "gui,utility")]
        tags: String,

        /// Max chunks to keep after ranking.
        #[arg(long, default_value_t = 64)]
        max_chunks: usize,

        /// Window size in bytes.
        #[arg(long, default_value_t = 4096)]
        window: usize,

        /// Max Shannon entropy (bits/byte) for accepted chunks.
        #[arg(long, default_value_t = 6.0)]
        max_entropy: f64,

        /// Scan raw file windows instead of PE sections first.
        #[arg(long)]
        raw: bool,
    },

    /// List corpus components and chunk stats.
    Corpus {
        #[command(subcommand)]
        command: CorpusCommand,
    },

    /// Built-in cover presets.
    Preset {
        #[command(subcommand)]
        command: PresetCommand,
    },

    /// Static checks on a filled Windows PE (no execution).
    Verify {
        /// Path to PE (.exe/.dll).
        #[arg(long, short = 'p')]
        pe: PathBuf,

        /// Expected company name (UTF-16 resource string).
        #[arg(long)]
        company: Option<String>,

        /// Expected product name.
        #[arg(long)]
        product: Option<String>,

        /// Require GUI subsystem.
        #[arg(long, default_value_t = true)]
        require_gui: bool,

        /// Require these import DLLs (comma-separated, lower-case).
        #[arg(long, default_value = "user32.dll,gdi32.dll")]
        require_imports: String,

        /// Require a non-empty Authenticode security directory (may be invalid).
        #[arg(long, default_value_t = false)]
        require_cert: bool,
    },

    /// Copy a donor PE's Authenticode certificate table onto a target PE (post-link).
    ///
    /// The signature will **not** cryptographically verify — only the security
    /// directory / WIN_CERTIFICATE blob is present for static heuristics.
    StampCert {
        /// Donor PE that already has an Authenticode table (e.g. corpus/bundled/putty-x64.exe).
        #[arg(long, short = 'd')]
        donor: PathBuf,

        /// Target PE to stamp (typically your filled agent after cargo build).
        #[arg(long, short = 't')]
        target: PathBuf,

        /// Output path (default: overwrite target).
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum CorpusCommand {
    /// Show components under a corpus root.
    List {
        #[arg(long, short = 'c', default_value = "corpus")]
        corpus: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PresetCommand {
    /// List built-in preset names.
    List,
    /// Print preset TOML to stdout.
    Show {
        name: String,
    },
    /// Validate that a preset loads.
    Check {
        name: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Ingest {
            source,
            corpus,
            id,
            tags,
            max_chunks,
            window,
            max_entropy,
            raw,
        } => run_ingest(source, corpus, id, tags, max_chunks, window, max_entropy, raw),
        Command::Corpus {
            command: CorpusCommand::List { corpus },
        } => run_corpus_list(corpus),
        Command::Preset {
            command: PresetCommand::List,
        } => {
            for name in PRESET_NAMES {
                println!("{name}");
            }
            Ok(())
        }
        Command::Preset {
            command: PresetCommand::Show { name },
        } => {
            let Some(toml) = preset_toml(&name) else {
                eprintln!("unknown preset: {name}");
                return ExitCode::FAILURE;
            };
            print!("{toml}");
            Ok(())
        }
        Command::Preset {
            command: PresetCommand::Check { name },
        } => run_preset_check(name),
        Command::Verify {
            pe,
            company,
            product,
            require_gui,
            require_imports,
            require_cert,
        } => run_verify(pe, company, product, require_gui, require_imports, require_cert),
        Command::StampCert {
            donor,
            target,
            output,
        } => run_stamp_cert(donor, target, output),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_preset_check(name: String) -> Result<(), binary_filler_core::Error> {
    let cover = cover_preset(&name)?;
    println!("ok {} ({})", cover.name, cover.product_name);
    Ok(())
}

fn run_ingest(
    source: PathBuf,
    corpus: PathBuf,
    id: Option<String>,
    tags: String,
    max_chunks: usize,
    window: usize,
    max_entropy: f64,
    raw: bool,
) -> Result<(), binary_filler_core::Error> {
    let tag_list: Vec<String> = tags
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();

    let options = IngestOptions {
        component_id: id.unwrap_or_default(),
        tags: tag_list,
        window_bytes: window,
        stride_bytes: window,
        budget: Budget {
            max_blob_bytes: usize::MAX,
            max_chunk_entropy: max_entropy,
            min_chunk_entropy: 1.5,
            min_chunk_bytes: 256,
            max_chunk_bytes: window.max(256),
        },
        max_chunks,
        prefer_pe_sections: !raw,
    };

    let report = ingest_file(&corpus, &source, options)?;
    println!("ingested {}", report.source.display());
    println!("  component : {}", report.component_id);
    println!("  dir       : {}", report.component_dir.display());
    println!("  source    : {} bytes", report.bytes_read);
    println!("  pe mode   : {}", report.used_pe_sections);
    println!("  candidates: {}", report.candidates_seen);
    println!("  chunks    : {}", report.chunks_written);
    println!("  chunk sum : {} bytes", report.total_chunk_bytes);
    println!("  avg H     : {:.3} bits/byte", report.average_entropy);
    Ok(())
}

fn run_corpus_list(corpus: PathBuf) -> Result<(), binary_filler_core::Error> {
    let corpus = Corpus::load(&corpus)?;
    println!("corpus {}", corpus.root().display());
    for component in corpus.components() {
        let bytes: usize = component.chunks.iter().map(|c| c.byte_len).sum();
        let avg_h = if component.chunks.is_empty() {
            0.0
        } else {
            component.chunks.iter().map(|c| c.entropy).sum::<f64>() / component.chunks.len() as f64
        };
        println!(
            "  {}  chunks={}  bytes={}  avgH={:.3}  tags={:?}",
            component.id,
            component.chunks.len(),
            bytes,
            avg_h,
            component.tags
        );
    }
    // Touch FailPolicy so docs examples stay linked in CLI help generation builds.
    let _ = FailPolicy::ops();
    Ok(())
}

fn run_stamp_cert(
    donor: PathBuf,
    target: PathBuf,
    output: Option<PathBuf>,
) -> Result<(), binary_filler_core::Error> {
    let out = output.unwrap_or_else(|| target.clone());
    let report = stamp_certificate_file(&donor, &target, &out)?;
    println!("stamped certificate (INVALID — hash will not verify)");
    println!("  donor     {}", report.donor.display());
    println!("  target    {}", report.target.display());
    println!("  output    {}", report.output.display());
    println!("  cert_bytes {}", report.certificate_bytes);
    println!("  sec_offset {}", report.security_file_offset);
    println!("  replaced  {}", report.had_existing_target_cert);
    println!("RESULT=OK");
    Ok(())
}

fn run_verify(
    pe: PathBuf,
    company: Option<String>,
    product: Option<String>,
    require_gui: bool,
    require_imports: String,
    require_cert: bool,
) -> Result<(), binary_filler_core::Error> {
    let data = std::fs::read(&pe).map_err(|e| binary_filler_core::Error::io(&pe, e))?;
    if data.len() < 64 || &data[..2] != b"MZ" {
        return Err(binary_filler_core::Error::Msg(format!(
            "{} is not a PE (missing MZ)",
            pe.display()
        )));
    }

    let file = object::File::parse(&*data)
        .map_err(|e| binary_filler_core::Error::Msg(format!("PE parse: {e}")))?;
    let pe64: PeFile64<'_> = PeFile::parse(&*data)
        .map_err(|e| binary_filler_core::Error::Msg(format!("PeFile64: {e}")))?;

    let subsystem = pe64.nt_headers().optional_header.subsystem.get(LE);
    let has_rsrc = pe64
        .data_directories()
        .get(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        .is_some_and(|d| d.virtual_address.get(LE) != 0);

    let (sec_off, sec_size) = security_directory(&data)?;
    let has_cert = sec_off != 0 && sec_size != 0;

    let sections: Vec<String> = file
        .sections()
        .filter_map(|s| s.name().ok().map(|n| n.to_string()))
        .collect();

    let mut imports: Vec<String> = file
        .imports()
        .map_err(|e| binary_filler_core::Error::Msg(format!("imports: {e}")))?
        .iter()
        .map(|i| String::from_utf8_lossy(i.library()).to_ascii_lowercase())
        .collect();
    imports.sort();
    imports.dedup();

    println!("pe {}", pe.display());
    println!("  size       {}", data.len());
    println!("  subsystem  {subsystem} (2=GUI)");
    println!("  rsrc_dir   {has_rsrc}");
    println!("  cert_dir   {has_cert} (off={sec_off} size={sec_size})");
    println!("  sections   {}", sections.join(","));
    println!("  imports    {}", imports.join(","));

    let mut failed = false;
    if require_gui && subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI {
        eprintln!("FAIL: expected GUI subsystem");
        failed = true;
    }
    if !has_rsrc {
        eprintln!("FAIL: missing resource directory");
        failed = true;
    }
    if !sections.iter().any(|s| s.starts_with(".rsrc")) {
        eprintln!("FAIL: missing .rsrc section");
        failed = true;
    }
    if require_cert && !has_cert {
        eprintln!("FAIL: missing Authenticode security directory");
        failed = true;
    }

    for s in [company.as_deref(), product.as_deref()].into_iter().flatten() {
        if !utf16le_contains(&data, s) {
            eprintln!("FAIL: missing UTF-16 string {s:?}");
            failed = true;
        } else {
            println!("  utf16 ok   {s}");
        }
    }

    for dll in require_imports.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if !imports.iter().any(|i| i == dll) {
            eprintln!("FAIL: missing import {dll}");
            failed = true;
        }
    }

    if failed {
        return Err(binary_filler_core::Error::Msg("verify failed".into()));
    }
    println!("RESULT=OK");
    Ok(())
}

fn utf16le_contains(haystack: &[u8], needle: &str) -> bool {
    let encoded: Vec<u8> = needle
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    haystack
        .windows(encoded.len())
        .any(|w| w == encoded.as_slice())
}
