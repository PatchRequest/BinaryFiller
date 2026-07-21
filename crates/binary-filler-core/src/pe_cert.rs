//! Copy Authenticode certificate tables between PE files.
//!
//! The resulting signature is **cryptographically invalid** (image hash no longer
//! matches). The goal is static presence of a security directory / WIN_CERTIFICATE
//! blob for heuristic feature pollution — not a valid signature.
//!
//! This is intentionally a post-link operation: the certificate table can only be
//! attached to a finished PE image.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

/// IMAGE_DIRECTORY_ENTRY_SECURITY
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

const PE32_MAGIC: u16 = 0x10b;
const PE32PLUS_MAGIC: u16 = 0x20b;

#[derive(Debug, Clone)]
pub struct CertStampReport {
    pub donor: std::path::PathBuf,
    pub target: std::path::PathBuf,
    pub output: std::path::PathBuf,
    pub certificate_bytes: usize,
    pub security_file_offset: u32,
    pub had_existing_target_cert: bool,
}

/// Extract the Authenticode certificate table from a PE (file offset range).
pub fn extract_certificate_table(pe: &[u8]) -> Result<Vec<u8>> {
    let (off, size) = security_directory(pe)?;
    if size == 0 || off == 0 {
        return Err(Error::Msg(
            "PE has no Authenticode certificate table (security data directory empty)".into(),
        ));
    }
    let start = off as usize;
    let end = start.saturating_add(size as usize);
    if end > pe.len() {
        return Err(Error::Msg(format!(
            "security directory out of bounds: offset={off} size={size} file_len={}",
            pe.len()
        )));
    }
    // Basic WIN_CERTIFICATE sanity: first DWORD is length.
    if size < 8 {
        return Err(Error::Msg("certificate table too small".into()));
    }
    Ok(pe[start..end].to_vec())
}

/// Stamp `donor`'s certificate table onto `target`, writing `output`.
///
/// Overwrites any existing security directory on the target. Truncates a trailing
/// certificate overlay when present so the file does not grow unboundedly.
pub fn stamp_certificate_file(
    donor: impl AsRef<Path>,
    target: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<CertStampReport> {
    let donor_path = donor.as_ref();
    let target_path = target.as_ref();
    let output_path = output.as_ref();

    let donor_bytes = fs::read(donor_path).map_err(|e| Error::io(donor_path, e))?;
    let target_bytes = fs::read(target_path).map_err(|e| Error::io(target_path, e))?;

    let cert = extract_certificate_table(&donor_bytes)?;
    let (stamped, had_existing) = stamp_certificate_bytes(&target_bytes, &cert)?;

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
    }
    fs::write(output_path, &stamped).map_err(|e| Error::io(output_path, e))?;

    let (sec_off, sec_size) = security_directory(&stamped)?;
    debug_assert_eq!(sec_size as usize, cert.len());

    Ok(CertStampReport {
        donor: donor_path.to_path_buf(),
        target: target_path.to_path_buf(),
        output: output_path.to_path_buf(),
        certificate_bytes: cert.len(),
        security_file_offset: sec_off,
        had_existing_target_cert: had_existing,
    })
}

/// In-memory stamp: append `cert` to `target` PE and point the security directory at it.
pub fn stamp_certificate_bytes(target: &[u8], cert: &[u8]) -> Result<(Vec<u8>, bool)> {
    if cert.is_empty() {
        return Err(Error::Msg("certificate blob is empty".into()));
    }
    if cert.len() > u32::MAX as usize {
        return Err(Error::Msg("certificate blob too large".into()));
    }

    let (stripped, had_existing) = strip_certificate_table(target)?;
    let mut out = stripped;

    // Certificate tables are 8-byte aligned in practice.
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let cert_off = out.len();
    if cert_off > u32::MAX as usize {
        return Err(Error::Msg("PE too large to attach certificate".into()));
    }
    out.extend_from_slice(cert);
    set_security_directory(&mut out, cert_off as u32, cert.len() as u32)?;
    // Checksum is wrong either way; zero it so tools don't trust a stale value.
    zero_optional_checksum(&mut out)?;

    Ok((out, had_existing))
}

/// Remove security directory; truncate trailing cert overlay when it sits at EOF.
pub fn strip_certificate_table(pe: &[u8]) -> Result<(Vec<u8>, bool)> {
    let (off, size) = security_directory(pe)?;
    if size == 0 || off == 0 {
        return Ok((pe.to_vec(), false));
    }
    let start = off as usize;
    let end = start.saturating_add(size as usize);
    if end > pe.len() {
        return Err(Error::Msg(
            "target security directory out of bounds; refusing to strip".into(),
        ));
    }

    let mut out = pe.to_vec();
    // If the cert is a pure trailing overlay, drop it.
    if end == pe.len() {
        out.truncate(start);
    }
    set_security_directory(&mut out, 0, 0)?;
    zero_optional_checksum(&mut out)?;
    Ok((out, true))
}

/// Returns (file_offset, size) from the security data directory.
pub fn security_directory(pe: &[u8]) -> Result<(u32, u32)> {
    let layout = pe_layout(pe)?;
    let entry_off = layout.data_dirs_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if entry_off + 8 > pe.len() {
        return Err(Error::Msg("security data directory entry out of bounds".into()));
    }
    let off = u32::from_le_bytes(pe[entry_off..entry_off + 4].try_into().unwrap());
    let size = u32::from_le_bytes(pe[entry_off + 4..entry_off + 8].try_into().unwrap());
    Ok((off, size))
}

fn set_security_directory(pe: &mut [u8], off: u32, size: u32) -> Result<()> {
    let layout = pe_layout(pe)?;
    if IMAGE_DIRECTORY_ENTRY_SECURITY >= layout.number_of_rva_and_sizes as usize {
        return Err(Error::Msg(
            "PE NumberOfRvaAndSizes too small for security directory".into(),
        ));
    }
    let entry_off = layout.data_dirs_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if entry_off + 8 > pe.len() {
        return Err(Error::Msg("cannot write security data directory".into()));
    }
    pe[entry_off..entry_off + 4].copy_from_slice(&off.to_le_bytes());
    pe[entry_off + 4..entry_off + 8].copy_from_slice(&size.to_le_bytes());
    Ok(())
}

fn zero_optional_checksum(pe: &mut [u8]) -> Result<()> {
    let layout = pe_layout(pe)?;
    // CheckSum is at optional header + 64 for both PE32 and PE32+.
    let checksum_off = layout.optional_header_offset + 64;
    if checksum_off + 4 > pe.len() {
        return Err(Error::Msg("checksum field out of bounds".into()));
    }
    pe[checksum_off..checksum_off + 4].copy_from_slice(&0u32.to_le_bytes());
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct PeLayout {
    optional_header_offset: usize,
    data_dirs_offset: usize,
    number_of_rva_and_sizes: u32,
}

fn pe_layout(pe: &[u8]) -> Result<PeLayout> {
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return Err(Error::Msg("not a PE file (missing MZ)".into()));
    }
    let e_lfanew = u32::from_le_bytes(pe[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 4 + 20 + 2 > pe.len() {
        return Err(Error::Msg("invalid e_lfanew".into()));
    }
    if &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(Error::Msg("missing PE signature".into()));
    }
    let optional_header_offset = e_lfanew + 4 + 20;
    let magic =
        u16::from_le_bytes(pe[optional_header_offset..optional_header_offset + 2].try_into().unwrap());

    let (num_rva_off, data_dirs_offset) = match magic {
        PE32_MAGIC => {
            // NumberOfRvaAndSizes at +92, data dirs at +96
            (optional_header_offset + 92, optional_header_offset + 96)
        }
        PE32PLUS_MAGIC => {
            // NumberOfRvaAndSizes at +108, data dirs at +112
            (optional_header_offset + 108, optional_header_offset + 112)
        }
        _ => {
            return Err(Error::Msg(format!(
                "unsupported optional header magic {magic:#x}"
            )))
        }
    };

    if num_rva_off + 4 > pe.len() {
        return Err(Error::Msg("NumberOfRvaAndSizes out of bounds".into()));
    }
    let number_of_rva_and_sizes =
        u32::from_le_bytes(pe[num_rva_off..num_rva_off + 4].try_into().unwrap());
    if number_of_rva_and_sizes < 5 {
        return Err(Error::Msg(
            "PE has fewer than 5 data directories; cannot store security directory".into(),
        ));
    }

    Ok(PeLayout {
        optional_header_offset,
        data_dirs_offset,
        number_of_rva_and_sizes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn bundled(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/bundled")
            .join(name)
    }

    #[test]
    fn extracts_putty_certificate() {
        let path = bundled("putty-x64.exe");
        if !path.is_file() {
            eprintln!("skip: bundled putty missing");
            return;
        }
        let pe = fs::read(&path).unwrap();
        let cert = extract_certificate_table(&pe).unwrap();
        assert!(cert.len() > 100);
        let (off, size) = security_directory(&pe).unwrap();
        assert_eq!(size as usize, cert.len());
        assert!(off > 0);
    }

    #[test]
    fn stamps_certificate_onto_unsigned_image() {
        let donor_path = bundled("putty-x64.exe");
        let unsigned_path = bundled("busybox-w32.exe");
        if !donor_path.is_file() || !unsigned_path.is_file() {
            eprintln!("skip: bundled samples missing");
            return;
        }
        let donor = fs::read(&donor_path).unwrap();
        let target = fs::read(&unsigned_path).unwrap();
        let cert = extract_certificate_table(&donor).unwrap();

        let (before_off, before_size) = security_directory(&target).unwrap();
        assert_eq!((before_off, before_size), (0, 0));

        let (stamped, had) = stamp_certificate_bytes(&target, &cert).unwrap();
        assert!(!had);
        let (off, size) = security_directory(&stamped).unwrap();
        assert_eq!(size as usize, cert.len());
        assert_eq!(&stamped[off as usize..off as usize + size as usize], cert.as_slice());
        // Round-trip extract
        let again = extract_certificate_table(&stamped).unwrap();
        assert_eq!(again, cert);
    }
}
