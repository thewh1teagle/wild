//! Validation and canonical construction of AMD64 PE exception data.
//!
//! AMD64's exception directory is a sequence of 12-byte `RUNTIME_FUNCTION`
//! records in `.pdata`. Each record names an `UNWIND_INFO` structure, normally
//! in `.xdata`. This module deliberately validates the loader-visible shape,
//! while leaving language-specific bytes following an exception handler opaque.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

const RUNTIME_FUNCTION_SIZE: usize = 12;
const UNWIND_INFO_HEADER_SIZE: usize = 4;
const UNWIND_CODE_SIZE: usize = 2;
const UNW_FLAG_EHANDLER: u8 = 1;
const UNW_FLAG_UHANDLER: u8 = 2;
const UNW_FLAG_CHAININFO: u8 = 4;
const MAX_CHAIN_DEPTH: usize = 32;

/// One AMD64 `RUNTIME_FUNCTION` record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
}

/// A PE optional-header data-directory value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExceptionDirectoryRange {
    pub rva: u32,
    pub size: u32,
}

/// An emission-ready AMD64 exception table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Amd64ExceptionTable {
    /// Runtime-function records in emitted order.
    pub functions: Vec<RuntimeFunction>,
    /// Deterministic bytes to emit as `.pdata`.
    pub pdata: Vec<u8>,
    /// Value to publish as `IMAGE_DIRECTORY_ENTRY_EXCEPTION`.
    pub directory: ExceptionDirectoryRange,
}

/// Broad category of malformed AMD64 exception data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeUnwindErrorKind {
    MisalignedPdata,
    TruncatedPdata,
    InvalidFunctionRange,
    FunctionOutOfBounds,
    OverlappingFunctions,
    InvalidUnwindRva,
    TruncatedUnwindInfo,
    UnsupportedUnwindVersion,
    InvalidUnwindFlags,
    InvalidUnwindCode,
    InvalidFrameRegister,
    InvalidHandlerRva,
    InvalidChain,
    ChainCycle,
    ArithmeticOverflow,
}

/// An actionable exception-table validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeUnwindError {
    kind: PeUnwindErrorKind,
    message: String,
}

impl PeUnwindError {
    fn new(kind: PeUnwindErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn kind(&self) -> PeUnwindErrorKind {
        self.kind
    }
}

impl fmt::Display for PeUnwindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PeUnwindError {}

pub type Result<T> = std::result::Result<T, PeUnwindError>;

/// Sorts an AMD64 `.pdata` contribution the same way as `lld-link`.
///
/// The production linker treats unwind data as opaque: it checks only the
/// loader-visible table shape and image range, then sorts records by their
/// begin RVA. In particular, it neither deduplicates records nor interprets
/// the referenced `.xdata` bytes.
pub fn sort_amd64_exception_table(
    pdata: &[u8],
    pdata_rva: u32,
    size_of_image: u32,
) -> Result<Amd64ExceptionTable> {
    let input_size = validate_pdata_shape(pdata, pdata_rva, size_of_image)?;
    let mut functions = pdata
        .chunks_exact(RUNTIME_FUNCTION_SIZE)
        .map(parse_runtime_function)
        .collect::<Vec<_>>();
    functions.sort_unstable_by_key(|function| function.begin_rva);

    let mut sorted = Vec::with_capacity(pdata.len());
    for function in &functions {
        sorted.extend_from_slice(&function.begin_rva.to_le_bytes());
        sorted.extend_from_slice(&function.end_rva.to_le_bytes());
        sorted.extend_from_slice(&function.unwind_info_rva.to_le_bytes());
    }

    Ok(Amd64ExceptionTable {
        functions,
        pdata: sorted,
        directory: ExceptionDirectoryRange {
            rva: pdata_rva,
            size: input_size,
        },
    })
}

/// Parses, validates, sorts and deduplicates an AMD64 `.pdata` contribution.
///
/// `pdata_rva` is where the returned bytes will be emitted. `xdata_rva` and
/// `xdata` describe one contiguous mapped region containing all referenced
/// unwind records. `size_of_image` is the exclusive upper bound for image RVAs.
pub fn build_amd64_exception_table(
    pdata: &[u8],
    pdata_rva: u32,
    xdata: &[u8],
    xdata_rva: u32,
    size_of_image: u32,
) -> Result<Amd64ExceptionTable> {
    validate_pdata_shape(pdata, pdata_rva, size_of_image)?;
    let xdata_size = u32::try_from(xdata.len()).map_err(|_| {
        PeUnwindError::new(
            PeUnwindErrorKind::ArithmeticOverflow,
            ".xdata exceeds the PE 32-bit section-size limit",
        )
    })?;
    checked_image_range(xdata_rva, xdata_size, size_of_image, ".xdata")?;

    let mut functions = pdata
        .chunks_exact(RUNTIME_FUNCTION_SIZE)
        .map(parse_runtime_function)
        .collect::<Vec<_>>();
    functions.sort_unstable();
    functions.dedup();

    for (index, function) in functions.iter().copied().enumerate() {
        validate_function(function, size_of_image, "runtime function")?;
        if let Some(previous) = index.checked_sub(1).and_then(|i| functions.get(i))
            && function.begin_rva < previous.end_rva
        {
            return Err(PeUnwindError::new(
                PeUnwindErrorKind::OverlappingFunctions,
                format!(
                    "runtime function {:#x}..{:#x} overlaps {:#x}..{:#x}",
                    function.begin_rva, function.end_rva, previous.begin_rva, previous.end_rva
                ),
            ));
        }
    }

    let source = UnwindSource {
        bytes: xdata,
        rva: xdata_rva,
        size_of_image,
    };
    let mut validated = BTreeSet::new();
    let mut active = BTreeSet::new();
    for function in &functions {
        validate_unwind_info(
            function.unwind_info_rva,
            source,
            &mut validated,
            &mut active,
            0,
        )?;
    }

    let canonical_size = functions
        .len()
        .checked_mul(RUNTIME_FUNCTION_SIZE)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| {
            PeUnwindError::new(
                PeUnwindErrorKind::ArithmeticOverflow,
                "canonical exception directory size overflow",
            )
        })?;
    checked_image_range(pdata_rva, canonical_size, size_of_image, ".pdata")?;
    let mut canonical = Vec::with_capacity(canonical_size as usize);
    for function in &functions {
        canonical.extend_from_slice(&function.begin_rva.to_le_bytes());
        canonical.extend_from_slice(&function.end_rva.to_le_bytes());
        canonical.extend_from_slice(&function.unwind_info_rva.to_le_bytes());
    }

    Ok(Amd64ExceptionTable {
        functions,
        pdata: canonical,
        directory: ExceptionDirectoryRange {
            rva: pdata_rva,
            size: canonical_size,
        },
    })
}

fn validate_pdata_shape(pdata: &[u8], pdata_rva: u32, size_of_image: u32) -> Result<u32> {
    if !pdata_rva.is_multiple_of(4) {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::MisalignedPdata,
            format!(".pdata RVA {pdata_rva:#x} is not 4-byte aligned"),
        ));
    }
    if !pdata.len().is_multiple_of(RUNTIME_FUNCTION_SIZE) {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::TruncatedPdata,
            format!(
                ".pdata size {} is not a multiple of {RUNTIME_FUNCTION_SIZE}",
                pdata.len()
            ),
        ));
    }

    let input_size = u32::try_from(pdata.len()).map_err(|_| {
        PeUnwindError::new(
            PeUnwindErrorKind::ArithmeticOverflow,
            ".pdata exceeds the PE 32-bit directory-size limit",
        )
    })?;
    checked_image_range(pdata_rva, input_size, size_of_image, ".pdata")?;
    Ok(input_size)
}

#[derive(Clone, Copy)]
struct UnwindSource<'data> {
    bytes: &'data [u8],
    rva: u32,
    size_of_image: u32,
}

fn validate_unwind_info(
    rva: u32,
    source: UnwindSource<'_>,
    validated: &mut BTreeSet<u32>,
    active: &mut BTreeSet<u32>,
    depth: usize,
) -> Result<()> {
    if validated.contains(&rva) {
        return Ok(());
    }
    if depth >= MAX_CHAIN_DEPTH || !active.insert(rva) {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::ChainCycle,
            format!("cyclic or excessively deep chained unwind info at RVA {rva:#x}"),
        ));
    }
    let result = validate_unwind_info_inner(rva, source, validated, active, depth);
    active.remove(&rva);
    if result.is_ok() {
        validated.insert(rva);
    }
    result
}

fn validate_unwind_info_inner(
    rva: u32,
    source: UnwindSource<'_>,
    validated: &mut BTreeSet<u32>,
    active: &mut BTreeSet<u32>,
    depth: usize,
) -> Result<()> {
    if !rva.is_multiple_of(4) {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::InvalidUnwindRva,
            format!("UNWIND_INFO RVA {rva:#x} is not 4-byte aligned"),
        ));
    }
    let offset = rva.checked_sub(source.rva).ok_or_else(|| {
        PeUnwindError::new(
            PeUnwindErrorKind::InvalidUnwindRva,
            format!(
                "UNWIND_INFO RVA {rva:#x} precedes .xdata at {:#x}",
                source.rva
            ),
        )
    })? as usize;
    let header = slice_at(
        source.bytes,
        offset,
        UNWIND_INFO_HEADER_SIZE,
        PeUnwindErrorKind::TruncatedUnwindInfo,
        format!("truncated UNWIND_INFO header at RVA {rva:#x}"),
    )?;
    let version = header[0] & 7;
    let flags = header[0] >> 3;
    if !matches!(version, 1 | 2) {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::UnsupportedUnwindVersion,
            format!("unsupported UNWIND_INFO version {version} at RVA {rva:#x}"),
        ));
    }
    if flags & !7 != 0 || flags & UNW_FLAG_CHAININFO != 0 && flags & 3 != 0 {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::InvalidUnwindFlags,
            format!("invalid UNWIND_INFO flags {flags:#x} at RVA {rva:#x}"),
        ));
    }
    let prolog_size = header[1];
    let code_count = usize::from(header[2]);
    let frame_register = header[3] & 0x0f;
    // The scaled offset has meaning only when a frame register is selected.
    // The Windows x64 format does not require that otherwise-unused nibble to
    // be zero, and both lld-link and LLVM's unwind reader preserve/accept it.
    if frame_register != 0 && !matches!(frame_register, 3 | 5 | 6 | 7 | 12..=15) {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::InvalidFrameRegister,
            format!(
                "volatile register {frame_register} cannot be a frame register at RVA {rva:#x}"
            ),
        ));
    }

    let aligned_code_count = code_count
        .checked_add(1)
        .map(|count| count & !1)
        .ok_or_else(|| {
            PeUnwindError::new(
                PeUnwindErrorKind::ArithmeticOverflow,
                format!("aligned unwind-code count overflow at RVA {rva:#x}"),
            )
        })?;
    let code_bytes = aligned_code_count
        .checked_mul(UNWIND_CODE_SIZE)
        .ok_or_else(|| {
            PeUnwindError::new(
                PeUnwindErrorKind::ArithmeticOverflow,
                format!("unwind-code size overflow at RVA {rva:#x}"),
            )
        })?;
    let codes_offset = offset + UNWIND_INFO_HEADER_SIZE;
    let codes = slice_at(
        source.bytes,
        codes_offset,
        code_bytes,
        PeUnwindErrorKind::TruncatedUnwindInfo,
        format!("truncated unwind-code array at RVA {rva:#x}"),
    )?;
    validate_codes(
        &codes[..code_count * UNWIND_CODE_SIZE],
        code_count,
        prolog_size,
        rva,
    )?;

    let suffix_offset = codes_offset
        .checked_add(aligned_code_count * UNWIND_CODE_SIZE)
        .ok_or_else(|| {
            PeUnwindError::new(
                PeUnwindErrorKind::ArithmeticOverflow,
                format!("UNWIND_INFO suffix offset overflow at RVA {rva:#x}"),
            )
        })?;
    if flags & UNW_FLAG_CHAININFO != 0 {
        let chained = parse_runtime_function(slice_at(
            source.bytes,
            suffix_offset,
            RUNTIME_FUNCTION_SIZE,
            PeUnwindErrorKind::TruncatedUnwindInfo,
            format!("truncated chained RUNTIME_FUNCTION at RVA {rva:#x}"),
        )?);
        validate_function(chained, source.size_of_image, "chained runtime function")?;
        let chained_header = unwind_header(chained.unwind_info_rva, source)?;
        if chained_header[3] != header[3] {
            return Err(PeUnwindError::new(
                PeUnwindErrorKind::InvalidChain,
                format!(
                    "chained UNWIND_INFO at RVA {:#x} does not preserve frame register/offset from RVA {rva:#x}",
                    chained.unwind_info_rva
                ),
            ));
        }
        validate_unwind_info(
            chained.unwind_info_rva,
            source,
            validated,
            active,
            depth + 1,
        )?;
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        let handler_bytes = slice_at(
            source.bytes,
            suffix_offset,
            4,
            PeUnwindErrorKind::TruncatedUnwindInfo,
            format!("missing exception-handler RVA at UNWIND_INFO RVA {rva:#x}"),
        )?;
        let handler_rva = read_u32(handler_bytes, 0);
        if handler_rva == 0 || handler_rva >= source.size_of_image {
            return Err(PeUnwindError::new(
                PeUnwindErrorKind::InvalidHandlerRva,
                format!(
                    "exception-handler RVA {handler_rva:#x} at UNWIND_INFO RVA {rva:#x} is outside the image"
                ),
            ));
        }
    }
    Ok(())
}

fn validate_codes(codes: &[u8], count: usize, prolog_size: u8, unwind_rva: u32) -> Result<()> {
    let mut slot = 0usize;
    let mut previous_offset = u8::MAX;
    while slot < count {
        let code_offset = codes[slot * 2];
        let operation = codes[slot * 2 + 1] & 0x0f;
        let operation_info = codes[slot * 2 + 1] >> 4;
        if code_offset > prolog_size || code_offset > previous_offset {
            return Err(PeUnwindError::new(
                PeUnwindErrorKind::InvalidUnwindCode,
                format!(
                    "unwind code slot {slot} has invalid prolog offset {code_offset} at RVA {unwind_rva:#x}"
                ),
            ));
        }
        previous_offset = code_offset;
        let slots = match operation {
            0 | 2 | 3 => 1,
            1 if operation_info == 0 => 2,
            1 if operation_info == 1 => 3,
            1 => 0,
            4 | 8 => 2,
            5 | 9 => 3,
            // Version 1 used these for the now-deprecated SAVE_XMM encodings;
            // version 2 reuses them for epilog/no-op records with the same size.
            6 => 2,
            7 => 3,
            10 if operation_info <= 1 => 1,
            _ => 0,
        };
        if slots == 0 || slot + slots > count {
            return Err(PeUnwindError::new(
                PeUnwindErrorKind::InvalidUnwindCode,
                format!(
                    "invalid or truncated unwind operation {operation} (info {operation_info}) in slot {slot} at RVA {unwind_rva:#x}"
                ),
            ));
        }
        slot += slots;
    }
    Ok(())
}

fn unwind_header(rva: u32, source: UnwindSource<'_>) -> Result<&[u8]> {
    if !rva.is_multiple_of(4) {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::InvalidUnwindRva,
            format!("UNWIND_INFO RVA {rva:#x} is not 4-byte aligned"),
        ));
    }
    let offset = rva.checked_sub(source.rva).ok_or_else(|| {
        PeUnwindError::new(
            PeUnwindErrorKind::InvalidUnwindRva,
            format!(
                "UNWIND_INFO RVA {rva:#x} precedes .xdata at {:#x}",
                source.rva
            ),
        )
    })? as usize;
    slice_at(
        source.bytes,
        offset,
        UNWIND_INFO_HEADER_SIZE,
        PeUnwindErrorKind::TruncatedUnwindInfo,
        format!("truncated UNWIND_INFO header at RVA {rva:#x}"),
    )
}

fn validate_function(function: RuntimeFunction, image_size: u32, what: &str) -> Result<()> {
    if function.begin_rva >= function.end_rva {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::InvalidFunctionRange,
            format!(
                "{what} has invalid range {:#x}..{:#x}",
                function.begin_rva, function.end_rva
            ),
        ));
    }
    if function.end_rva > image_size {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::FunctionOutOfBounds,
            format!(
                "{what} range {:#x}..{:#x} exceeds image size {image_size:#x}",
                function.begin_rva, function.end_rva
            ),
        ));
    }
    Ok(())
}

fn checked_image_range(start: u32, size: u32, image_size: u32, what: &str) -> Result<()> {
    let end = start.checked_add(size).ok_or_else(|| {
        PeUnwindError::new(
            PeUnwindErrorKind::ArithmeticOverflow,
            format!("{what} RVA range overflows u32"),
        )
    })?;
    if end > image_size {
        return Err(PeUnwindError::new(
            PeUnwindErrorKind::FunctionOutOfBounds,
            format!("{what} range {start:#x}..{end:#x} exceeds image size {image_size:#x}"),
        ));
    }
    Ok(())
}

fn parse_runtime_function(bytes: &[u8]) -> RuntimeFunction {
    RuntimeFunction {
        begin_rva: read_u32(bytes, 0),
        end_rva: read_u32(bytes, 4),
        unwind_info_rva: read_u32(bytes, 8),
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn slice_at(
    bytes: &[u8],
    offset: usize,
    size: usize,
    kind: PeUnwindErrorKind,
    message: String,
) -> Result<&[u8]> {
    let end = offset.checked_add(size).ok_or_else(|| {
        PeUnwindError::new(PeUnwindErrorKind::ArithmeticOverflow, message.clone())
    })?;
    bytes
        .get(offset..end)
        .ok_or_else(|| PeUnwindError::new(kind, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_SIZE: u32 = 0x5000;
    const PDATA_RVA: u32 = 0x2000;
    const XDATA_RVA: u32 = 0x3000;

    fn function(begin: u32, end: u32, unwind: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&begin.to_le_bytes());
        bytes.extend_from_slice(&end.to_le_bytes());
        bytes.extend_from_slice(&unwind.to_le_bytes());
        bytes
    }

    fn basic_unwind() -> Vec<u8> {
        vec![1, 4, 1, 0, 4, 0, 0, 0]
    }

    #[test]
    fn lld_sort_preserves_opaque_records_and_duplicates() {
        let first = function(0x1000, 0, 0xffff_fff1);
        let second = function(0x2000, 1, 0xdead_beef);
        let pdata = [second.as_slice(), first.as_slice(), first.as_slice()].concat();

        let table = sort_amd64_exception_table(&pdata, PDATA_RVA, IMAGE_SIZE).unwrap();

        assert_eq!(
            table.pdata,
            [first.as_slice(), first.as_slice(), second.as_slice()].concat()
        );
        assert_eq!(table.directory.rva, PDATA_RVA);
        assert_eq!(table.directory.size, 36);
    }

    #[test]
    fn lld_sort_rejects_malformed_pdata_shape_and_range() {
        let record = function(0x1000, 0x1010, XDATA_RVA);
        let error = sort_amd64_exception_table(&record, PDATA_RVA + 1, IMAGE_SIZE).unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::MisalignedPdata);

        let error = sort_amd64_exception_table(&record[..11], PDATA_RVA, IMAGE_SIZE).unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::TruncatedPdata);

        let error = sort_amd64_exception_table(&record, IMAGE_SIZE - 4, IMAGE_SIZE).unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::FunctionOutOfBounds);
    }

    #[test]
    fn sorts_deduplicates_and_rebuilds_pdata() {
        let first = function(0x1000, 0x1010, XDATA_RVA);
        let second = function(0x1100, 0x1120, XDATA_RVA);
        let pdata = [second.as_slice(), first.as_slice(), first.as_slice()].concat();
        let table =
            build_amd64_exception_table(&pdata, PDATA_RVA, &basic_unwind(), XDATA_RVA, IMAGE_SIZE)
                .unwrap();

        assert_eq!(table.pdata, [first, second].concat());
        assert_eq!(table.directory.rva, PDATA_RVA);
        assert_eq!(table.directory.size, 24);
    }

    #[test]
    fn accepts_eh_and_uh_handlers() {
        for flags in [UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, 3] {
            let xdata = vec![1 | (flags << 3), 0, 0, 0, 0x00, 0x10, 0, 0];
            build_amd64_exception_table(
                &function(0x1000, 0x1010, XDATA_RVA),
                PDATA_RVA,
                &xdata,
                XDATA_RVA,
                IMAGE_SIZE,
            )
            .unwrap();
        }
    }

    #[test]
    fn ignores_frame_offset_when_there_is_no_frame_register() {
        for frame_offset in 1..=15 {
            let xdata = [1, 0, 0, frame_offset << 4];
            build_amd64_exception_table(
                &function(0x1000, 0x1010, XDATA_RVA),
                PDATA_RVA,
                &xdata,
                XDATA_RVA,
                IMAGE_SIZE,
            )
            .unwrap();
        }
    }

    #[test]
    fn rejects_volatile_frame_registers() {
        for frame_register in [1, 2, 4, 8, 9, 10, 11] {
            let xdata = [1, 0, 0, frame_register];
            let error = build_amd64_exception_table(
                &function(0x1000, 0x1010, XDATA_RVA),
                PDATA_RVA,
                &xdata,
                XDATA_RVA,
                IMAGE_SIZE,
            )
            .unwrap_err();
            assert_eq!(error.kind(), PeUnwindErrorKind::InvalidFrameRegister);
        }
    }

    #[test]
    fn accepts_and_follows_chained_info() {
        let mut xdata = vec![1 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0];
        xdata.extend_from_slice(&function(0x1000, 0x1010, XDATA_RVA + 16));
        xdata.extend_from_slice(&basic_unwind());
        build_amd64_exception_table(
            &function(0x1100, 0x1120, XDATA_RVA),
            PDATA_RVA,
            &xdata,
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap();
    }

    #[test]
    fn rejects_overlap_after_sorting() {
        let pdata = [
            function(0x1010, 0x1030, XDATA_RVA),
            function(0x1000, 0x1020, XDATA_RVA),
        ]
        .concat();
        let error =
            build_amd64_exception_table(&pdata, PDATA_RVA, &basic_unwind(), XDATA_RVA, IMAGE_SIZE)
                .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::OverlappingFunctions);
    }

    #[test]
    fn rejects_malformed_ranges_and_unwind_code_arrays() {
        let error = build_amd64_exception_table(
            &function(0x1010, 0x1010, XDATA_RVA),
            PDATA_RVA,
            &basic_unwind(),
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::InvalidFunctionRange);

        let truncated = [1, 4, 2, 0, 4, 1];
        let error = build_amd64_exception_table(
            &function(0x1000, 0x1010, XDATA_RVA),
            PDATA_RVA,
            &truncated,
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::TruncatedUnwindInfo);
    }

    #[test]
    fn rejects_bad_flags_handlers_and_chains() {
        let bad_flags = [1 | (8 << 3), 0, 0, 0];
        let error = build_amd64_exception_table(
            &function(0x1000, 0x1010, XDATA_RVA),
            PDATA_RVA,
            &bad_flags,
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::InvalidUnwindFlags);

        let missing_handler = [1 | (UNW_FLAG_EHANDLER << 3), 0, 0, 0];
        let error = build_amd64_exception_table(
            &function(0x1000, 0x1010, XDATA_RVA),
            PDATA_RVA,
            &missing_handler,
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::TruncatedUnwindInfo);

        let mut cycle = vec![1 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0];
        cycle.extend_from_slice(&function(0x1000, 0x1010, XDATA_RVA));
        let error = build_amd64_exception_table(
            &function(0x1100, 0x1120, XDATA_RVA),
            PDATA_RVA,
            &cycle,
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::ChainCycle);

        let mut mismatched_frame = vec![1 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0x35];
        mismatched_frame.extend_from_slice(&function(0x1000, 0x1010, XDATA_RVA + 16));
        mismatched_frame.extend_from_slice(&[1, 0, 0, 0]);
        let error = build_amd64_exception_table(
            &function(0x1100, 0x1120, XDATA_RVA),
            PDATA_RVA,
            &mismatched_frame,
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::InvalidChain);
    }

    #[test]
    fn rejects_unaligned_pdata_and_unwind_info() {
        let error = build_amd64_exception_table(
            &function(0x1000, 0x1010, XDATA_RVA),
            PDATA_RVA + 1,
            &basic_unwind(),
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::MisalignedPdata);

        let error = build_amd64_exception_table(
            &function(0x1000, 0x1010, XDATA_RVA + 1),
            PDATA_RVA,
            &basic_unwind(),
            XDATA_RVA,
            IMAGE_SIZE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), PeUnwindErrorKind::InvalidUnwindRva);
    }
}
