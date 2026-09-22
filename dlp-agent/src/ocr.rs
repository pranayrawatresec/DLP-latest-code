//! Offline image OCR via the Windows built-in OCR engine (WinRT
//! `Windows.Media.Ocr`). Turns an image (a pasted screenshot, an image file on a
//! stick, a scanned/text-less PDF page rendered upstream) into text so the SHARED
//! detection engine (`detect::verdict_text` / EDM) can score it. Used across every
//! channel that inspects content, gated by the console OCR policy.
//!
//! Why the OS engine: it ships with Windows, runs **fully offline**, is
//! Microsoft-signed, and adds **no third-party code or model files** — the product's
//! minimal-supply-chain rule (and the cleanest for a defence accreditation). It
//! needs the OS OCR language pack installed; when absent, [`available`] is false and
//! callers fall back to their fail-mode.
//!
//! Non-Windows builds get inert stubs so the crate keeps cross-compiling.

/// True when an image's leading bytes look like a raster format the OS decoder can
/// read (PNG/JPEG/GIF/BMP/TIFF). A cheap gate so we only attempt OCR on real images.
pub fn looks_like_image(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    let b = bytes;
    // PNG
    if b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return true;
    }
    // JPEG
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return true;
    }
    // GIF
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return true;
    }
    // BMP
    if b.starts_with(b"BM") {
        return true;
    }
    // TIFF (little/big endian)
    if b.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || b.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) {
        return true;
    }
    false
}

/// A clipboard `CF_DIB` is a `BITMAPINFOHEADER` + palette + pixels with NO file
/// header — the OS image decoder can't read it directly. Prepend a 14-byte
/// `BITMAPFILEHEADER` so it becomes a valid in-memory `.bmp`. Pure + unit-tested.
///
/// The pixel-data offset = 14 (file header) + the DIB header size (first u32 of the
/// DIB) + the colour table. We approximate the colour table for the common
/// 24/32-bpp screenshot case (no palette); paletted DIBs (≤8bpp) are rare for
/// screenshots and simply may not decode (caller falls back). Returns None if the
/// DIB is too small to be valid.
pub fn dib_to_bmp(dib: &[u8]) -> Option<Vec<u8>> {
    if dib.len() < 40 {
        return None; // smaller than a BITMAPINFOHEADER
    }
    let header_size = u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]) as usize;
    if header_size < 12 || header_size > dib.len() {
        return None;
    }
    // bit count is at offset 14 in BITMAPINFOHEADER (u16). Colour table only for
    // <=8bpp; screenshots are 24/32bpp → no table.
    let bpp = if dib.len() >= 16 {
        u16::from_le_bytes([dib[14], dib[15]])
    } else {
        0
    };
    let color_table = if bpp != 0 && bpp <= 8 {
        (1usize << bpp) * 4
    } else {
        0
    };
    let pixel_offset = 14 + header_size + color_table;
    let file_size = 14 + dib.len();
    let mut out = Vec::with_capacity(file_size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(file_size as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved1
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    out.extend_from_slice(&(pixel_offset as u32).to_le_bytes());
    out.extend_from_slice(dib);
    Some(out)
}

/// Width*height of a `CF_DIB` from its `BITMAPINFOHEADER` (width @ off 4, height
/// @ off 8, signed LE). `None` if the header is too short.
pub fn dib_pixels(dib: &[u8]) -> Option<u64> {
    if dib.len() < 12 {
        return None;
    }
    let w = i32::from_le_bytes([dib[4], dib[5], dib[6], dib[7]]).unsigned_abs() as u64;
    let h = i32::from_le_bytes([dib[8], dib[9], dib[10], dib[11]]).unsigned_abs() as u64;
    Some(w.saturating_mul(h))
}

/// OCR a clipboard `CF_DIB` (raw, no file header), honoring the pixel cap. Returns
/// the recognized text, or None (too big / undecodable / no engine / no text).
pub fn ocr_dib(dib: &[u8], max_pixels: u64) -> Option<String> {
    if let Some(px) = dib_pixels(dib) {
        if px > max_pixels {
            return None;
        }
    }
    let bmp = dib_to_bmp(dib)?;
    image_to_text(&bmp)
}

/// OCR a self-contained image file (PNG/JPEG/BMP/…), honoring a rough size cap
/// (bytes ≈ up to 4 bytes/pixel). Returns recognized text or None.
pub fn ocr_image(bytes: &[u8], max_pixels: u64) -> Option<String> {
    if !looks_like_image(bytes) {
        return None;
    }
    // Rough guard without decoding: assume ≤4 bytes/pixel uncompressed-worst-case.
    if (bytes.len() as u64) > max_pixels.saturating_mul(4) {
        return None;
    }
    image_to_text(bytes)
}

// ---------------------------------------------------------------------------
// Windows: the real OCR path.
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod imp {
    use std::sync::atomic::{AtomicU8, Ordering};

    // Ensure the calling thread has a WinRT apartment exactly once. RoInitialize
    // returns S_OK / S_FALSE (already init) / RPC_E_CHANGED_MODE (a different mode
    // already set) — all fine for our read-only WinRT use, so we never treat init
    // as fatal.
    fn ensure_apartment() {
        thread_local! { static INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
        INIT.with(|done| {
            if !done.get() {
                use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};
                unsafe {
                    let _ = RoInitialize(RO_INIT_MULTITHREADED);
                }
                done.set(true);
            }
        });
    }

    // Availability is cached: 0 = unknown, 1 = available, 2 = unavailable.
    static AVAIL: AtomicU8 = AtomicU8::new(0);

    fn make_engine() -> Option<windows::Media::Ocr::OcrEngine> {
        use windows::Media::Ocr::OcrEngine;
        // Prefer the user's profile languages; the call returns null (Err/!ok) when
        // no OCR language pack is installed.
        ensure_apartment();
        OcrEngine::TryCreateFromUserProfileLanguages().ok()
    }

    pub fn available() -> bool {
        match AVAIL.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => {
                let ok = make_engine().is_some();
                AVAIL.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
                ok
            }
        }
    }

    /// Decode `bytes` (a self-contained image container: PNG/JPEG/BMP/…) and OCR it.
    /// Returns the recognized text, or None on any failure (caller falls back).
    pub fn image_to_text(bytes: &[u8]) -> Option<String> {
        use windows::Graphics::Imaging::BitmapDecoder;
        use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};

        ensure_apartment();
        let engine = make_engine()?;

        // WinRT decoders read from an IRandomAccessStream — write the bytes into an
        // in-memory stream, rewind, decode to a SoftwareBitmap, then recognize. Each
        // async op is driven to completion synchronously with `.get()` (this runs on
        // a worker thread; clipboard/seal events are infrequent).
        let stream = InMemoryRandomAccessStream::new().ok()?;
        let writer = DataWriter::CreateDataWriter(&stream).ok()?;
        writer.WriteBytes(bytes).ok()?;
        writer.StoreAsync().ok()?.get().ok()?;
        writer.FlushAsync().ok()?.get().ok()?;
        writer.DetachStream().ok()?;
        stream.Seek(0).ok()?;

        let decoder = BitmapDecoder::CreateAsync(&stream).ok()?.get().ok()?;
        let bitmap = decoder.GetSoftwareBitmapAsync().ok()?.get().ok()?;
        let result = engine.RecognizeAsync(&bitmap).ok()?.get().ok()?;
        let text = result.Text().ok()?.to_string_lossy();
        if text.trim().is_empty() {
            None
        } else {
            Some(text)
        }
    }
}

#[cfg(windows)]
pub use imp::{available, image_to_text};

// ---------------------------------------------------------------------------
// Non-Windows stubs.
// ---------------------------------------------------------------------------
#[cfg(not(windows))]
pub fn available() -> bool {
    false
}

#[cfg(not(windows))]
pub fn image_to_text(_bytes: &[u8]) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_image_magics() {
        assert!(looks_like_image(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0]));
        assert!(looks_like_image(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(looks_like_image(b"BM------------"));
        assert!(looks_like_image(b"GIF89a--------"));
        // Not images:
        assert!(!looks_like_image(b"%PDF-1.7 ----"));
        assert!(!looks_like_image(b"plain text"));
        assert!(!looks_like_image(&[]));
    }

    #[test]
    fn dib_to_bmp_prepends_a_valid_file_header() {
        // Minimal 40-byte BITMAPINFOHEADER, 32bpp (no colour table).
        let mut dib = vec![0u8; 40];
        dib[0] = 40; // biSize = 40 (little-endian u32)
        dib[14] = 32; // biBitCount = 32
        dib.extend_from_slice(&[0xAA; 16]); // fake pixels
        let bmp = dib_to_bmp(&dib).expect("valid dib");
        assert_eq!(&bmp[0..2], b"BM");
        // file size = 14 + dib len
        assert_eq!(u32::from_le_bytes([bmp[2], bmp[3], bmp[4], bmp[5]]), (14 + dib.len()) as u32);
        // pixel offset = 14 + 40 (header) + 0 (no table)
        assert_eq!(u32::from_le_bytes([bmp[10], bmp[11], bmp[12], bmp[13]]), 54);
        // the DIB is appended verbatim after the 14-byte header
        assert_eq!(&bmp[14..], &dib[..]);
    }

    #[test]
    fn dib_to_bmp_rejects_too_small() {
        assert!(dib_to_bmp(&[0u8; 8]).is_none());
    }
}
