//! Raw-protocol lab for reverse-engineering the Mad Dog GK150W boot logo write.
//!
//! The standard AKP153 boot-logo write (LOG + JPEG data) is rejected by the
//! GK150W firmware, so this tool tries several variants on the raw HID level
//! and hex-dumps whatever the device sends back.
//!
//! Usage:
//!   cargo run -p set_boot_logo --bin boot_logo_lab -- <strategy> <image>
//!
//! Strategies:
//!   replica             LOG(854) -> STP -> JPEG          (exact ajazz-sdk order)
//!   jpeg-stp-last       LOG(854) -> JPEG -> STP
//!   raw-bgr-854         DIS -> LOG(854x480x3) -> raw BGR -> STP
//!   raw-rgb-854         DIS -> LOG(854x480x3) -> raw RGB -> STP
//!   raw-bgr-800         DIS -> LOG(800x480x3) -> raw BGR -> STP
//!   raw-rgb-800         DIS -> LOG(800x480x3) -> raw RGB -> STP
//!   no-init-bgr-800     LOG(800x480x3) -> raw BGR -> STP      (pure 293 flow, no init)
//!   connect-bgr-800     DIS -> CONNECT -> LOG(800) -> raw BGR -> STP
//!   official-bgr-800    DIS -> LIG(100) -> CLE -> STP -> CONNECT -> LOG(800) -> raw BGR -> STP
//!
//! IMPORTANT: quit OpenDeck first, and after each attempt unplug/replug the
//! device and check whether the boot logo changed.

use std::error::Error;

use ajazz_sdk::{
    convert_image_with_format, ImageFormat, ImageMirroring, ImageMode, ImageRotation, Kind,
};
use hidapi::{HidApi, HidDevice};
use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;

const VID: u16 = 0x1200;
const PID: u16 = 0x2014;

/// v1 report: report id + 512 bytes of payload, zero padded
const REPORT_LEN: usize = 513;

/// `[0x00, 'C','R','T', 0x00, 0x00]` — common prefix of every command
const REQUEST_HEADER: [u8; 6] = [0x00, 0x43, 0x52, 0x54, 0x00, 0x00];

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let strategy = args.get(1).ok_or_else(usage)?;
    let image_path = args.get(2).ok_or_else(usage)?;

    println!("Opening device {VID:#06x}:{PID:#06x}...");
    let device = open_device()?;
    println!("Device opened");

    match strategy.as_str() {
        "replica" => {
            init(&device)?;
            println!("Sending LOG(854x480)...");
            device.write(&log_packet(854, 480))?;
            println!("Sending STP...");
            device.write(&stp_packet())?;
            println!("Sending JPEG data...");
            send_data(&device, &jpeg_data(image_path)?)?;
        }
        "jpeg-stp-last" => {
            init(&device)?;
            println!("Sending LOG(854x480)...");
            device.write(&log_packet(854, 480))?;
            println!("Sending JPEG data...");
            send_data(&device, &jpeg_data(image_path)?)?;
            println!("Sending STP...");
            device.write(&stp_packet())?;
        }
        "raw-bgr-854" => {
            init(&device)?;
            send_logo_raw(&device, image_path, 854, 480, true)?;
        }
        "raw-rgb-854" => {
            init(&device)?;
            send_logo_raw(&device, image_path, 854, 480, false)?;
        }
        "raw-bgr-800" => {
            init(&device)?;
            send_logo_raw(&device, image_path, 800, 480, true)?;
        }
        "raw-rgb-800" => {
            init(&device)?;
            send_logo_raw(&device, image_path, 800, 480, false)?;
        }
        "no-init-bgr-800" => {
            send_logo_raw(&device, image_path, 800, 480, true)?;
        }
        "connect-bgr-800" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_logo_raw(&device, image_path, 800, 480, true)?;
        }
        "official-bgr-800" => {
            init(&device)?;
            println!("Sending LIG(100)...");
            device.write(&lig_packet(100))?;
            println!("Sending CLE(all)...");
            device.write(&clear_all_packet())?;
            println!("Sending STP...");
            device.write(&stp_packet())?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_logo_raw(&device, image_path, 800, 480, true)?;
        }
        "connect-jpeg-800" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_logo_jpeg(&device, image_path, 800, 480)?;
        }
        "connect-jpeg-854" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_logo_jpeg(&device, image_path, 854, 480)?;
        }
        "jpeg-len-800" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;

            let image = image::open(image_path)?;
            let format = ImageFormat {
                mode: ImageMode::JPEG,
                size: (800, 480),
                rotation: ImageRotation::Rot0,
                mirror: ImageMirroring::None,
            };
            let data = convert_image_with_format(format, image)?;

            println!("Sending LOG(size={len})...", len = data.len());
            device.write(&log_packet_with_size(data.len() as u32))?;
            println!("Sending JPEG data ({size} bytes)...", size = data.len());
            send_data(&device, &data)?;
            println!("Sending STP...");
            device.write(&stp_packet())?;
        }
        "pattern-rgb-800" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            run_pattern(&device, false)?;
        }
        "pattern-bgr-800" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            run_pattern(&device, true)?;
        }
        "jpeg-padded-800" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_padded_jpeg(&device, image_path, 800, 480)?;
        }
        "jpeg-padded-854" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_padded_jpeg(&device, image_path, 854, 480)?;
        }
        "pattern-565" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            run_pattern_565(&device)?;
        }
        "pattern-f02" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            run_pattern_flag(&device, 0x02)?;
        }
        "pattern-f03" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            run_pattern_flag(&device, 0x03)?;
        }
        "pattern-f00" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            run_pattern_flag(&device, 0x00)?;
        }
        "official-pattern-bgr" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_official_logo_pattern(&device, true)?;
        }
        "official-pattern-rgb" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_official_logo_pattern(&device, false)?;
        }
        "official-photo-bgr" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_official_logo(&device, image_path, 800, 480, true)?;
        }
        "official-photo-rgb" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_official_logo(&device, image_path, 800, 480, false)?;
        }
        "official-fast-bgr" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_official_logo_pattern_fast(&device, true)?;
        }
        "official-fast-rgb" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_official_logo_pattern_fast(&device, false)?;
        }
        "v3-pattern-bgr" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_logo_pattern(&device, true)?;
        }
        "v3-pattern-rgb" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_logo_pattern(&device, false)?;
        }
        "v3-photo-bgr" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_logo(&device, image_path, 800, 480, true)?;
        }
        "v3-photo-rgb" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_logo(&device, image_path, 800, 480, false)?;
        }
        "v3-pattern-565" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_logo_pattern_565(&device)?;
        }
        "v3-jpeg-padded" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_jpeg_padded(&device, image_path, 800, 480)?;
        }
        "v3-ff" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            println!("Sending all-0xFF region (should render WHITE if raw format works)...");
            let data = vec![0xFFu8; 800 * 480 * 3];
            send_v3_logo_bytes(&device, &data)?;
        }
        "v3-hdr-le" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_jpeg_with_header(&device, image_path, true)?;
        }
        "v3-hdr-be" => {
            init(&device)?;
            println!("Sending CONNECT (keep alive)...");
            device.write(&connect_packet())?;
            send_v3_jpeg_with_header(&device, image_path, false)?;
        }
        "hs-jpeg-len" => {
            send_handshake_logo(&device, image_path, false)?;
        }
        "hs-jpeg-pad" => {
            send_handshake_logo(&device, image_path, true)?;
        }
        "hs-pattern-bgr" => {
            send_handshake_logo_pattern(&device, true)?;
        }
        "hs-pace-jpeg-len" => {
            send_paced_logo(&device, image_path, false)?;
        }
        "hs-pace-jpeg-pad" => {
            send_paced_logo(&device, image_path, true)?;
        }
        "hs-512-jpeg-pad" => {
            send_paced_logo_512(&device, image_path, true)?;
        }
        "hs-512-jpeg-len" => {
            send_paced_logo_512(&device, image_path, false)?;
        }
        "hs-512-pattern-bgr" => {
            send_paced_pattern_512(&device, true)?;
        }
        // --- ULE-finish strategies (finish command discovered in the official
        // app's libSDLibrary: SDDevice::getUploadFinishedCommand = CRT\0\0ULE).
        // Every previous attempt ended with STP, which the bootloader likely
        // ignores — the logo is only committed on ULE. ---
        "ule-jpeg" => {
            let jpeg = jpeg_800x480(image_path)?;
            let total = 800 * 480 * 3;
            let mut data = vec![0u8; total];
            data[..jpeg.len()].copy_from_slice(&jpeg);
            println!(
                "Sending {jpeg_len} JPEG bytes zero-padded to {total} bytes...",
                jpeg_len = jpeg.len()
            );
            send_ule_logo(&device, &data, 0x01)?;
        }
        "ule-jpeg-f00" => {
            let jpeg = jpeg_800x480(image_path)?;
            let total = 800 * 480 * 3;
            let mut data = vec![0u8; total];
            data[..jpeg.len()].copy_from_slice(&jpeg);
            send_ule_logo(&device, &data, 0x00)?;
        }
        "ule-jpeg-f02" => {
            let jpeg = jpeg_800x480(image_path)?;
            let total = 800 * 480 * 3;
            let mut data = vec![0u8; total];
            data[..jpeg.len()].copy_from_slice(&jpeg);
            send_ule_logo(&device, &data, 0x02)?;
        }
        "ule-bgr" => {
            let mut raw = Vec::with_capacity(800 * 480 * 3);
            for x in 0..800u32 {
                let (r, g, b) = if x < 400 { (255, 0, 0) } else { (0, 0, 255) };
                for _ in 0..480u32 {
                    raw.extend_from_slice(&[b, g, r]);
                }
            }
            println!("Sending raw BGR pattern (left red / right blue)...");
            send_ule_logo(&device, &raw, 0x01)?;
        }
        "ule-ff" => {
            println!("Sending all-0xFF region (white if raw renders)...");
            send_ule_logo(&device, &vec![0xFFu8; 800 * 480 * 3], 0x01)?;
        }
        "ule-jpeg-q100" => {
            let jpeg = jpeg_800x480_q100(image_path)?;
            let total = 800 * 480 * 3;
            let mut data = vec![0u8; total];
            data[..jpeg.len()].copy_from_slice(&jpeg);
            println!(
                "Sending {jpeg_len} q100 JPEG bytes zero-padded to {total} bytes...",
                jpeg_len = jpeg.len()
            );
            send_ule_logo(&device, &data, 0x01)?;
        }
        "ule-jpeg-q100-f02" => {
            let jpeg = jpeg_800x480_q100(image_path)?;
            let total = 800 * 480 * 3;
            let mut data = vec![0u8; total];
            data[..jpeg.len()].copy_from_slice(&jpeg);
            println!(
                "Sending {jpeg_len} q100 JPEG bytes zero-padded to {total} bytes (flag 0x02)...",
                jpeg_len = jpeg.len()
            );
            send_ule_logo(&device, &data, 0x02)?;
        }
        // --- The exact flow captured from the official app (USBPcap):
        // LOG announce (size = EXACT JPEG byte count, flag 0x01) -> JPEG in
        // 1024-byte chunks -> wait for ACK -> STP. The JPEG is the 854x480
        // screen image ROTATED 90° counter-clockwise (480x854). The firmware
        // rejects payloads above 0x7f800 bytes (510 KiB), so quality is
        // stepped down until the JPEG fits.
        "official-log" => {
            let jpeg = encode_official_logo(image_path)?;
            send_official_logo_exact(&device, &jpeg)?;
        }
        "encode" => {
            let _ = encode_official_logo(image_path)?;
        }
        "official-log-q90" => {
            let jpeg = encode_official_logo_at(image_path, 90)?;
            println!("JPEG: 480x854 q90 = {} bytes", jpeg.len());
            send_official_logo_exact(&device, &jpeg)?;
        }
        other => {
            eprintln!("Unknown strategy: {other}");
            return Err(usage().into());
        }
    }

    println!();
    println!("Write sequence sent. Dumping device responses...");
    dump_input(&device);

    println!();
    println!("Now unplug/replug the device and check the boot logo.");

    Ok(())
}

fn usage() -> String {
    "Usage: boot_logo_lab <replica|jpeg-stp-last|raw-bgr-854|raw-rgb-854|raw-bgr-800|raw-rgb-800|no-init-bgr-800|connect-bgr-800|official-bgr-800|connect-jpeg-800|connect-jpeg-854|jpeg-len-800|pattern-rgb-800|pattern-bgr-800|jpeg-padded-800|jpeg-padded-854|pattern-565|pattern-f02|pattern-f03|pattern-f00|official-pattern-bgr|official-pattern-rgb|official-photo-bgr|official-photo-rgb|official-fast-bgr|official-fast-rgb|v3-pattern-bgr|v3-pattern-rgb|v3-photo-bgr|v3-photo-rgb|v3-pattern-565|v3-jpeg-padded|v3-ff|v3-hdr-le|v3-hdr-be|hs-jpeg-len|hs-jpeg-pad|hs-pattern-bgr|hs-pace-jpeg-len|hs-pace-jpeg-pad|hs-512-jpeg-pad|hs-512-jpeg-len|hs-512-pattern-bgr|ule-jpeg|ule-jpeg-f00|ule-jpeg-f02|ule-bgr|ule-ff|ule-jpeg-q100|ule-jpeg-q100-f02> <image>"
        .to_string()
}

fn open_device() -> Result<HidDevice, Box<dyn Error>> {
    let api = HidApi::new()?;
    let device_info = api
        .device_list()
        .find(|info| info.vendor_id() == VID && info.product_id() == PID)
        .cloned()
        .ok_or_else(|| format!("No device with VID {VID:#06x} PID {PID:#06x} found"))?;

    Ok(device_info.open_device(&api)?)
}

/// Sends the `DIS` init command, like `Ajazz::initialize`
fn init(device: &HidDevice) -> Result<(), Box<dyn Error>> {
    println!("Sending DIS (init)...");
    device.write(&packet(&[0x44, 0x49, 0x53, 0x00, 0x00]))?;
    Ok(())
}

/// Builds a 513-byte v1 command packet: header + command, zero padded
fn packet(command: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(REPORT_LEN);
    buf.extend_from_slice(&REQUEST_HEADER);
    buf.extend_from_slice(command);
    buf.resize(REPORT_LEN, 0x00);
    buf
}

/// `LOG` packet: "LOG\0" + big-endian raw image size (3 bytes) + 0x01 flag
fn log_packet(width: u32, height: u32) -> Vec<u8> {
    log_packet_with_size(width * height * 3)
}

/// `LOG` packet with an arbitrary announced byte count
fn log_packet_with_size(size: u32) -> Vec<u8> {
    log_packet_flag(size, 0x01)
}

/// `LOG` packet with arbitrary size and flag byte
fn log_packet_flag(size: u32, flag: u8) -> Vec<u8> {
    let bytes = size.to_be_bytes();
    packet(&[0x4c, 0x4f, 0x47, 0x00, bytes[1], bytes[2], bytes[3], flag])
}

/// `STP` (flush/refresh) packet
fn stp_packet() -> Vec<u8> {
    packet(&[0x53, 0x54, 0x50])
}

/// `LIG` (brightness) packet
fn lig_packet(percent: u8) -> Vec<u8> {
    packet(&[0x4c, 0x49, 0x47, 0x00, 0x00, percent])
}

/// `CLE` (clear all icons) packet
fn clear_all_packet() -> Vec<u8> {
    packet(&[0x43, 0x4c, 0x45, 0x00, 0x00, 0x00, 0xff])
}

/// `CONNECT` (keep alive) packet, as sent periodically by the official software
fn connect_packet() -> Vec<u8> {
    packet(&[0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54])
}

/// Sends payload in 512-byte reports, each prefixed with the 0x00 report id
fn send_data(device: &HidDevice, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut sent = 0usize;
    for chunk in data.chunks(512) {
        let mut report = Vec::with_capacity(REPORT_LEN);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(REPORT_LEN, 0x00);
        device.write(&report)?;
        sent += chunk.len();
    }
    println!("  sent {sent} bytes in {} reports", data.chunks(512).len());
    Ok(())
}

/// Produces the JPEG data exactly like `Ajazz::set_logo_image` does
fn jpeg_data(image_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let image = image::open(image_path)?;
    Ok(convert_image_with_format(
        Kind::MadDogGk150W.logo_image_format(),
        image,
    )?)
}

/// Official GK150W boot-logo JPEG with the firmware's 0x7f800-byte limit
/// enforced: quality is stepped down from 100 by 10 until the payload fits.
fn encode_official_logo(image_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut quality = 100u8;
    loop {
        let jpeg = encode_official_logo_at(image_path, quality)?;
        println!("JPEG: 480x854 q{quality} = {} bytes", jpeg.len());
        if jpeg.len() <= 0x7f800 || quality <= 60 {
            return Ok(jpeg);
        }
        quality -= 10;
    }
}

/// Encodes the official GK150W boot-logo JPEG at a fixed quality.
fn encode_official_logo_at(image_path: &str, quality: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let image = image::open(image_path)?
        .resize_exact(854, 480, FilterType::Triangle)
        .rotate270()
        .into_rgb8();
    let mut jpeg = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut jpeg, quality);
    encoder.encode(&image, 480, 854, image::ColorType::Rgb8.into())?;
    Ok(jpeg)
}

/// Sends LOG + raw RGB/BGR data (Mirabox 293 style) + STP
fn send_logo_raw(
    device: &HidDevice,
    image_path: &str,
    width: u32,
    height: u32,
    bgr: bool,
) -> Result<(), Box<dyn Error>> {
    let image = image::open(image_path)?;
    let image = image
        .resize_exact(width, height, FilterType::Triangle)
        .to_rgb8();

    let mut raw = Vec::with_capacity((width * height * 3) as usize);
    for pixel in image.pixels() {
        if bgr {
            raw.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
        } else {
            raw.extend_from_slice(&[pixel[0], pixel[1], pixel[2]]);
        }
    }

    send_raw_bytes(device, width, height, &raw)
}

/// Sends LOG + raw bytes + STP
fn send_raw_bytes(
    device: &HidDevice,
    width: u32,
    height: u32,
    raw: &[u8],
) -> Result<(), Box<dyn Error>> {
    println!("Sending LOG({width}x{height}x3)...");
    device.write(&log_packet(width, height))?;

    println!("Sending raw data...");
    send_data(device, raw)?;

    println!("Sending STP...");
    device.write(&stp_packet())?;

    Ok(())
}

/// Sends a diagnostic pattern: left half pure red, right half pure blue
fn run_pattern(device: &HidDevice, bgr: bool) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 3) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 { (255, 0, 0) } else { (0, 0, 255) };
        for _ in 0..H {
            if bgr {
                raw.extend_from_slice(&[b, g, r]);
            } else {
                raw.extend_from_slice(&[r, g, b]);
            }
        }
    }

    println!(
        "Sending pattern (left red / right blue, {} order)...",
        if bgr { "BGR" } else { "RGB" }
    );
    send_raw_bytes(device, W, H, &raw)
}

/// Sends LOG + JPEG data (AKP153 style, but preceded by CONNECT) + STP
fn send_logo_jpeg(
    device: &HidDevice,
    image_path: &str,
    width: u32,
    height: u32,
) -> Result<(), Box<dyn Error>> {
    println!("Sending LOG({width}x{height}x3)...");
    device.write(&log_packet(width, height))?;

    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (width as usize, height as usize),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    let data = convert_image_with_format(format, image)?;

    println!("Sending JPEG data ({size} bytes)...", size = data.len());
    send_data(device, &data)?;

    println!("Sending STP...");
    device.write(&stp_packet())?;

    Ok(())
}

/// Sends LOG + JPEG data padded with zeros to the full raw screen size + STP
fn send_padded_jpeg(
    device: &HidDevice,
    image_path: &str,
    width: u32,
    height: u32,
) -> Result<(), Box<dyn Error>> {
    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (width as usize, height as usize),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    let jpeg = convert_image_with_format(format, image)?;

    let total = (width * height * 3) as usize;
    let mut data = vec![0u8; total];
    data[..jpeg.len()].copy_from_slice(&jpeg);

    println!("Sending LOG({width}x{height}x3)...");
    device.write(&log_packet(width, height))?;
    println!(
        "Sending {jpeg_len} JPEG bytes padded with zeros to {total} bytes...",
        jpeg_len = jpeg.len()
    );
    send_data(device, &data)?;
    println!("Sending STP...");
    device.write(&stp_packet())?;

    Ok(())
}

/// Sends a RGB565 diagnostic pattern: left half pure red, right half pure blue
fn run_pattern_565(device: &HidDevice) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 2) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 {
            (255u16, 0u16, 0u16)
        } else {
            (0u16, 0u16, 255u16)
        };
        let value: u16 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
        for _ in 0..H {
            raw.extend_from_slice(&value.to_le_bytes());
        }
    }

    println!("Sending LOG({W}x{H}x2)...");
    device.write(&log_packet_with_size(W * H * 2))?;
    println!("Sending RGB565 pattern (left red / right blue)...");
    send_data(device, &raw)?;
    println!("Sending STP...");
    device.write(&stp_packet())?;

    Ok(())
}

/// Sends a raw RGB red/blue pattern with a custom LOG flag byte
fn run_pattern_flag(device: &HidDevice, flag: u8) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 3) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 { (255, 0, 0) } else { (0, 0, 255) };
        for _ in 0..H {
            raw.extend_from_slice(&[r, g, b]);
        }
    }

    println!("Sending LOG({W}x{H}x3, flag={flag:#04x})...");
    device.write(&log_packet_flag(W * H * 3, flag))?;
    println!("Sending raw RGB pattern (left red / right blue)...");
    send_data(device, &raw)?;
    println!("Sending STP...");
    device.write(&stp_packet())?;

    Ok(())
}

/// Exact replica of the official `setBackgroundBitmap` flow, extracted from
/// disassembly of the StreamDock libtransport.so:
///   LOG announce -> wait for response -> per-chunk send + wait -> final wait.
/// No STP at the end.
fn send_official_logo(
    device: &HidDevice,
    image_path: &str,
    width: u32,
    height: u32,
    bgr: bool,
) -> Result<(), Box<dyn Error>> {
    let image = image::open(image_path)?;
    let image = image
        .resize_exact(width, height, FilterType::Triangle)
        .to_rgb8();

    let mut raw = Vec::with_capacity((width * height * 3) as usize);
    for pixel in image.pixels() {
        if bgr {
            raw.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
        } else {
            raw.extend_from_slice(&[pixel[0], pixel[1], pixel[2]]);
        }
    }

    send_official_logo_bytes(device, width, height, &raw)
}

/// Same, but with the diagnostic red/blue pattern instead of a photo
fn send_official_logo_pattern(device: &HidDevice, bgr: bool) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 3) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 { (255, 0, 0) } else { (0, 0, 255) };
        for _ in 0..H {
            if bgr {
                raw.extend_from_slice(&[b, g, r]);
            } else {
                raw.extend_from_slice(&[r, g, b]);
            }
        }
    }

    println!(
        "Sending pattern (left red / right blue, {} order)...",
        if bgr { "BGR" } else { "RGB" }
    );
    send_official_logo_bytes(device, W, H, &raw)
}

/// Official flow WITHOUT the final STP and without per-chunk waits:
/// announce -> blast all chunks -> wait for the final ACKs. Fast.
fn send_official_logo_pattern_fast(
    device: &HidDevice,
    bgr: bool,
) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 3) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 { (255, 0, 0) } else { (0, 0, 255) };
        for _ in 0..H {
            if bgr {
                raw.extend_from_slice(&[b, g, r]);
            } else {
                raw.extend_from_slice(&[r, g, b]);
            }
        }
    }

    println!(
        "Sending pattern (left red / right blue, {} order, no STP)...",
        if bgr { "BGR" } else { "RGB" }
    );

    let bytes = (raw.len() as u32).to_be_bytes();
    let mut announce = Vec::with_capacity(REPORT_LEN);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&bytes);
    announce.push(0x01);
    announce.resize(REPORT_LEN, 0x00);

    println!("Sending LOG announce...");
    device.write(&announce)?;

    println!("Sending data chunks (no STP)...");
    send_data(device, &raw)?;

    println!("Final ACK wait...");
    dump_input(device);

    println!("Done. Unplug/replug the device and check the boot logo.");

    Ok(())
}

fn send_official_logo_bytes(
    device: &HidDevice,
    width: u32,
    height: u32,
    raw: &[u8],
) -> Result<(), Box<dyn Error>> {
    let size = raw.len() as u32;
    let bytes = size.to_be_bytes();

    // LOG announce: [0x00] "CRT\0\0" "LOG" size32BE 0x01
    let mut announce = Vec::with_capacity(REPORT_LEN);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&bytes);
    announce.push(0x01);
    announce.resize(REPORT_LEN, 0x00);

    println!("Sending LOG announce (size={size})...");
    device.write(&announce)?;
    wait_ack(device, true)?;

    println!(
        "Sending {chunk_count} data chunks, waiting for ACK after each...",
        chunk_count = raw.chunks(512).len()
    );
    let mut acks = 0u32;
    for chunk in raw.chunks(512) {
        let mut report = Vec::with_capacity(REPORT_LEN);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(REPORT_LEN, 0x00);
        device.write(&report)?;
        if wait_ack(device, false)? {
            acks += 1;
        }
    }
    println!("Got {acks} ACKs during data transfer.");

    println!("Final wait...");
    wait_ack(device, true)?;

    println!("Official flow complete.");

    let _ = (width, height);
    Ok(())
}

/// Reads one response from the device. Returns true if it was an ACK.
/// Short timeout (500 ms) so the whole sequence never drags on.
fn wait_ack(device: &HidDevice, verbose: bool) -> Result<bool, Box<dyn Error>> {
    device.set_blocking_mode(true)?;
    let mut buf = vec![0u8; 512];
    match device.read_timeout(&mut buf, 500) {
        Ok(0) => {
            if verbose {
                println!("  (timeout — no response)");
            }
            Ok(false)
        }
        Ok(n) => {
            let is_ack = n >= 7 && buf[..7] == [0x41, 0x43, 0x4b, 0x00, 0x00, 0x4f, 0x4b];
            if verbose {
                println!(
                    "  response ({n} bytes): {:02x?}{}",
                    &buf[..n.min(16)],
                    if is_ack { "  ACK" } else { "" }
                );
            }
            Ok(is_ack)
        }
        Err(e) => {
            if verbose {
                println!("  read error: {e}");
            }
            Ok(false)
        }
    }
}

/// V3-class write: the GK150W's OUTPUT report is 1024 bytes (from the report
/// descriptor), so the announce and every data chunk must be 1025-byte reports
/// (0x00 report id + 1024 bytes of payload). Using 512-byte chunks left every
/// other 512 bytes zeroed in the stream — corrupt image, black boot screen.
fn send_v3_logo(
    device: &HidDevice,
    image_path: &str,
    width: u32,
    height: u32,
    bgr: bool,
) -> Result<(), Box<dyn Error>> {
    let image = image::open(image_path)?;
    let image = image
        .resize_exact(width, height, FilterType::Triangle)
        .to_rgb8();

    let mut raw = Vec::with_capacity((width * height * 3) as usize);
    for pixel in image.pixels() {
        if bgr {
            raw.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
        } else {
            raw.extend_from_slice(&[pixel[0], pixel[1], pixel[2]]);
        }
    }

    send_v3_logo_bytes(device, &raw)
}

/// Same, with the red/blue diagnostic pattern
fn send_v3_logo_pattern(device: &HidDevice, bgr: bool) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 3) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 { (255, 0, 0) } else { (0, 0, 255) };
        for _ in 0..H {
            if bgr {
                raw.extend_from_slice(&[b, g, r]);
            } else {
                raw.extend_from_slice(&[r, g, b]);
            }
        }
    }

    println!(
        "Sending pattern (left red / right blue, {} order)...",
        if bgr { "BGR" } else { "RGB" }
    );
    send_v3_logo_bytes(device, &raw)
}

fn send_v3_logo_bytes(device: &HidDevice, raw: &[u8]) -> Result<(), Box<dyn Error>> {
    const REPORT_LEN_V3: usize = 1025;

    let size = raw.len() as u32;
    let bytes = size.to_be_bytes();

    // LOG announce: [0x00] "CRT\0\0" "LOG" size32BE 0x01, padded to 1025
    let mut announce = Vec::with_capacity(REPORT_LEN_V3);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&bytes);
    announce.push(0x01);
    announce.resize(REPORT_LEN_V3, 0x00);

    println!("Sending LOG announce (size={size}) as a 1025-byte report...");
    device.write(&announce)?;

    println!(
        "Sending {chunk_count} chunks of 1024 bytes...",
        chunk_count = raw.chunks(1024).len()
    );
    for chunk in raw.chunks(1024) {
        let mut report = Vec::with_capacity(REPORT_LEN_V3);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(REPORT_LEN_V3, 0x00);
        device.write(&report)?;
    }

    println!("Final ACK wait...");
    dump_input(device);

    println!("Done. Unplug/replug the device and check the boot logo.");

    Ok(())
}

/// RGB565 pattern (little-endian), 800x480x2 = 768000 bytes, 1024-byte chunks
fn send_v3_logo_pattern_565(device: &HidDevice) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 2) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 {
            (255u16, 0u16, 0u16)
        } else {
            (0u16, 0u16, 255u16)
        };
        let value: u16 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
        for _ in 0..H {
            raw.extend_from_slice(&value.to_le_bytes());
        }
    }

    println!("Sending RGB565 pattern (left red / right blue)...");
    send_v3_logo_bytes(device, &raw)
}

/// JPEG (800x480) zero-padded to the full raw size, 1024-byte chunks
fn send_v3_jpeg_padded(
    device: &HidDevice,
    image_path: &str,
    width: u32,
    height: u32,
) -> Result<(), Box<dyn Error>> {
    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (width as usize, height as usize),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    let jpeg = convert_image_with_format(format, image)?;

    let total = (width * height * 3) as usize;
    let mut data = vec![0u8; total];
    data[..jpeg.len()].copy_from_slice(&jpeg);

    println!(
        "Sending {jpeg_len} JPEG bytes padded with zeros to {total} bytes (1024-byte chunks)...",
        jpeg_len = jpeg.len()
    );
    send_v3_logo_bytes(device, &data)
}

/// JPEG with a 4-byte length header at the start of the region (LE or BE),
/// zero-padded to the full raw size.
fn send_v3_jpeg_with_header(
    device: &HidDevice,
    image_path: &str,
    little_endian: bool,
) -> Result<(), Box<dyn Error>> {
    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (800, 480),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    let jpeg = convert_image_with_format(format, image)?;

    let total = 800 * 480 * 3;
    let mut data = vec![0u8; total];
    let len_bytes = if little_endian {
        (jpeg.len() as u32).to_le_bytes()
    } else {
        (jpeg.len() as u32).to_be_bytes()
    };
    data[..4].copy_from_slice(&len_bytes);
    data[4..4 + jpeg.len()].copy_from_slice(&jpeg);

    println!(
        "Sending [{endian} size header {jpeg_len}] + JPEG, padded to {total} bytes...",
        endian = if little_endian { "LE" } else { "BE" },
        jpeg_len = jpeg.len()
    );
    send_v3_logo_bytes(device, &data)
}

/// Official logo flow with the "HAN" handshake, extracted from the Mad Dog
/// app's libSDLibrary: HAN -> LOG announce -> JPEG data -> STP (finish).
fn send_handshake_logo(
    device: &HidDevice,
    image_path: &str,
    pad_to_raw: bool,
) -> Result<(), Box<dyn Error>> {
    println!("Sending HAN handshake...");
    device.write(&han_packet())?;

    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (800, 480),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    let jpeg = convert_image_with_format(format, image)?;

    let (announced, data) = if pad_to_raw {
        let total = 800 * 480 * 3;
        let mut data = vec![0u8; total];
        data[..jpeg.len()].copy_from_slice(&jpeg);
        (total as u32, data)
    } else {
        (jpeg.len() as u32, jpeg)
    };

    println!(
        "Sending LOG announce (size={announced}, JPEG={jpeg_len} bytes)...",
        jpeg_len = data.len()
    );
    let mut announce = Vec::with_capacity(1025);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&announced.to_be_bytes());
    announce.push(0x01);
    announce.resize(1025, 0x00);
    device.write(&announce)?;

    println!("Sending data (1024-byte chunks)...");
    for chunk in data.chunks(1024) {
        let mut report = Vec::with_capacity(1025);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(1025, 0x00);
        device.write(&report)?;
    }

    println!("Sending STP (finish)...");
    device.write(&v3_packet(b"STP"))?;

    println!("Final ACK wait...");
    dump_input(device);

    println!("Done. Unplug/replug the device and check the boot logo.");

    Ok(())
}

/// Same flow with the red/blue pattern in raw BGR (in case the handshake
/// makes raw format work after all).
fn send_handshake_logo_pattern(device: &HidDevice, bgr: bool) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 3) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 { (255, 0, 0) } else { (0, 0, 255) };
        for _ in 0..H {
            if bgr {
                raw.extend_from_slice(&[b, g, r]);
            } else {
                raw.extend_from_slice(&[r, g, b]);
            }
        }
    }

    println!("Sending HAN handshake...");
    device.write(&han_packet())?;

    println!("Sending LOG announce (size={})...", raw.len());
    let mut announce = Vec::with_capacity(1025);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    announce.push(0x01);
    announce.resize(1025, 0x00);
    device.write(&announce)?;

    println!(
        "Sending raw {} pattern (1024-byte chunks)...",
        if bgr { "BGR" } else { "RGB" }
    );
    for chunk in raw.chunks(1024) {
        let mut report = Vec::with_capacity(1025);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(1025, 0x00);
        device.write(&report)?;
    }

    println!("Sending STP (finish)...");
    device.write(&v3_packet(b"STP"))?;

    println!("Final ACK wait...");
    dump_input(device);

    println!("Done. Unplug/replug the device and check the boot logo.");

    Ok(())
}

/// Builds a 1025-byte V3 report: [0x00 report id] + command + zero padding
fn v3_packet(command: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1025);
    buf.push(0x00);
    buf.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    buf.extend_from_slice(command);
    buf.resize(1025, 0x00);
    buf
}

/// The official handshake packet: [0x00][H][A][N] — NO "CRT\0\0" prefix!
fn han_packet() -> Vec<u8> {
    let mut buf = Vec::with_capacity(1025);
    buf.push(0x00);
    buf.extend_from_slice(b"HAN");
    buf.resize(1025, 0x00);
    buf
}

/// Official flow with per-chunk ACK pacing:
///   HAN -> LOG announce -> [chunk -> wait ACK] * N -> STP
fn send_paced_logo(
    device: &HidDevice,
    image_path: &str,
    pad_to_raw: bool,
) -> Result<(), Box<dyn Error>> {
    println!("Sending HAN handshake...");
    device.write(&han_packet())?;

    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (800, 480),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    let jpeg = convert_image_with_format(format, image)?;

    let (announced, data) = if pad_to_raw {
        let total = 800 * 480 * 3;
        let mut data = vec![0u8; total];
        data[..jpeg.len()].copy_from_slice(&jpeg);
        (total as u32, data)
    } else {
        (jpeg.len() as u32, jpeg)
    };

    println!(
        "Sending LOG announce (size={announced}, JPEG={jpeg_len} bytes)...",
        jpeg_len = data.len()
    );
    println!(
        "Sending LOG announce (size={announced}, JPEG={jpeg_len} bytes)...",
        jpeg_len = data.len()
    );
    let mut announce = Vec::with_capacity(1025);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&announced.to_be_bytes());
    announce.push(0x01);
    announce.resize(1025, 0x00);
    device.write(&announce)?;

    // Read the announce ACK before sending data — the firmware may ignore
    // the data stream until the host consumes it.
    println!("Waiting for announce ACK...");
    {
        let mut buf = vec![0u8; 512];
        match device.read_timeout(&mut buf, 2000) {
            Ok(0) => println!("  (timeout — no announce ACK)"),
            Ok(n) => println!(
                "  announce response ({n} bytes): {:02x?}",
                &buf[..n.min(16)]
            ),
            Err(e) => println!("  read error: {e}"),
        }
    }

    println!(
        "Sending {chunk_count} chunks, waiting for ACK after each...",
        chunk_count = data.chunks(1024).len()
    );
    let mut acks = 0u32;
    let mut silent_streak = 0u32;
    for (i, chunk) in data.chunks(1024).enumerate() {
        let mut report = Vec::with_capacity(1025);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(1025, 0x00);
        device.write(&report)?;

        // Wait for the device reply (flow control), 300ms timeout
        let mut buf = vec![0u8; 512];
        match device.read_timeout(&mut buf, 300) {
            Ok(n) if n >= 7 && buf[..7] == [0x41, 0x43, 0x4b, 0x00, 0x00, 0x4f, 0x4b] => {
                acks += 1;
                silent_streak = 0;
            }
            Ok(0) => {
                silent_streak += 1;
                if i < 3 || i % 200 == 0 {
                    println!("  chunk {i}: timeout (no reply)");
                }
                if silent_streak >= 5 {
                    println!("  (no replies — blasting the rest without waiting)");
                    for chunk in data.chunks(1024).skip(i + 1) {
                        let mut report = Vec::with_capacity(1025);
                        report.push(0x00);
                        report.extend_from_slice(chunk);
                        report.resize(1025, 0x00);
                        device.write(&report)?;
                    }
                    break;
                }
            }
            Ok(n) => {
                silent_streak += 1;
                if i < 3 {
                    println!("  chunk {i}: got {n} bytes: {:02x?}", &buf[..n.min(16)]);
                }
            }
            Err(e) => {
                silent_streak += 1;
                if i < 3 {
                    println!("  chunk {i}: read error: {e}");
                }
            }
        }
    }
    println!("Got {acks} ACKs during data transfer.");

    println!("Sending STP (finish)...");
    device.write(&v3_packet(b"STP"))?;

    println!("Final ACK wait...");
    dump_input(device);

    println!("Done. Unplug/replug the device and check the boot logo.");

    Ok(())
}

/// Variant with 512-byte data chunks (513-byte reports) after a 1025-byte
/// announce — matches the ACK pattern we observed (2 ACKs = announce + data).
fn send_paced_logo_512(
    device: &HidDevice,
    image_path: &str,
    pad_to_raw: bool,
) -> Result<(), Box<dyn Error>> {
    println!("Sending HAN handshake...");
    device.write(&han_packet())?;

    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (800, 480),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    let jpeg = convert_image_with_format(format, image)?;

    let (announced, data) = if pad_to_raw {
        let total = 800 * 480 * 3;
        let mut data = vec![0u8; total];
        data[..jpeg.len()].copy_from_slice(&jpeg);
        (total as u32, data)
    } else {
        (jpeg.len() as u32, jpeg)
    };

    // 1025-byte announce
    let mut announce = Vec::with_capacity(1025);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&announced.to_be_bytes());
    announce.push(0x01);
    announce.resize(1025, 0x00);

    println!("Sending LOG announce (size={announced})...");
    device.write(&announce)?;

    println!("Waiting for announce ACK...");
    {
        let mut buf = vec![0u8; 512];
        match device.read_timeout(&mut buf, 2000) {
            Ok(0) => println!("  (timeout)"),
            Ok(n) => println!(
                "  announce response ({n} bytes): {:02x?}",
                &buf[..n.min(16)]
            ),
            Err(e) => println!("  read error: {e}"),
        }
    }

    println!("Sending data in 512-byte chunks (513-byte reports, no per-chunk wait)...");
    for chunk in data.chunks(512) {
        let mut report = Vec::with_capacity(513);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(513, 0x00);
        device.write(&report)?;
    }
    println!("Data sent.");

    println!("Sending STP (finish)...");
    device.write(&v3_packet(b"STP"))?;

    println!("Final ACK wait...");
    dump_input(device);

    println!("Done. Unplug/replug the device and check the boot logo.");

    Ok(())
}

/// Converts an image to the 800x480 JPEG payload used for the boot logo
fn jpeg_800x480(image_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let image = image::open(image_path)?;
    let format = ImageFormat {
        mode: ImageMode::JPEG,
        size: (800, 480),
        rotation: ImageRotation::Rot0,
        mirror: ImageMirroring::None,
    };
    Ok(convert_image_with_format(format, image)?)
}

/// Converts to an 800x480 JPEG at **quality 100** — the official app encodes
/// the boot logo with `QImageToQByteArray(image, "JPG", 100, ...)`.
fn jpeg_800x480_q100(image_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let image = image::open(image_path)?
        .resize_exact(800, 480, FilterType::Triangle)
        .into_rgb8();
    let mut buf = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut buf, 100);
    encoder.encode(&image, 800, 480, image::ColorType::Rgb8.into())?;
    Ok(buf)
}

/// `CRT\0\0ULE` — the official upload-finish command.
///
/// Found in the Mad Dog app's libSDLibrary (`SDDevice::getUploadFinishedCommand`):
/// bytes 0x43 0x52 0x54 0x00 0x00 0x55 0x4C 0x45. Every earlier lab strategy
/// finished with `STP`, which the bootloader apparently ignores — the logo is
/// committed to flash only after `ULE`.
fn ule_packet() -> Vec<u8> {
    v3_packet(b"ULE")
}

/// Official V3 logo-upload flow reconstructed from libSDLibrary:
///   HAN handshake -> LOG announce -> data -> **ULE** finish.
fn send_ule_logo(device: &HidDevice, data: &[u8], flag: u8) -> Result<(), Box<dyn Error>> {
    println!("Sending HAN handshake...");
    device.write(&han_packet())?;

    let mut announce = Vec::with_capacity(1025);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&(data.len() as u32).to_be_bytes());
    announce.push(flag);
    announce.resize(1025, 0x00);
    println!(
        "Sending LOG announce (size={}, flag={flag:#04x})...",
        data.len()
    );
    device.write(&announce)?;

    println!("Waiting for announce ACK...");
    {
        let mut buf = vec![0u8; 512];
        match device.read_timeout(&mut buf, 2000) {
            Ok(0) => println!("  (timeout — no announce ACK)"),
            Ok(n) => println!(
                "  announce response ({n} bytes): {:02x?}",
                &buf[..n.min(16)]
            ),
            Err(e) => println!("  read error: {e}"),
        }
    }

    println!(
        "Sending data ({} bytes in {} 1024-byte chunks)...",
        data.len(),
        data.chunks(1024).len()
    );
    for chunk in data.chunks(1024) {
        let mut report = Vec::with_capacity(1025);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(1025, 0x00);
        device.write(&report)?;
    }

    println!("Sending ULE (finish)...");
    device.write(&ule_packet())?;

    println!("Final ACK wait...");
    dump_input(device);

    Ok(())
}

/// Same flow with the red/blue raw BGR pattern in 512-byte chunks
fn send_paced_pattern_512(device: &HidDevice, bgr: bool) -> Result<(), Box<dyn Error>> {
    const W: u32 = 800;
    const H: u32 = 480;

    let mut raw = Vec::with_capacity((W * H * 3) as usize);
    for x in 0..W {
        let (r, g, b) = if x < W / 2 { (255, 0, 0) } else { (0, 0, 255) };
        for _ in 0..H {
            if bgr {
                raw.extend_from_slice(&[b, g, r]);
            } else {
                raw.extend_from_slice(&[r, g, b]);
            }
        }
    }

    println!("Sending HAN handshake...");
    device.write(&han_packet())?;

    let mut announce = Vec::with_capacity(1025);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    announce.push(0x01);
    announce.resize(1025, 0x00);
    println!("Sending LOG announce (size={})...", raw.len());
    device.write(&announce)?;

    println!("Waiting for announce ACK...");
    {
        let mut buf = vec![0u8; 512];
        match device.read_timeout(&mut buf, 2000) {
            Ok(0) => println!("  (timeout)"),
            Ok(n) => println!(
                "  announce response ({n} bytes): {:02x?}",
                &buf[..n.min(16)]
            ),
            Err(e) => println!("  read error: {e}"),
        }
    }

    println!(
        "Sending raw {} pattern in 512-byte chunks...",
        if bgr { "BGR" } else { "RGB" }
    );
    println!(
        "Sending raw {} pattern in 512-byte chunks (no per-chunk wait)...",
        if bgr { "BGR" } else { "RGB" }
    );
    for chunk in raw.chunks(512) {
        let mut report = Vec::with_capacity(513);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(513, 0x00);
        device.write(&report)?;
    }
    println!("Data sent.");

    println!("Sending STP (finish)...");
    device.write(&v3_packet(b"STP"))?;

    println!("Final ACK wait...");
    dump_input(device);

    println!("Done. Unplug/replug the device and check the boot logo.");

    Ok(())
}

/// The exact boot-logo flow captured from the official Stream Panel app:
///   LOG announce (size = exact JPEG length, flag 0x01) -> JPEG data in
///   1024-byte chunks -> STP. No HAN handshake, no ULE.
fn send_official_logo_exact(device: &HidDevice, jpeg: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut announce = Vec::with_capacity(1025);
    announce.push(0x00);
    announce.extend_from_slice(&[0x43, 0x52, 0x54, 0x00, 0x00]);
    announce.extend_from_slice(&[0x4c, 0x4f, 0x47]);
    announce.extend_from_slice(&(jpeg.len() as u32).to_be_bytes());
    announce.push(0x01);
    announce.resize(1025, 0x00);
    println!("Sending LOG announce (size={})...", jpeg.len());
    device.write(&announce)?;

    // Official app waits ~3 s here while the device erases the logo flash
    // sector (it polls IN reports every few ms).
    println!("Waiting 3 s for flash erase...");
    std::thread::sleep(std::time::Duration::from_millis(3000));

    println!(
        "Sending JPEG data in {chunks} 1024-byte chunks...",
        chunks = jpeg.chunks(1024).len()
    );
    for chunk in jpeg.chunks(1024) {
        let mut report = Vec::with_capacity(1025);
        report.push(0x00);
        report.extend_from_slice(chunk);
        report.resize(1025, 0x00);
        device.write(&report)?;
    }

    // The device ACKs the data write (~3 s) BEFORE the host sends STP.
    println!("Waiting for device ACK (before STP)...");
    let acked = wait_for_ack(device, 6000);
    println!(
        "  ACK {}",
        if acked {
            "received"
        } else {
            "NOT received (timeout)"
        }
    );

    println!("Sending STP (finish)...");
    device.write(&v3_packet(b"STP"))?;

    println!("Post-STP input...");
    dump_input(device);

    Ok(())
}

/// Polls IN reports until an `ACK .. OK` arrives or `timeout_ms` elapses.
fn wait_for_ack(device: &HidDevice, timeout_ms: i32) -> bool {
    device.set_blocking_mode(true).expect("set blocking mode");
    let start = std::time::Instant::now();
    let mut buf = vec![0u8; 1024];
    while start.elapsed().as_millis() < timeout_ms as u128 {
        let remaining =
            timeout_ms - start.elapsed().as_millis().min(timeout_ms as u128) as i32;
        match device.read_timeout(&mut buf, remaining.min(100)) {
            Ok(0) => continue,
            Ok(n) => {
                println!("  (read {n} bytes: {:02x?}...)", &buf[..n.min(16)]);
                if buf[..n].starts_with(&[0x41, 0x43, 0x4b, 0x00, 0x00, 0x4f, 0x4b]) {
                    return true;
                }
            }
            Err(_) => continue,
        }
    }
    false
}

/// Reads and hex-dumps everything the device sends within ~2s windows
fn dump_input(device: &HidDevice) {
    device.set_blocking_mode(true).expect("set blocking mode");

    let mut buf = vec![0u8; 1024];
    let mut packets = 0usize;

    for _ in 0..6 {
        match device.read_timeout(&mut buf, 2000) {
            Ok(0) => {
                // hidapi returns Ok(0) on timeout — the device stayed silent
                println!("  (timeout — no response)");
                break;
            }
            Ok(n) => {
                packets += 1;
                let shown = n.min(64);
                println!("  packet #{packets} ({n} bytes):");
                print_hex(&buf[..shown]);
            }
            Err(_) => break,
        }
    }

    if packets == 0 {
        println!("  (no response — device stayed silent)");
    }
}

fn print_hex(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("    {i:04x}: {:<47}  {}", hex.join(" "), ascii);
    }
}
