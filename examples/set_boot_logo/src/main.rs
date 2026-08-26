use std::error::Error;

use ajazz_sdk::{
    convert_mad_dog_gk150w_logo, list_devices, new_hidapi, Ajazz, Kind,
    MAD_DOG_GK150W_LOGO_MAX_BYTES,
};
use hidapi::HidApi;
use image::{DynamicImage, Rgb, RgbImage};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().skip(1).any(|arg| arg == "--check") {
        return run_preflight_checks();
    }

    let image_path = args.get(1).ok_or_else(|| {
        "Usage: set_boot_logo <image_path>\n       set_boot_logo --check".to_string()
    })?;

    let hid = new_hidapi()?;
    let (kind, serial) = first_device(&hid)?;

    let image = image::open(image_path)?;

    // Diagnostics: prove that the payload really differs between input files.
    let payload = convert_mad_dog_gk150w_logo(image.clone())?;
    println!(
        "JPEG payload: {} bytes (device limit: {MAD_DOG_GK150W_LOGO_MAX_BYTES} bytes)",
        payload.len()
    );
    println!(
        "  first 16 bytes: {}",
        payload
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    println!("Setting boot logo image: {image_path}");

    let device = Ajazz::connect_with_retries(&hid, kind, &serial, 10)?;
    device.set_logo_image(image)?;

    println!("Boot logo image updated");

    Ok(())
}

/// Lists devices, picks the first one and prints it. Fails if nothing was found.
fn first_device(hid: &HidApi) -> Result<(Kind, String), Box<dyn Error>> {
    let devices = list_devices(hid);
    if devices.is_empty() {
        return Err(
            "No supported Ajazz devices found. The SDK only recognizes vendor IDs 0x5548, 0x0300 and 0x1200."
                .to_string()
                .into(),
        );
    }

    for (kind, serial) in &devices {
        println!("Found device: {kind:?} ({serial})");
    }

    let (kind, serial) = devices
        .into_iter()
        .next()
        .expect("devices list is not empty");

    Ok((kind, serial))
}

/// Runs a series of reversible checks that validate the protocol layer without
/// writing anything to the device's flash (and in particular: no boot logo write).
fn run_preflight_checks() -> Result<(), Box<dyn Error>> {
    println!("Running non-destructive pre-flight checks (no boot logo is written)");
    println!();
    println!("NOTE: quit OpenDeck before running this, otherwise its reader task");
    println!("may steal ACK packets from the device and cause false negatives.");
    println!();

    let hid = new_hidapi()?;
    let (kind, serial) = first_device(&hid)?;

    let device = Ajazz::connect_with_retries(&hid, kind, &serial, 10)?;

    println!("Device info:");
    println!("  kind:          {kind:?}");
    println!("  serial:        {serial}");
    println!("  manufacturer:  {}", device.manufacturer()?);
    println!("  product:       {}", device.product()?);
    println!("  firmware:      {}", device.firmware_version()?);
    println!();

    // "LIG" command — the same one OpenDeck sends on connect. Reversible.
    println!("Testing brightness command...");
    device.set_brightness(50)?;
    println!("  OK");
    println!();

    // Exercises the image announce + data reports + flush path that the boot
    // logo write also uses. Button images live in RAM and are cleared right
    // after — nothing is persisted to flash.
    println!("Testing button image write + flush + clear...");
    let mut img = RgbImage::new(85, 85);
    for pixel in img.pixels_mut() {
        *pixel = Rgb([0, 128, 255]);
    }
    device.set_button_image(0, DynamicImage::ImageRgb8(img))?;
    device.flush()?;
    device.clear_all_button_images()?;
    println!("  OK");
    println!();

    println!("All transport checks passed.");
    println!("The only untested step is the boot-logo write command itself");
    println!("(flash write + expected ACK). Run without --check to do it.");

    Ok(())
}
