//! The ignored tests need a classic PCAN-USB plugged in, and only ever listen:
//!
//! ```sh
//! cargo test -p wiretap-io --test can_pcan -- --ignored --nocapture
//! ```

#![cfg(all(feature = "can-pcan", any(target_os = "macos", target_os = "windows")))]

use std::time::Duration;

use tokio::time::{timeout, timeout_at, Instant};
use wiretap_io::can::{
    pcan::{self, PcanDevice, PcanModel, PcanOptions},
    CanError, CanEvent, CanOptions,
};

fn nowhere(model: PcanModel) -> PcanDevice {
    PcanDevice {
        serial: None,
        bus: 255,
        address: 255,
        product: String::new(),
        model,
    }
}

fn listen_only() -> CanOptions {
    let mut options = CanOptions::default();
    options.listen_only = true;
    options.reopen = None;
    options
}

async fn open_err(pcan: PcanOptions) -> CanError {
    match timeout(Duration::from_secs(5), pcan::open(pcan, listen_only())).await {
        Ok(Ok(_)) => panic!("the open should fail"),
        Ok(Err(error)) => error,
        Err(_) => panic!("the open should fail in time"),
    }
}

#[tokio::test]
async fn a_selector_that_matches_nothing_is_the_callers_open_error() {
    for model in [PcanModel::Usb, PcanModel::UsbFd] {
        match open_err(PcanOptions::new(nowhere(model), 500_000)).await {
            CanError::Open { device, .. } => assert_eq!(device, "pcan 255:255"),
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn what_the_device_cant_do_is_refused_before_any_claim() {
    let untimeable = PcanOptions::new(nowhere(PcanModel::Usb), 1_000);
    let mut fd_on_classic = PcanOptions::new(nowhere(PcanModel::Usb), 500_000);
    fd_on_classic.data = Some((2_000_000, None));
    let mut second_channel = PcanOptions::new(nowhere(PcanModel::ChipUsb), 500_000);
    second_channel.channel = 1;
    for pcan in [untimeable, fd_on_classic, second_channel] {
        let error = open_err(pcan).await;
        assert!(matches!(error, CanError::Config(_)), "{error:?}");
    }
}

fn first_device() -> PcanDevice {
    let found = pcan::devices().expect("a USB listing");
    println!("devices: {found:?}");
    found
        .into_iter()
        .find(|device| device.model == PcanModel::Usb)
        .expect("a PCAN-USB plugged in")
}

#[tokio::test]
#[ignore = "needs a PCAN-USB: see this file's header"]
async fn probe_reads_the_first_adapter() {
    let info = pcan::probe(&first_device(), Duration::from_secs(3))
        .await
        .expect("a probe");
    println!("{info:?}");
}

#[tokio::test]
#[ignore = "needs a PCAN-USB: see this file's header"]
async fn listen_only_at_500k_for_five_seconds() {
    let pcan = PcanOptions::new(first_device(), 500_000);
    let mut task = pcan::open(pcan, listen_only()).await.expect("an open");
    let until = Instant::now() + Duration::from_secs(5);
    let mut frames = 0;
    while let Ok(Some(event)) = timeout_at(until, task.next_event()).await {
        match event {
            CanEvent::Connected(info) => println!("connected: {info:?}"),
            CanEvent::Read(reads) => {
                for read in reads {
                    frames += 1;
                    let f = &read.frame;
                    let id = if f.extended {
                        format!("{:08X}", f.arb_id)
                    } else {
                        format!("{:03X}", f.arb_id)
                    };
                    let data: Vec<String> = f.data.iter().map(|b| format!("{b:02X}")).collect();
                    let rtr = if f.rtr { " R" } else { "" };
                    println!(
                        "{:?} {:?} {id} [{}]{rtr} {} device_us={:?}",
                        read.at,
                        read.direction,
                        f.dlc(),
                        data.join(" "),
                        read.device_us
                    );
                }
            }
            CanEvent::Disconnected { error, .. } => panic!("lost: {error}"),
            other => println!("{other:?}"),
        }
    }
    println!("{frames} frames in 5 s");
    task.stop().await;
}
