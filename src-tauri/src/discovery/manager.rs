use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tauri::{AppHandle, Emitter};
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};

use super::{
    models::{DiscoveryDevice, DiscoveryEvent},
    parser::parse_mndp,
};

const MNDP_PORT: u16 = 5678;
const DEVICE_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);
const MAX_DATAGRAM: usize = 2048;

type SeenDevice = (DiscoveryDevice, Instant);

#[derive(Default)]
pub struct DiscoveryManager {
    task: Mutex<Option<JoinHandle<()>>>,
    starting: AtomicBool,
}

impl DiscoveryManager {
    pub async fn start(&self, app: AppHandle) -> Result<(), String> {
        if self
            .starting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        let result = self.start_listener(app).await;
        self.starting.store(false, Ordering::SeqCst);

        result
    }

    async fn start_listener(&self, app: AppHandle) -> Result<(), String> {
        {
            let task = self
                .task
                .lock()
                .map_err(|_| "Discovery lock poisoned".to_string())?;

            if task.as_ref().is_some_and(|handle| !handle.is_finished()) {
                println!("[MNDP] Discovery is already running");
                return Ok(());
            }
        }

        println!("[MNDP] Starting discovery listener...");
        println!("[MNDP] Binding UDP port {}", MNDP_PORT);

        let socket = UdpSocket::bind(("0.0.0.0", MNDP_PORT))
            .await
            .map_err(|error| format!("MNDP bind failed: {error}"))?;

        println!("[MNDP] Listening on 0.0.0.0:{}", MNDP_PORT);

        let handle = tokio::spawn(async move {
            Self::listen(socket, app).await;
        });

        let mut task = match self.task.lock() {
            Ok(task) => task,
            Err(_) => {
                handle.abort();
                return Err("Discovery lock poisoned".to_string());
            }
        };

        *task = Some(handle);

        Ok(())
    }

    async fn listen(socket: UdpSocket, app: AppHandle) {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let mut devices: HashMap<String, SeenDevice> = HashMap::new();

        let mut cleanup = interval(CLEANUP_INTERVAL);
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);

        println!("[MNDP] Listener started successfully");

        loop {
            tokio::select! {
                received = socket.recv_from(&mut buffer) => {
                    match received {
                        Ok((size, source)) => {
                            println!(
                                "[MNDP] Packet received: {} bytes from {}",
                                size,
                                source
                            );

                            match parse_mndp(&buffer[..size], source.ip()) {
                                Some(device) => {
                                    println!(
                                        "[MNDP] Device found: identity={:?}, mac={:?}, ip={}",
                                        device.identity,
                                        device.mac_address,
                                        device.ipv4_address.as_deref().unwrap_or("-")
                                    );

                                    Self::publish_device(
                                        &app,
                                        &mut devices,
                                        device,
                                    );
                                }

                                None => {
                                    let hex = buffer[..size]
                                        .iter()
                                        .map(|byte| format!("{byte:02X}"))
                                        .collect::<Vec<_>>()
                                        .join(" ");

                                    println!(
                                        "[MNDP] Parser rejected packet from {}: {}",
                                        source,
                                        hex
                                    );
                                }
                            }
                        }

                        Err(error) => {
                            eprintln!(
                                "[MNDP] UDP receive error: {}",
                                error
                            );
                        }
                    }
                }

                _ = cleanup.tick() => {
                    Self::remove_stale_devices(
                        &app,
                        &mut devices,
                    );
                }
            }
        }
    }

    fn publish_device(
        app: &AppHandle,
        devices: &mut HashMap<String, SeenDevice>,
        device: DiscoveryDevice,
    ) {
        let key = device
            .mac_address
            .clone()
            .unwrap_or_else(|| device.source_ip.clone());

        let event_type = match devices.get_mut(&key) {
            Some((previous, last_seen)) => {
                *previous = device.clone();
                *last_seen = Instant::now();

                "updated"
            }

            None => {
                devices.insert(key, (device.clone(), Instant::now()));

                "found"
            }
        };

        let payload = DiscoveryEvent {
            device,
            event_type: event_type.to_string(),
        };

        match app.emit("discovery://device", payload) {
            Ok(_) => {
                println!("[MNDP] Event emitted: {}", event_type);
            }

            Err(error) => {
                eprintln!("[MNDP] Failed to emit event: {}", error);
            }
        }
    }

    fn remove_stale_devices(app: &AppHandle, devices: &mut HashMap<String, SeenDevice>) {
        let stale: Vec<String> = devices
            .iter()
            .filter(|(_, (_, last_seen))| last_seen.elapsed() >= DEVICE_TIMEOUT)
            .map(|(key, _)| key.clone())
            .collect();

        for key in stale {
            if let Some((device, _)) = devices.remove(&key) {
                println!("[MNDP] Device lost: {:?}", device.identity);

                let payload = DiscoveryEvent {
                    device,
                    event_type: "lost".to_string(),
                };

                if let Err(error) = app.emit("discovery://device", payload) {
                    eprintln!("[MNDP] Failed to emit lost event: {}", error);
                }
            }
        }
    }

    pub fn stop(&self) -> Result<(), String> {
        let mut task = self
            .task
            .lock()
            .map_err(|_| "Discovery lock poisoned".to_string())?;

        if let Some(handle) = task.take() {
            handle.abort();
            println!("[MNDP] Discovery stopped");
        }

        Ok(())
    }

    pub fn is_running(&self) -> Result<bool, String> {
        let task = self
            .task
            .lock()
            .map_err(|_| "Discovery lock poisoned".to_string())?;

        Ok(task.as_ref().is_some_and(|handle| !handle.is_finished()))
    }
}
