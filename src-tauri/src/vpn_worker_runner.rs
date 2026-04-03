use crate::proxy_storage::is_process_running;
use crate::vpn_worker_storage::{
  delete_vpn_worker_config, find_vpn_worker_by_vpn_id, generate_vpn_worker_id,
  get_vpn_worker_config, list_vpn_worker_configs, save_vpn_worker_config, VpnWorkerConfig,
};
use std::process::Stdio;

const VPN_WORKER_POLL_INTERVAL_MS: u64 = 100;
const VPN_WORKER_STARTUP_TIMEOUT_MS: u64 = 10_000;
const OPENVPN_WORKER_STARTUP_TIMEOUT_MS: u64 = 100_000;

async fn vpn_worker_accepting_connections(config: &VpnWorkerConfig) -> bool {
  let has_local_url = config
    .local_url
    .as_ref()
    .map(|local_url| !local_url.is_empty())
    .unwrap_or(false);

  let Some(port) = config.local_port else {
    return false;
  };

  if !has_local_url {
    return false;
  }

  matches!(
    tokio::time::timeout(
      tokio::time::Duration::from_millis(100),
      tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await,
    Ok(Ok(_))
  )
}

async fn wait_for_vpn_worker_ready(
  id: &str,
  vpn_type: &str,
) -> Result<VpnWorkerConfig, Box<dyn std::error::Error>> {
  let startup_timeout = if vpn_type == "openvpn" {
    tokio::time::Duration::from_millis(OPENVPN_WORKER_STARTUP_TIMEOUT_MS)
  } else {
    tokio::time::Duration::from_millis(VPN_WORKER_STARTUP_TIMEOUT_MS)
  };
  let startup_deadline = tokio::time::Instant::now() + startup_timeout;

  log::info!(
    "Waiting for VPN worker {} to start up and update config... v2",
    id
  );
  log::info!(
    "VPN worker {} startup timeout set to {:.1}s for {}",
    id,
    startup_timeout.as_secs_f32(),
    vpn_type
  );
  tokio::time::sleep(tokio::time::Duration::from_millis(
    VPN_WORKER_POLL_INTERVAL_MS,
  ))
  .await;

  let mut attempts = 0;
  let log_path = std::env::temp_dir().join(format!("donut-vpn-{}.log", id));

  loop {
    tokio::time::sleep(tokio::time::Duration::from_millis(
      VPN_WORKER_POLL_INTERVAL_MS,
    ))
    .await;

    if let Some(updated_config) = get_vpn_worker_config(id) {
      let process_running = updated_config.pid.map(is_process_running).unwrap_or(false);

      if !process_running && attempts > 2 {
        let log_output =
          std::fs::read_to_string(&log_path).unwrap_or_else(|_| "No log available".to_string());
        log::error!("VPN worker process died. Log output:\n{}", log_output);
        return Err(format!("VPN worker process crashed. OpenVPN error:\n{}", log_output).into());
      }

      log::debug!(
        "Attempt {}: config exists, process_running={}, local_url={:?}, local_port={:?}",
        attempts + 1,
        process_running,
        updated_config.local_url,
        updated_config.local_port
      );

      if vpn_worker_accepting_connections(&updated_config).await {
        log::info!(
          "VPN worker {} started successfully. local_url: {}, port: {}",
          id,
          updated_config.local_url.as_deref().unwrap_or_default(),
          updated_config.local_port.unwrap_or_default()
        );
        return Ok(updated_config);
      }

      if updated_config.local_url.is_none() {
        log::debug!(
          "Attempt {}: local_url not set yet (config exists)",
          attempts + 1
        );
      }
    } else {
      log::debug!("Attempt {}: config not found in storage", attempts + 1);
    }

    attempts += 1;
    if tokio::time::Instant::now() >= startup_deadline {
      if let Some(config) = get_vpn_worker_config(id) {
        let process_running = config.pid.map(is_process_running).unwrap_or(false);
        let log_output =
          std::fs::read_to_string(&log_path).unwrap_or_else(|_| "No log available".to_string());
        log::error!(
          "VPN worker failed to start within {:.1}s. pid={:?}, process_running={}, local_url={:?}",
          startup_timeout.as_secs_f32(),
          config.pid,
          process_running,
          config.local_url
        );
        log::error!(
          "Final config state: id={}, vpn_id={}, vpn_type={}, local_port={:?}, config_file={}",
          config.id,
          config.vpn_id,
          config.vpn_type,
          config.local_port,
          config.config_file_path
        );
        delete_vpn_worker_config(id);
        return Err(
          format!(
            "VPN worker failed to start within {:.1}s.\n\nVPN worker log:\n{}",
            startup_timeout.as_secs_f32(),
            log_output
          )
          .into(),
        );
      }
      log::error!("VPN worker config {} not found after spawn", id);
      delete_vpn_worker_config(id);
      return Err("VPN worker config not found after spawn".into());
    }
  }
}

pub async fn start_vpn_worker(vpn_id: &str) -> Result<VpnWorkerConfig, Box<dyn std::error::Error>> {
  // First, clean up any dead VPN worker processes from previous attempts
  log::info!("Cleaning up any dead VPN worker processes...");
  for config in list_vpn_worker_configs() {
    if let Some(pid) = config.pid {
      if !is_process_running(pid) {
        log::info!(
          "Found dead VPN worker process (pid: {}), cleaning up config: {}",
          pid,
          config.id
        );
        delete_vpn_worker_config(&config.id);
      }
    }
  }

  // Check if a VPN worker for this vpn_id already exists and is running
  if let Some(existing) = find_vpn_worker_by_vpn_id(vpn_id) {
    if let Some(pid) = existing.pid {
      if is_process_running(pid) {
        log::info!(
          "Found existing running VPN worker for vpn_id: {}, pid: {}",
          vpn_id,
          pid
        );
        if vpn_worker_accepting_connections(&existing).await {
          return Ok(existing);
        }

        log::info!(
          "Existing VPN worker for vpn_id: {} is still starting; waiting for readiness",
          vpn_id
        );
        return wait_for_vpn_worker_ready(&existing.id, &existing.vpn_type).await;
      }

      log::info!(
        "Found dead VPN worker config for vpn_id: {}, cleaning up",
        vpn_id
      );
      delete_vpn_worker_config(&existing.id);
    } else {
      log::info!(
        "Found stale VPN worker config without PID for vpn_id: {}, cleaning up",
        vpn_id
      );
      delete_vpn_worker_config(&existing.id);
    }
  }

  // Load VPN config from storage to determine type
  let vpn_config = {
    let storage = crate::vpn::VPN_STORAGE
      .lock()
      .map_err(|e| format!("Failed to lock VPN storage: {e}"))?;
    storage
      .load_config(vpn_id)
      .map_err(|e| format!("Failed to load VPN config: {e}"))?
  };

  let vpn_type_str = match vpn_config.vpn_type {
    crate::vpn::VpnType::WireGuard => "wireguard",
    crate::vpn::VpnType::OpenVPN => "openvpn",
  };

  // For OpenVPN on Windows, try to clean up any orphaned OpenVPN processes
  // This helps reset the DCO device if there was a recent crash
  #[cfg(windows)]
  if vpn_type_str == "openvpn" {
    log::info!("Attempting to clean up any orphaned OpenVPN processes...");
    // Kill all openvpn.exe processes (this is safe since we'll start a fresh one)
    let _ = std::process::Command::new("taskkill")
      .args(["/F", "/IM", "openvpn.exe"])
      .output();
    // Give the system a moment to release resources
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
  }

  // Write decrypted config to a temp file
  let config_file_path = std::env::temp_dir()
    .join(format!("donut_vpn_{}.conf", vpn_id))
    .to_string_lossy()
    .to_string();

  std::fs::write(&config_file_path, &vpn_config.config_data)?;

  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&config_file_path, std::fs::Permissions::from_mode(0o600));
  }

  let id = generate_vpn_worker_id();
  log::info!("Generated VPN worker ID: {}", id);

  // Find an available port
  let local_port = {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()?.port()
  };
  log::info!("Allocated port for VPN worker: {}", local_port);

  let config = VpnWorkerConfig::new(
    id.clone(),
    vpn_id.to_string(),
    vpn_type_str.to_string(),
    config_file_path.clone(),
  );
  save_vpn_worker_config(&config)?;
  log::info!(
    "Saved VPN worker config. VPN type: {}, config file: {}",
    vpn_type_str,
    config_file_path
  );

  // Spawn detached VPN worker process
  // Find the donut-proxy binary (separate worker binary that handles vpn-worker subcommand)
  let proxy_exe = {
    let current_exe = std::env::current_exe()?;
    let current_dir = current_exe
      .parent()
      .ok_or("Failed to get parent directory of current exe")?;

    // Check for donut-proxy in standard locations
    #[cfg(windows)]
    let proxy_name = "donut-proxy.exe";
    #[cfg(unix)]
    let proxy_name = "donut-proxy";

    // Try: current directory, ../binaries (for Tauri app structure), same location
    let candidates = [
      current_dir.join(proxy_name),
      current_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("binaries").join(proxy_name))
        .unwrap_or_default(),
      current_dir.join("../../../binaries").join(proxy_name),
    ];

    let mut proxy_path = None;
    for candidate in &candidates {
      if candidate.exists() {
        log::info!("Found donut-proxy at: {:?}", candidate);
        proxy_path = Some(candidate.clone());
        break;
      }
    }

    proxy_path.ok_or_else(|| -> Box<dyn std::error::Error> {
      let paths = candidates
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
      format!("donut-proxy binary not found. Searched: {}", paths).into()
    })?
  };

  log::info!("Spawning VPN worker from executable: {:?}", proxy_exe);

  #[cfg(unix)]
  {
    use std::os::unix::process::CommandExt;
    use std::process::Command as StdCommand;

    let mut cmd = StdCommand::new(&proxy_exe);
    cmd.arg("vpn-worker");
    cmd.arg("start");
    cmd.arg("--id");
    cmd.arg(&id);
    cmd.arg("--port");
    cmd.arg(local_port.to_string());

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());

    let log_path = std::env::temp_dir().join(format!("donut-vpn-{}.log", id));
    if let Ok(file) = std::fs::File::create(&log_path) {
      log::info!("VPN worker stderr will be logged to: {:?}", log_path);
      cmd.stderr(Stdio::from(file));
    } else {
      cmd.stderr(Stdio::null());
    }

    unsafe {
      cmd.pre_exec(|| {
        libc::setsid();
        if libc::setpriority(libc::PRIO_PROCESS, 0, -10) != 0 {
          let _ = libc::setpriority(libc::PRIO_PROCESS, 0, -5);
        }
        Ok(())
      });
    }

    let child = cmd.spawn()?;
    let pid = child.id();
    log::info!(
      "VPN worker spawned successfully on Unix. PID: {}, local_port: {}",
      pid,
      local_port
    );

    let mut config_with_pid = config.clone();
    config_with_pid.pid = Some(pid);
    config_with_pid.local_port = Some(local_port);
    save_vpn_worker_config(&config_with_pid)?;
    log::info!("Updated VPN worker config with PID: {}", pid);

    drop(child);
  }

  #[cfg(windows)]
  {
    use std::os::windows::process::CommandExt;
    use std::process::Command as StdCommand;

    let mut cmd = StdCommand::new(&proxy_exe);
    cmd.arg("vpn-worker");
    cmd.arg("start");
    cmd.arg("--id");
    cmd.arg(&id);
    cmd.arg("--port");
    cmd.arg(local_port.to_string());

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());

    let log_path = std::env::temp_dir().join(format!("donut-vpn-{}.log", id));
    if let Ok(file) = std::fs::File::create(&log_path) {
      log::info!("VPN worker stderr will be logged to: {:?}", log_path);
      cmd.stderr(Stdio::from(file));
    } else {
      cmd.stderr(Stdio::null());
    }

    const DETACHED_PROCESS: u32 = 0x00000008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);

    let child = cmd.spawn()?;
    let pid = child.id();
    log::info!(
      "VPN worker spawned successfully on Windows. PID: {}, local_port: {}",
      pid,
      local_port
    );

    let mut config_with_pid = config.clone();
    config_with_pid.pid = Some(pid);
    config_with_pid.local_port = Some(local_port);
    save_vpn_worker_config(&config_with_pid)?;
    log::info!("Updated VPN worker config with PID: {}", pid);

    drop(child);
  }

  wait_for_vpn_worker_ready(&id, vpn_type_str).await
}

pub async fn stop_vpn_worker(id: &str) -> Result<bool, Box<dyn std::error::Error>> {
  let config = get_vpn_worker_config(id);

  if let Some(config) = config {
    if let Some(pid) = config.pid {
      #[cfg(unix)]
      {
        use std::process::Command;
        let _ = Command::new("kill")
          .arg("-TERM")
          .arg(pid.to_string())
          .output();
      }
      #[cfg(windows)]
      {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let _ = Command::new("taskkill")
          .args(["/F", "/PID", &pid.to_string()])
          .creation_flags(CREATE_NO_WINDOW)
          .output();
      }

      tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // Clean up temp config file
    let _ = std::fs::remove_file(&config.config_file_path);

    delete_vpn_worker_config(id);
    return Ok(true);
  }

  Ok(false)
}

pub async fn stop_vpn_worker_by_vpn_id(vpn_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
  if let Some(config) = find_vpn_worker_by_vpn_id(vpn_id) {
    return stop_vpn_worker(&config.id).await;
  }
  Ok(false)
}

pub async fn stop_all_vpn_workers() -> Result<(), Box<dyn std::error::Error>> {
  let configs = list_vpn_worker_configs();
  for config in configs {
    let _ = stop_vpn_worker(&config.id).await;
  }
  Ok(())
}
