use super::config::{OpenVpnConfig, VpnError};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub struct OpenVpnSocks5Server {
  config: OpenVpnConfig,
  port: u16,
}

impl OpenVpnSocks5Server {
  pub fn new(config: OpenVpnConfig, port: u16) -> Self {
    Self { config, port }
  }

  fn read_log_tail(path: &Path, n: usize) -> String {
    std::fs::read_to_string(path)
      .unwrap_or_default()
      .lines()
      .rev()
      .take(n)
      .collect::<Vec<_>>()
      .into_iter()
      .rev()
      .collect::<Vec<_>>()
      .join("\n")
  }

  /// Extract a VPN-assigned IP from a management interface line.
  /// Lines look like: `1775178899,ASSIGN_IP,,10.7.7.10,,,,`
  /// or `>STATE:...,CONNECTED,SUCCESS,10.7.7.10,...`
  fn extract_vpn_ip(line: &str) -> Option<Ipv4Addr> {
    // Try comma-separated fields and find a private IP in 10.x.x.x range
    for field in line.split(',') {
      let trimmed = field.trim();
      if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
        // Only accept private VPN IPs (10.x, 172.16-31.x, 192.168.x)
        if ip.is_private() && !ip.is_loopback() {
          return Some(ip);
        }
      }
    }
    None
  }

  fn log_indicates_connected(log_content: &str) -> bool {
    log_content.contains("Initialization Sequence Completed")
  }

  fn log_indicates_netsh_error(log_content: &str) -> bool {
    log_content.contains("ERROR: command failed")
  }

  fn has_config_directive(config: &str, directive: &str) -> bool {
    config.lines().any(|line| {
      let trimmed = line.trim();
      !trimmed.is_empty()
        && !trimmed.starts_with('#')
        && !trimmed.starts_with(';')
        && trimmed.starts_with(directive)
    })
  }

  fn build_runtime_config(&self) -> String {
    let mut runtime_config = self.config.raw_config.clone();

    // Prevent OpenVPN from hijacking the system's default route.
    // The SOCKS5 proxy binds outgoing sockets to the VPN interface IP,
    // so only browser traffic (via SOCKS5) goes through the tunnel.
    if !Self::has_config_directive(&runtime_config, "pull-filter") {
      log::info!("[vpn-worker] Adding pull-filters to prevent global route hijack");
      runtime_config.push_str("\r\npull-filter ignore \"redirect-gateway\"\r\n");
      runtime_config.push_str("pull-filter ignore \"block-outside-dns\"\r\n");
      // Prevent VPN DNS from being registered system-wide
      runtime_config.push_str("pull-filter ignore \"dhcp-option\"\r\n");
    }

    // Add a high-metric default route through the VPN gateway so that
    // traffic explicitly bound to the VPN interface IP can reach the internet,
    // while all other system traffic uses the normal default gateway.
    if !Self::has_config_directive(&runtime_config, "route 0.0.0.0") {
      log::info!("[vpn-worker] Adding high-metric default route through VPN gateway");
      runtime_config.push_str("\r\nroute 0.0.0.0 0.0.0.0 vpn_gateway 9999\r\n");
    }

    #[cfg(windows)]
    {
      // Strip `dev-node` so OpenVPN doesn't try to reuse a named DCO adapter
      // from another VPN client (e.g. Surfshark). With disable-dco + wintun
      // OpenVPN will create its own adapter instead.
      if Self::has_config_directive(&runtime_config, "dev-node") {
        log::info!("[vpn-worker] Stripping 'dev-node' directive to avoid reusing a DCO adapter");
        runtime_config = runtime_config
          .lines()
          .filter(|line| {
            let trimmed = line.trim();
            trimmed.is_empty()
              || trimmed.starts_with('#')
              || trimmed.starts_with(';')
              || !trimmed.starts_with("dev-node")
          })
          .collect::<Vec<_>>()
          .join("\r\n");
      }

      if !Self::has_config_directive(&runtime_config, "disable-dco") {
        log::info!("[vpn-worker] Appending 'disable-dco' for Windows compatibility");
        runtime_config.push_str("\r\ndisable-dco\r\n");
      }

      if self.config.dev_type.starts_with("tun")
        && !Self::has_config_directive(&runtime_config, "windows-driver")
      {
        log::info!("[vpn-worker] Appending 'windows-driver wintun' for tun profile");
        runtime_config.push_str("\r\nwindows-driver wintun\r\n");
      }
    }

    runtime_config
  }

  fn find_openvpn_binary() -> Result<PathBuf, VpnError> {
    log::info!("[vpn-worker] Searching for OpenVPN binary...");
    let locations = [
      "/usr/sbin/openvpn",
      "/usr/local/sbin/openvpn",
      "/opt/homebrew/bin/openvpn",
      "/usr/bin/openvpn",
      "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
      "C:\\Program Files (x86)\\OpenVPN\\bin\\openvpn.exe",
    ];

    for loc in &locations {
      let path = PathBuf::from(loc);
      if path.exists() {
        log::info!("[vpn-worker] Found OpenVPN at: {}", loc);
        return Ok(path);
      }
    }

    #[cfg(unix)]
    {
      if let Ok(output) = Command::new("which").arg("openvpn").output() {
        if output.status.success() {
          let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
          if !path.is_empty() {
            log::info!("[vpn-worker] Found OpenVPN via 'which': {}", path);
            return Ok(PathBuf::from(path));
          }
        }
      }
    }

    #[cfg(windows)]
    {
      use std::os::windows::process::CommandExt;
      const CREATE_NO_WINDOW: u32 = 0x08000000;
      if let Ok(output) = Command::new("where")
        .arg("openvpn")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
      {
        if output.status.success() {
          let path = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
          if !path.is_empty() {
            log::info!("[vpn-worker] Found OpenVPN via 'where': {}", path);
            return Ok(PathBuf::from(path));
          }
        }
      }
    }

    let error_msg = "OpenVPN binary not found. Please install OpenVPN.";
    log::error!("[vpn-worker] {}", error_msg);
    Err(VpnError::Connection(error_msg.to_string()))
  }

  pub async fn run(self, config_id: String) -> Result<(), VpnError> {
    let openvpn_bin = Self::find_openvpn_binary()?;
    log::info!("[vpn-worker] Found OpenVPN binary at: {:?}", openvpn_bin);

    // On Windows, flush stale IPs from OpenVPN/DCO adapters left by previous crashed
    // sessions. Without this, netsh "set address" fails with "The object already exists".
    #[cfg(windows)]
    {
      use std::os::windows::process::CommandExt;
      const CREATE_NO_WINDOW: u32 = 0x08000000;

      // Find adapters whose name contains common OpenVPN/DCO/Wintun keywords
      if let Ok(output) = Command::new("netsh")
        .args(["interface", "ip", "show", "config"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
      {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Look for adapter names like "OpenVPN Data Channel Offload ...", "OpenVPN Wintun", etc.
        for line in stdout.lines() {
          let trimmed = line.trim();
          if let Some(name) = trimmed
            .strip_prefix("Configuration for interface \"")
            .and_then(|s| s.strip_suffix('"'))
          {
            let lower = name.to_lowercase();
            if lower.contains("openvpn") || lower.contains("ovpn-dco") || lower.contains("wintun") {
              log::info!(
                "[vpn-worker] Resetting stale adapter '{}' to DHCP before launch",
                name
              );
              let _ = Command::new("netsh")
                .args(["interface", "ip", "set", "address", name, "dhcp"])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
            }
          }
        }
      }
    }

    // Write config to temp file
    let config_path = std::env::temp_dir().join(format!("openvpn_{}.ovpn", config_id));
    let runtime_config = self.build_runtime_config();
    std::fs::write(&config_path, runtime_config).map_err(VpnError::Io)?;
    log::info!(
      "[vpn-worker] Wrote OpenVPN config to: {}",
      config_path.display()
    );

    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }

    // Find a management port
    let mgmt_listener = std::net::TcpListener::bind("127.0.0.1:0")
      .map_err(|e| VpnError::Connection(format!("Failed to bind management port: {e}")))?;
    let mgmt_port = mgmt_listener
      .local_addr()
      .map_err(|e| VpnError::Connection(format!("Failed to get management port: {e}")))?
      .port();
    drop(mgmt_listener);
    log::info!("[vpn-worker] Allocated management port: {}", mgmt_port);

    // Use --log so OpenVPN writes directly to a file with per-line flushing.
    // Piping stdout to a file uses full buffering on Windows, so log content
    // like "Initialization Sequence Completed" can stay in buffer and never
    // reach disk while the process is running.
    let openvpn_log_path = std::env::temp_dir().join(format!("openvpn-{}.log", config_id));
    log::info!(
      "[vpn-worker] OpenVPN output will be logged to: {}",
      openvpn_log_path.display()
    );

    // Start OpenVPN — connect directly to the VPN server (no --socks-proxy flag).
    // The SOCKS5 server we expose below relies on OS routing to send traffic through
    // the TUN/TAP interface that OpenVPN sets up.
    let mut cmd = Command::new(&openvpn_bin);
    cmd
      .arg("--config")
      .arg(&config_path)
      .arg("--management")
      .arg("127.0.0.1")
      .arg(mgmt_port.to_string())
      .arg("--log")
      .arg(&openvpn_log_path)
      .arg("--verb")
      .arg("3")
      .stdout(Stdio::null())
      .stderr(Stdio::null());

    // On Windows, hide the OpenVPN console window (output goes to our log file)
    #[cfg(windows)]
    {
      use std::os::windows::process::CommandExt;
      const CREATE_NO_WINDOW: u32 = 0x08000000;

      // Enforce compatibility flags at CLI level so they take effect even when
      // profile text contains conflicting directives.
      cmd.arg("--disable-dco");
      if self.config.dev_type.starts_with("tun") {
        cmd.arg("--windows-driver").arg("wintun");
      }

      cmd.creation_flags(CREATE_NO_WINDOW);
    }

    log::info!("[vpn-worker] Spawning OpenVPN process...");
    let mut child = cmd
      .spawn()
      .map_err(|e| VpnError::Connection(format!("Failed to start OpenVPN: {e}")))?;
    log::info!(
      "[vpn-worker] OpenVPN process spawned with PID: {:?}",
      child.id()
    );

    // Give OpenVPN a moment to initialise before we start polling
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Check for an immediate crash
    match child.try_wait() {
      Ok(Some(status)) => {
        let _ = std::fs::remove_file(&config_path);
        let tail = Self::read_log_tail(&openvpn_log_path, 20);
        let error_msg = format!(
          "OpenVPN exited immediately (status: {}). On Windows, OpenVPN MUST be run with \
           administrator privileges to create a TAP adapter. Last output:\n{}",
          status, tail
        );
        log::error!("[vpn-worker] {}", error_msg);
        return Err(VpnError::Connection(error_msg));
      }
      Ok(None) => log::info!("[vpn-worker] OpenVPN process is alive after 2s"),
      Err(e) => {
        let _ = std::fs::remove_file(&config_path);
        return Err(VpnError::Connection(format!(
          "Failed to check OpenVPN status: {e}"
        )));
      }
    }

    // Wait for OpenVPN to actually establish the VPN tunnel via the management interface.
    // A simple alive-check is NOT enough — OpenVPN can take 10-30 seconds to authenticate
    // and bring up the TAP adapter. Without being truly CONNECTED the SOCKS5 server below
    // would forward traffic through the host's real IP.
    log::info!(
      "[vpn-worker] Waiting for OpenVPN tunnel to be established (management port {}, timeout 90s)...",
      mgmt_port
    );
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(90);

    // Step 1: connect to the management socket (OpenVPN may take a few seconds to open it)
    let mgmt_stream = loop {
      if tokio::time::Instant::now() >= deadline {
        let tail = Self::read_log_tail(&openvpn_log_path, 20);
        return Err(VpnError::Connection(format!(
          "Timed out connecting to OpenVPN management interface. \
           On Windows, OpenVPN requires administrator privileges to create a TAP adapter. \
           Last OpenVPN output:\n{}",
          tail
        )));
      }
      if let Ok(Some(status)) = child.try_wait() {
        let tail = Self::read_log_tail(&openvpn_log_path, 20);
        return Err(VpnError::Connection(format!(
          "OpenVPN exited (status: {}) before the tunnel was established. \
           On Windows, OpenVPN requires administrator privileges. Last output:\n{}",
          status, tail
        )));
      }
      match TcpStream::connect(format!("127.0.0.1:{}", mgmt_port)).await {
        Ok(s) => {
          log::info!("[vpn-worker] Connected to OpenVPN management interface");
          break s;
        }
        Err(_) => tokio::time::sleep(tokio::time::Duration::from_millis(500)).await,
      }
    };

    // Step 2: query current state and subscribe to future CONNECTED notifications.
    // Split the stream so we can read lines AND periodically re-query state
    // (state on notifications can be missed if CONNECTED happens before subscription).
    let (mgmt_reader, mut mgmt_writer) = mgmt_stream.into_split();
    let _ = mgmt_writer.write_all(b"state on\nstate\n").await;

    let mut lines = BufReader::new(mgmt_reader).lines();
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    interval.tick().await; // consume the first immediate tick
    let mut loop_count = 0u64;
    let mut vpn_ip: Option<Ipv4Addr> = None;

    loop {
      loop_count += 1;

      if tokio::time::Instant::now() >= deadline {
        let tail = Self::read_log_tail(&openvpn_log_path, 20);
        return Err(VpnError::Connection(format!(
          "Timed out waiting for OpenVPN to reach CONNECTED state (90s). \
           On Windows, OpenVPN must run as Administrator to create a TAP adapter. \
           Last OpenVPN output:\n{}",
          tail
        )));
      }

      if let Ok(Some(status)) = child.try_wait() {
        let tail = Self::read_log_tail(&openvpn_log_path, 20);
        return Err(VpnError::Connection(format!(
          "OpenVPN exited (status: {}) before connecting. Last output:\n{}",
          status, tail
        )));
      }

      tokio::select! {
        line_result = lines.next_line() => {
          match line_result {
            Ok(Some(line)) => {
              log::info!("[vpn-worker] mgmt line: {}", line);
              // Try to extract VPN IP from any management line
              if let Some(ip) = Self::extract_vpn_ip(&line) {
                log::info!("[vpn-worker] Extracted VPN IP: {}", ip);
                vpn_ip = Some(ip);
              }
              if line.contains(",CONNECTED,") {
                log::info!("[vpn-worker] OpenVPN VPN tunnel is now CONNECTED (via mgmt)");
                break;
              }
              if line.contains("AUTH_FAILED") {
                let tail = Self::read_log_tail(&openvpn_log_path, 20);
                return Err(VpnError::Connection(format!(
                  "OpenVPN authentication failed. Check your VPN credentials. Last output:\n{}",
                  tail
                )));
              }
              if line.contains(",EXITING,") || line.contains(">FATAL:") {
                let tail = Self::read_log_tail(&openvpn_log_path, 20);
                return Err(VpnError::Connection(format!(
                  "OpenVPN is exiting. Last output:\n{}",
                  tail
                )));
              }
            }
            Ok(None) => {
              log::warn!("[vpn-worker] Management connection closed (EOF)");
              let tail = Self::read_log_tail(&openvpn_log_path, 20);
              return Err(VpnError::Connection(format!(
                "OpenVPN management connection closed before CONNECTED state. Last output:\n{}",
                tail
              )));
            }
            Err(e) => {
              log::error!("[vpn-worker] Management read error: {}", e);
            }
          }
        }
        _ = interval.tick() => {
          log::info!(
            "[vpn-worker] Tick #{}: checking log file and re-querying state",
            loop_count
          );

          // Re-query state via management (catches missed CONNECTED)
          if let Err(e) = mgmt_writer.write_all(b"state\n").await {
            log::warn!("[vpn-worker] Failed to write state query to mgmt: {}", e);
          }

          // Check log file for successful connection or errors.
          // Use spawn_blocking because std::fs can block the async runtime on Windows
          // if OpenVPN holds the log file with restrictive sharing flags.
          let log_path = openvpn_log_path.clone();
          let log_read = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&log_path)
          }).await;

          match log_read {
            Ok(Ok(content)) => {
              log::info!("[vpn-worker] Log file: {} bytes", content.len());
              if Self::log_indicates_connected(&content) {
                log::info!(
                  "[vpn-worker] Detected 'Initialization Sequence Completed' in OpenVPN log"
                );
                break;
              }
              if Self::log_indicates_netsh_error(&content) {
                log::error!("[vpn-worker] Detected netsh error in OpenVPN log");
                let tail = Self::read_log_tail(&openvpn_log_path, 30);
                return Err(VpnError::Connection(format!(
                  "OpenVPN failed to configure network adapter via netsh. \
                   OpenVPN log:\n{}",
                  tail
                )));
              }
            }
            Ok(Err(e)) => {
              log::warn!("[vpn-worker] Cannot read log file: {}", e);
            }
            Err(e) => {
              log::warn!("[vpn-worker] spawn_blocking for log read failed: {}", e);
            }
          }
        }
      }
    }

    // If we didn't get the VPN IP from management, extract from the log file
    // (look for "ifconfig X.X.X.X" in PUSH_REPLY or netsh set address)
    if vpn_ip.is_none() {
      if let Ok(log_content) = std::fs::read_to_string(&openvpn_log_path) {
        // Look for "ifconfig 10.x.x.x" in PUSH_REPLY
        for line in log_content.lines() {
          if let Some(pos) = line.find("ifconfig ") {
            let after = &line[pos + 9..];
            if let Some(ip_str) = after
              .split_whitespace()
              .next()
              .or_else(|| after.split(',').next())
            {
              if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                if ip.is_private() {
                  log::info!("[vpn-worker] Extracted VPN IP from log: {}", ip);
                  vpn_ip = Some(ip);
                  break;
                }
              }
            }
          }
        }
      }
    }

    let vpn_bind_ip = vpn_ip.unwrap_or_else(|| {
      log::warn!("[vpn-worker] Could not determine VPN IP, SOCKS5 will use default routing");
      Ipv4Addr::UNSPECIFIED
    });
    let vpn_bind_ip = Arc::new(vpn_bind_ip);
    log::info!(
      "[vpn-worker] SOCKS5 proxy will bind outgoing connections to {}",
      vpn_bind_ip
    );

    // Start a basic SOCKS5 proxy that tunnels through the OpenVPN TUN interface
    let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))
      .await
      .map_err(|e| VpnError::Connection(format!("Failed to bind SOCKS5: {e}")))?;

    let actual_port = listener
      .local_addr()
      .map_err(|e| VpnError::Connection(format!("Failed to get local addr: {e}")))?
      .port();

    if let Some(mut wc) = crate::vpn_worker_storage::get_vpn_worker_config(&config_id) {
      wc.local_port = Some(actual_port);
      wc.local_url = Some(format!("socks5://127.0.0.1:{}", actual_port));
      let _ = crate::vpn_worker_storage::save_vpn_worker_config(&wc);
    }

    log::info!(
      "[vpn-worker] OpenVPN SOCKS5 server listening on 127.0.0.1:{}",
      actual_port
    );

    loop {
      match listener.accept().await {
        Ok((client, _)) => {
          let bind_ip = vpn_bind_ip.clone();
          tokio::spawn(Self::handle_socks5_client(client, bind_ip));
        }
        Err(e) => {
          log::warn!("[vpn-worker] Accept error: {e}");
        }
      }
    }
  }

  async fn handle_socks5_client(
    mut client: TcpStream,
    vpn_bind_ip: Arc<Ipv4Addr>,
  ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::debug!("[socks5] New client connection");

    // Read greeting header (VER, NMETHODS)
    let mut greeting_header = [0u8; 2];
    if let Err(e) = client.read_exact(&mut greeting_header).await {
      if e.kind() != std::io::ErrorKind::UnexpectedEof {
        log::debug!("[socks5] Failed to read greeting header: {}", e);
      }
      return Ok(());
    }

    let ver = greeting_header[0];
    let nmethods = greeting_header[1] as usize;
    if ver != 0x05 {
      log::debug!(
        "[socks5] Unsupported SOCKS version in greeting: {:02x}",
        ver
      );
      return Ok(());
    }

    let mut methods = vec![0u8; nmethods];
    if let Err(e) = client.read_exact(&mut methods).await {
      if e.kind() != std::io::ErrorKind::UnexpectedEof {
        log::debug!("[socks5] Failed to read methods list: {}", e);
      }
      return Ok(());
    }

    // No authentication required
    client.write_all(&[0x05, 0x00]).await?;

    // Read request header (VER, CMD, RSV, ATYP)
    let mut req_header = [0u8; 4];
    if let Err(e) = client.read_exact(&mut req_header).await {
      if e.kind() != std::io::ErrorKind::UnexpectedEof {
        log::debug!("[socks5] Failed to read request header: {}", e);
      }
      return Ok(());
    }

    let req_ver = req_header[0];
    let cmd = req_header[1];
    let atyp = req_header[3];

    if req_ver != 0x05 {
      log::debug!("[socks5] Invalid request version: {:02x}", req_ver);
      return Ok(());
    }

    if cmd != 0x01 {
      // Command not supported
      let _ = client
        .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;
      log::debug!("[socks5] Unsupported command: {:02x}", cmd);
      return Ok(());
    }

    let dest_addr = match atyp {
      0x01 => {
        // IPv4: 4 bytes addr + 2 bytes port
        let mut addr_port = [0u8; 6];
        if let Err(e) = client.read_exact(&mut addr_port).await {
          if e.kind() != std::io::ErrorKind::UnexpectedEof {
            log::debug!("[socks5] Failed to read IPv4 destination: {}", e);
          }
          return Ok(());
        }
        let ip = std::net::Ipv4Addr::new(addr_port[0], addr_port[1], addr_port[2], addr_port[3]);
        let port = u16::from_be_bytes([addr_port[4], addr_port[5]]);
        format!("{}:{}", ip, port)
      }
      0x03 => {
        // Domain: 1 byte length + N bytes domain + 2 bytes port
        let mut len_buf = [0u8; 1];
        if let Err(e) = client.read_exact(&mut len_buf).await {
          if e.kind() != std::io::ErrorKind::UnexpectedEof {
            log::debug!("[socks5] Failed to read domain length: {}", e);
          }
          return Ok(());
        }
        let domain_len = len_buf[0] as usize;
        if domain_len == 0 {
          log::debug!("[socks5] Invalid zero-length domain");
          return Ok(());
        }

        let mut domain_bytes = vec![0u8; domain_len];
        if let Err(e) = client.read_exact(&mut domain_bytes).await {
          if e.kind() != std::io::ErrorKind::UnexpectedEof {
            log::debug!("[socks5] Failed to read domain: {}", e);
          }
          return Ok(());
        }

        let mut port_bytes = [0u8; 2];
        if let Err(e) = client.read_exact(&mut port_bytes).await {
          if e.kind() != std::io::ErrorKind::UnexpectedEof {
            log::debug!("[socks5] Failed to read domain port: {}", e);
          }
          return Ok(());
        }

        let domain = String::from_utf8_lossy(&domain_bytes).to_string();
        let port = u16::from_be_bytes(port_bytes);
        format!("{}:{}", domain, port)
      }
      0x04 => {
        // IPv6: 16 bytes addr + 2 bytes port
        let mut addr_port = [0u8; 18];
        if let Err(e) = client.read_exact(&mut addr_port).await {
          if e.kind() != std::io::ErrorKind::UnexpectedEof {
            log::debug!("[socks5] Failed to read IPv6 destination: {}", e);
          }
          return Ok(());
        }
        let ip = std::net::Ipv6Addr::from([
          addr_port[0],
          addr_port[1],
          addr_port[2],
          addr_port[3],
          addr_port[4],
          addr_port[5],
          addr_port[6],
          addr_port[7],
          addr_port[8],
          addr_port[9],
          addr_port[10],
          addr_port[11],
          addr_port[12],
          addr_port[13],
          addr_port[14],
          addr_port[15],
        ]);
        let port = u16::from_be_bytes([addr_port[16], addr_port[17]]);
        format!("{}:{}", ip, port)
      }
      other => {
        log::debug!("[socks5] Unsupported address type: {:02x}", other);
        let _ = client
          .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
          .await;
        return Ok(());
      }
    };

    log::debug!(
      "[socks5] Connecting to {} through OpenVPN tunnel (bind={})",
      dest_addr,
      vpn_bind_ip
    );
    // Connect to destination through OpenVPN tunnel by binding to the VPN interface IP.
    // This ensures only SOCKS5 proxy traffic goes through the VPN, not all system traffic.
    let connect_result: Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> = async {
      let dest: std::net::SocketAddr = dest_addr.parse()?;
      let socket = if dest.is_ipv4() {
        let sock = tokio::net::TcpSocket::new_v4()?;
        if !vpn_bind_ip.is_unspecified() {
          sock.bind(std::net::SocketAddr::new(
            std::net::IpAddr::V4(*vpn_bind_ip),
            0,
          ))?;
        }
        sock
      } else {
        tokio::net::TcpSocket::new_v6()?
      };
      Ok(socket.connect(dest).await?)
    }
    .await;
    match connect_result {
      Ok(upstream) => {
        log::debug!("[socks5] Connected to {}, starting relay", dest_addr);
        client
          .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
          .await?;

        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();

        let c2u = tokio::io::copy(&mut cr, &mut uw);
        let u2c = tokio::io::copy(&mut ur, &mut cw);

        let (r1, r2) = tokio::try_join!(c2u, u2c)?;
        log::debug!(
          "[socks5] Relay done for {}: client->upstream={} bytes, upstream->client={} bytes",
          dest_addr,
          r1,
          r2
        );
      }
      Err(e) => {
        log::debug!(
          "[socks5] Failed to connect to {} through VPN tunnel: {}",
          dest_addr,
          e
        );
        client
          .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
          .await?;
      }
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_find_openvpn_binary_format() {
    let result = OpenVpnSocks5Server::find_openvpn_binary();
    match result {
      Ok(path) => assert!(!path.as_os_str().is_empty()),
      Err(e) => assert!(e.to_string().contains("not found")),
    }
  }
}
