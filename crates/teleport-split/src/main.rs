use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use teleport_split::connect::{self, Connection};
use teleport_split::platform::{self, STATUS_FILE};
use teleport_split::sso::{self, Mfa};
use teleport_split::{
    CONNECT_FILE, Entry, ROUTES_FILE, ROUTES_HEADER, Result, State, Status, config_dir, parse_config,
};

const USAGE: &str = "\
A UniFi Teleport client that only routes your consoles' networks.

Usage:
  teleport-split login                 Sign in with your UI account
  teleport-split logout                Forget the saved session
  teleport-split ls                    List your consoles and their networks
  sudo teleport-split up <console>     Connect in the foreground; Ctrl-C disconnects

With the helper (sudo teleport-split install):
  teleport-split connect <console>     Connect and stay connected
  teleport-split disconnect
  teleport-split status
  sudo teleport-split uninstall

Extra destinations through Teleport, besides the console's own networks:
  teleport-split list
  teleport-split add <network|address|host>...
  teleport-split remove <network|address|host>...
";

/// How often the daemon looks at the connect file and the tunnel's health.
const TICK: Duration = Duration::from_secs(1);
/// How long to wait between attempts; doubled after each failure, up to the maximum.
const RETRY: Duration = Duration::from_secs(15);
const RETRY_MAX: Duration = Duration::from_secs(300);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let dir = config_dir();
    let result = match args.as_slice() {
        ["login"] => login(&dir),
        ["logout"] => sso::clear_session(&dir),
        ["ls"] => ls(&dir),
        ["up", console] => daemon(&dir, Some(console)),
        ["connect", console] => fs::create_dir_all(&dir)
            .and_then(|()| fs::write(dir.join(CONNECT_FILE), console))
            .map_err(Into::into),
        ["disconnect"] => remove(&dir.join(CONNECT_FILE)),
        ["status"] => status(),
        ["list"] => list(&dir),
        ["add", entries @ ..] if !entries.is_empty() => edit(&dir, entries, true),
        ["remove", entries @ ..] if !entries.is_empty() => edit(&dir, entries, false),
        ["install"] => install(&dir),
        ["install", "--config", dir] => install(Path::new(dir)),
        ["uninstall"] => platform::uninstall().map_err(Into::into),
        ["daemon", "--config", dir] => daemon(Path::new(dir), None),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let denied = e
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
            eprintln!(
                "teleport-split: {e}{}",
                if denied { " (this command needs sudo)" } else { "" }
            );
            ExitCode::FAILURE
        }
    }
}

fn remove(file: &Path) -> Result<()> {
    match fs::remove_file(file) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn login(dir: &Path) -> Result<()> {
    let user = prompt("UI account (email or username): ")?;
    let password = rpassword::prompt_password("Password: ")?;
    let session = sso::login(&user, &password, &mut || {
        let code = prompt("6-digit code, or Enter to approve the push notification: ")?;
        Ok(if code.is_empty() { Mfa::Push } else { Mfa::Totp(code) })
    })?;
    sso::save_session(dir, &session)?;
    println!("Signed in as {}.", session.user);
    Ok(())
}

fn ls(dir: &Path) -> Result<()> {
    for console in connect::consoles(dir)? {
        let subnets: Vec<String> = console.subnets.iter().map(ToString::to_string).collect();
        let state = if console.online { "online" } else { "offline" };
        println!("{}  ({state})  {}", console.name, subnets.join(" "));
    }
    Ok(())
}

fn status() -> Result<()> {
    let text = match fs::read_to_string(STATUS_FILE) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("The helper is not running. Run: sudo teleport-split install");
            return Ok(());
        }
        other => other?,
    };
    let status: Status = text.parse().map_err(|()| format!("{STATUS_FILE} is malformed"))?;
    println!("{}", status.summary());
    for route in &status.routes {
        println!("  via Teleport  {route}");
    }
    for route in &status.skipped {
        println!("  skipped       {route}");
    }
    Ok(())
}

/// The text of `routes.conf`, or its header while it does not exist.
fn routes_text(dir: &Path) -> Result<String> {
    match fs::read_to_string(dir.join(ROUTES_FILE)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ROUTES_HEADER.into()),
        other => Ok(other?),
    }
}

fn list(dir: &Path) -> Result<()> {
    for entry in parse_config(&routes_text(dir)?).entries {
        println!("{entry}");
    }
    Ok(())
}

fn edit(dir: &Path, entries: &[&str], add: bool) -> Result<()> {
    let wanted = entries
        .iter()
        .map(|e| {
            e.parse::<Entry>()
                .map_err(|()| format!("not a network, address or host name: {e}").into())
        })
        .collect::<Result<Vec<Entry>>>()?;
    let mut lines: Vec<String> = routes_text(dir)?.lines().map(str::to_string).collect();
    // Compare parsed entries, so "10.0.0.1/8" finds the line "10.0.0.0/8  # office".
    let entry_of = |line: &str| parse_config(line).entries.pop();
    for entry in wanted {
        let present = lines.iter().any(|l| entry_of(l).as_ref() == Some(&entry));
        if add && !present {
            lines.push(entry.to_string());
        } else if !add {
            lines.retain(|l| entry_of(l).as_ref() != Some(&entry));
        }
    }
    fs::create_dir_all(dir)?;
    fs::write(dir.join(ROUTES_FILE), lines.join("\n") + "\n")?;
    println!("Saved. It applies the next time Teleport connects.");
    Ok(())
}

fn install(config_dir: &Path) -> Result<()> {
    platform::install(config_dir)?;
    println!(
        "Helper installed. It uses the session and routes in {}",
        config_dir.display()
    );
    Ok(())
}

/// Keep the tunnel to the wanted console up: `console` when given (`up`),
/// otherwise whatever the connect file names (the helper).
fn daemon(dir: &Path, console: Option<&str>) -> Result<()> {
    let mut current: Option<(String, Connection)> = None;
    let mut error = String::new();
    let mut retry_at = Instant::now();
    let mut retry_in = RETRY;
    let mut written = String::new();
    let mut connected_once = false;
    let mut publish = |status: Status| -> Result<()> {
        let text = status.to_string();
        if text != written {
            eprintln!("{}", status.summary());
            for route in &status.skipped {
                eprintln!("  skipped {route}");
            }
            // The status file belongs to the helper; a foreground `up` only prints.
            if console.is_none() {
                // Rename into place so a reader never sees half a file.
                let tmp = format!("{STATUS_FILE}.tmp");
                fs::write(&tmp, &text)?;
                fs::rename(&tmp, STATUS_FILE)?;
            }
            written = text;
        }
        Ok(())
    };
    loop {
        let wanted = match console {
            Some(console) => Some(console.to_string()),
            None => fs::read_to_string(dir.join(CONNECT_FILE))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        };
        // Dropping the connection closes the interface, which takes its routes with it.
        if current
            .as_ref()
            .is_some_and(|(name, c)| Some(name) != wanted.as_ref() || !c.tunnel.alive())
        {
            current = None;
        }
        if wanted.is_none() {
            (retry_at, retry_in) = (Instant::now(), RETRY);
        }
        if let (None, Some(name)) = (&current, &wanted)
            && Instant::now() >= retry_at
        {
            publish(Status {
                state: State::Connecting,
                console: name.clone(),
                ..Status::default()
            })?;
            let extra = parse_config(&routes_text(dir).unwrap_or_default()).entries;
            // Whatever the outcome, wait before the next attempt: a tunnel that keeps
            // dying must not turn into a sign-in loop against Ubiquiti's cloud.
            retry_at = Instant::now() + retry_in;
            match connect::connect(dir, name, &extra) {
                Ok(connection) => {
                    current = Some((name.clone(), connection));
                    connected_once = true;
                    retry_in = RETRY;
                }
                // In the foreground a first failure is the user's answer; only a lost connection is retried.
                Err(e) if console.is_some() && !connected_once => return Err(e),
                Err(e) => {
                    error = e.to_string();
                    retry_in = (retry_in * 2).min(RETRY_MAX);
                }
            }
        }
        publish(match (&current, wanted) {
            (Some((name, c)), _) => Status {
                state: State::Connected,
                console: name.clone(),
                iface: c.tunnel.iface().into(),
                routes: c.routes.clone(),
                skipped: c.skipped.clone(),
                error: String::new(),
            },
            (None, Some(console)) => Status {
                state: State::Failed,
                console,
                error: error.clone(),
                ..Status::default()
            },
            (None, None) => Status::default(),
        })?;
        thread::sleep(TICK);
    }
}
