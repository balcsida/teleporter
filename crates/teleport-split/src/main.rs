use std::fs;
use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use teleport_split::platform::{self, STATUS_FILE, System};
use teleport_split::{Applied, Config, DISABLED_FILE, Entry, ROUTES_FILE, Status};
use teleport_split::{config_dir, parse_config, read_routes, reconcile};

const USAGE: &str = "\
Split tunneling for UniFi Teleport (WiFiman).

Usage:
  teleport-split status            Show what the helper is doing
  teleport-split list              Show the destinations routed through Teleport
  teleport-split add <dest>...     Route a network, address or host name through Teleport
  teleport-split remove <dest>...  Stop routing it through Teleport
  teleport-split on                Split tunnel: only listed destinations use Teleport
  teleport-split off               Full tunnel: everything uses Teleport, as WiFiman does
  sudo teleport-split install      Install and start the helper
  sudo teleport-split uninstall    Remove it and restore the full tunnel
";

/// How often the daemon looks for changes to the config files.
const TICK: Duration = Duration::from_secs(3);
/// How often host names are resolved again.
const REFRESH: Duration = Duration::from_secs(60);
/// Route changes arrive in bursts; wait for the burst to end.
const DEBOUNCE: Duration = Duration::from_millis(300);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["status"] => status(),
        ["list"] => list(),
        ["add", entries @ ..] if !entries.is_empty() => edit(entries, true),
        ["remove", entries @ ..] if !entries.is_empty() => edit(entries, false),
        ["on"] => set_split(true),
        ["off"] => set_split(false),
        ["install"] => install(&config_dir()),
        ["install", "--config", dir] => install(Path::new(dir)),
        ["uninstall"] => uninstall(),
        ["daemon", "--config", dir] => daemon(Path::new(dir)),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("teleport-split: {e} (this command needs sudo)");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("teleport-split: {e}");
            ExitCode::FAILURE
        }
    }
}

fn status() -> io::Result<()> {
    let text = match fs::read_to_string(STATUS_FILE) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("The helper is not installed. Run: sudo teleport-split install");
            return Ok(());
        }
        other => other?,
    };
    let status: Status = text
        .parse()
        .map_err(|()| io::Error::other(format!("{STATUS_FILE} is malformed")))?;
    println!("{}", status.summary());
    for route in &status.routes {
        println!("  via Teleport  {route}");
    }
    for route in &status.failed {
        println!("  failed        {route}");
    }
    for line in &status.bad_lines {
        println!("  ignored       {ROUTES_FILE} line {line}");
    }
    if config_dir().join(DISABLED_FILE).exists() {
        println!("Split tunneling is off. Run: teleport-split on");
    }
    Ok(())
}

fn list() -> io::Result<()> {
    for entry in parse_config(&read_routes(&config_dir())?).entries {
        println!("{entry}");
    }
    Ok(())
}

fn edit(entries: &[&str], add: bool) -> io::Result<()> {
    let wanted = entries
        .iter()
        .map(|e| {
            e.parse::<Entry>()
                .map_err(|()| io::Error::other(format!("not a network, address or host name: {e}")))
        })
        .collect::<io::Result<Vec<Entry>>>()?;
    let dir = config_dir();
    let mut lines: Vec<String> = read_routes(&dir)?.lines().map(str::to_string).collect();
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
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(ROUTES_FILE), lines.join("\n") + "\n")
}

fn set_split(on: bool) -> io::Result<()> {
    let dir = config_dir();
    let marker = dir.join(DISABLED_FILE);
    if on {
        match fs::remove_file(marker) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    } else {
        fs::create_dir_all(&dir)?;
        fs::write(marker, "")?;
    }
    Ok(())
}

fn install(config_dir: &Path) -> io::Result<()> {
    platform::install(config_dir)?;
    println!("Helper installed. It reads {}", config_dir.join(ROUTES_FILE).display());
    Ok(())
}

fn uninstall() -> io::Result<()> {
    platform::uninstall()?;
    // Hand a connected tunnel back the way WiFiman set it up.
    reconcile(&mut System, &Config::default(), false, &mut Applied::default());
    println!("Helper removed.");
    Ok(())
}

fn daemon(dir: &Path) -> io::Result<()> {
    let (tx, rx) = mpsc::channel();
    platform::watch_routes(tx);

    let mut applied = Applied::default();
    let mut config = Config::default();
    let mut seen = None;
    let mut written = String::new();
    let mut refreshed = Instant::now();
    let mut woke = true;
    loop {
        let routes = dir.join(ROUTES_FILE);
        let split = !dir.join(DISABLED_FILE).exists();
        let stamp = Some((fs::metadata(&routes).and_then(|m| m.modified()).ok(), split));
        if woke || stamp != seen || refreshed.elapsed() >= REFRESH {
            // An unreadable file keeps the last good config instead of dropping every route.
            if let Ok(text) = read_routes(dir) {
                config = parse_config(&text);
            }
            let status = reconcile(&mut System, &config, split, &mut applied).to_string();
            if status != written {
                eprintln!("{}", status.trim_end().replace('\n', " "));
                // Rename into place so a reader never sees half a file.
                let tmp = format!("{STATUS_FILE}.tmp");
                fs::write(&tmp, &status)?;
                fs::rename(&tmp, STATUS_FILE)?;
                written = status;
            }
            seen = stamp;
            refreshed = Instant::now();
        }
        woke = match rx.recv_timeout(TICK) {
            Ok(()) => {
                thread::sleep(DEBOUNCE);
                while rx.try_recv().is_ok() {}
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
            // The route monitor died: fall back to the periodic refresh.
            Err(RecvTimeoutError::Disconnected) => {
                thread::sleep(TICK);
                false
            }
        };
    }
}
