//! The macOS menu bar frontend. It lists the account's consoles, and otherwise
//! holds no logic: it reads the helper's status file and writes the same files
//! as the CLI, which is all a WinUI 3 frontend has to do as well.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};
use std::{fs, io, thread};

use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

use teleport_split::platform::STATUS_FILE;
use teleport_split::{CONNECT_FILE, ROUTES_FILE, ROUTES_HEADER, Status, config_dir, connect};

const REFRESH: Duration = Duration::from_secs(2);
/// How often the console list is fetched again.
const RELOAD: Duration = Duration::from_secs(120);
/// Where the console entries start: after the status line, the account line and a separator.
const CONSOLES_AT: usize = 3;

enum AppEvent {
    Menu(MenuEvent),
    /// The account's console names, or why they could not be listed.
    Consoles(Result<Vec<String>, String>),
}

fn main() {
    let mut event_loop = EventLoopBuilder::<AppEvent>::with_user_event().build();
    // A menu bar app: no Dock icon, no main window.
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    let proxy = event_loop.create_proxy();
    let menu_proxy = proxy.clone();
    MenuEvent::set_event_handler(Some(move |event| drop(menu_proxy.send_event(AppEvent::Menu(event)))));

    let status = MenuItem::new("", false, None);
    let account = MenuItem::new("Loading consoles…", false, None);
    let sign_in = MenuItem::new("Sign In…", true, None);
    let routes = MenuItem::new("Edit Extra Routes…", true, None);
    let install = MenuItem::new("", true, None);
    let menu = Menu::new();
    menu.append_items(&[
        &status,
        &account,
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::separator(),
        &sign_in,
        &routes,
        &install,
        &PredefinedMenuItem::quit(None),
    ])
    .expect("a new menu accepts items");

    let mut tray = None;
    let mut consoles: Vec<CheckMenuItem> = Vec::new();
    let mut session_seen = None;
    let mut loaded = Instant::now();
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH);
        let dir = config_dir();
        match event {
            // The tray icon may only be created once the event loop runs.
            Event::NewEvents(_) if tray.is_none() => {
                let icon = TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_icon_templated(icon())
                    .with_tooltip("Teleport Split Tunnel");
                tray = Some(icon.build().expect("the menu bar accepts an icon"));
            }
            Event::NewEvents(_) => {}
            Event::UserEvent(AppEvent::Consoles(found)) => {
                for item in consoles.drain(..) {
                    let _ = menu.remove(&item);
                }
                match found {
                    Ok(names) => {
                        account.set_text(if names.is_empty() {
                            "No consoles on this account"
                        } else {
                            "Consoles"
                        });
                        consoles = names
                            .iter()
                            .map(|name| CheckMenuItem::new(name, true, false, None))
                            .collect();
                        for (i, item) in consoles.iter().enumerate() {
                            let _ = menu.insert(item, CONSOLES_AT + i);
                        }
                    }
                    Err(e) => account.set_text(e),
                }
            }
            Event::UserEvent(AppEvent::Menu(event)) => {
                let result = if let Some(console) = consoles.iter().find(|c| *c.id() == event.id) {
                    // muda has already flipped the check mark: checked means "connect to this one".
                    if console.is_checked() {
                        fs::create_dir_all(&dir).and_then(|()| fs::write(dir.join(CONNECT_FILE), console.text()))
                    } else {
                        fs::remove_file(dir.join(CONNECT_FILE))
                    }
                } else if event.id == *sign_in.id() {
                    sign_in_terminal()
                } else if event.id == *routes.id() {
                    edit_routes()
                } else if event.id == *install.id() {
                    install_helper()
                } else {
                    Ok(())
                };
                if let Err(e) = result {
                    eprintln!("teleport-split-menubar: {e}");
                }
            }
            _ => return,
        }

        // A new session file means someone signed in (or out). Otherwise the list is only
        // refreshed now and then, which also retries after a failure.
        let session = fs::metadata(dir.join("session.json")).and_then(|m| m.modified()).ok();
        if session_seen != Some(session) || loaded.elapsed() >= RELOAD {
            session_seen = Some(session);
            loaded = Instant::now();
            load_consoles(proxy.clone());
        }
        let installed = fs::read_to_string(STATUS_FILE).ok();
        status.set_text(match installed.as_deref().map(str::parse::<Status>) {
            None => "Helper not installed".into(),
            Some(Ok(status)) => status.summary(),
            Some(Err(())) => "Helper status is unreadable".into(),
        });
        let wanted = fs::read_to_string(dir.join(CONNECT_FILE)).unwrap_or_default();
        for console in &consoles {
            console.set_checked(console.text() == wanted.trim());
        }
        install.set_text(if installed.is_some() {
            "Reinstall Helper…"
        } else {
            "Install Helper…"
        });
    });
}

/// List the consoles off the main thread; the answer comes back as an event.
fn load_consoles(proxy: EventLoopProxy<AppEvent>) {
    thread::spawn(move || {
        let found = connect::consoles(&config_dir())
            .map(|consoles| consoles.into_iter().map(|c| c.name).collect())
            .map_err(|e| e.to_string());
        let _ = proxy.send_event(AppEvent::Consoles(found));
    });
}

/// A fork: one path in, two out. Drawn as alpha only, since macOS tints
/// template images to match the menu bar.
fn icon() -> Icon {
    const SIZE: u32 = 44;
    const STROKES: [[f32; 4]; 3] = [
        [5.0, 22.0, 19.0, 22.0],
        [19.0, 22.0, 39.0, 9.0],
        [19.0, 22.0, 39.0, 35.0],
    ];
    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    for (i, pixel) in rgba.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let (x, y) = ((i as u32 % SIZE) as f32 + 0.5, (i as u32 / SIZE) as f32 + 0.5);
        let distance = STROKES
            .iter()
            .map(|&[ax, ay, bx, by]| {
                let (dx, dy) = (bx - ax, by - ay);
                let t = (((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
                (x - ax - t * dx).hypot(y - ay - t * dy)
            })
            .fold(f32::MAX, f32::min);
        // A 6 px stroke with a 1 px soft edge.
        pixel[3] = ((3.5 - distance).clamp(0.0, 1.0) * 255.0) as u8;
    }
    Icon::from_rgba(rgba, SIZE, SIZE).expect("the buffer matches its dimensions")
}

/// Signing in needs a password and a second factor, so it happens in a
/// terminal: a `.command` file is something Terminal runs when opened.
fn sign_in_terminal() -> io::Result<()> {
    let cli = std::env::current_exe()?.with_file_name("teleport-split");
    let dir = config_dir();
    let script = dir.join("login.command");
    fs::create_dir_all(&dir)?;
    let quoted = cli.display().to_string().replace('\'', "'\\''");
    fs::write(&script, format!("#!/bin/sh\nexec '{quoted}' login\n"))?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    Command::new("/usr/bin/open").arg(script).status().map(drop)
}

fn edit_routes() -> io::Result<()> {
    let dir = config_dir();
    let file = dir.join(ROUTES_FILE);
    if !file.exists() {
        fs::create_dir_all(&dir)?;
        fs::write(&file, ROUTES_HEADER)?;
    }
    Command::new("/usr/bin/open").arg("-t").arg(file).status().map(drop)
}

/// Run `teleport-split install` as root, behind the system password prompt.
fn install_helper() -> io::Result<()> {
    let cli = std::env::current_exe()?.with_file_name("teleport-split");
    if !cli.exists() {
        return Err(io::Error::other(format!("{} is missing", cli.display())));
    }
    let literal = |s: &std::path::Path| {
        format!(
            "\"{}\"",
            s.display().to_string().replace('\\', "\\\\").replace('"', "\\\"")
        )
    };
    let script = format!(
        "do shell script quoted form of {} & \" install --config \" & quoted form of {} with administrator privileges",
        literal(&cli),
        literal(&config_dir())
    );
    let mut osascript = Command::new("/usr/bin/osascript").args(["-e", &script]).spawn()?;
    // The prompt can stay open for a long time; do not block the menu on it.
    thread::spawn(move || drop(osascript.wait()));
    Ok(())
}
