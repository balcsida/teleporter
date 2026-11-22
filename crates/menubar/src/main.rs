//! The macOS menu bar frontend. It lists the account's consoles, and otherwise
//! holds no logic: it reads the helper's status file and writes the same files
//! as the CLI, which is all a WinUI 3 frontend has to do as well.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};
use std::{fs, io, thread};

use core_foundation::base::TCFType;
use core_foundation::string::{CFString, CFStringRef};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

use teleport_split::platform::STATUS_FILE;
use teleport_split::sso::{self, BrowserLogin};
use teleport_split::{CONNECT_FILE, ROUTES_FILE, ROUTES_HEADER, Status, config_dir, connect};

const REFRESH: Duration = Duration::from_secs(2);
/// How often the console list is fetched again.
const RELOAD: Duration = Duration::from_secs(120);
/// Where the console entries start: after the status line, the account line and a separator.
const CONSOLES_AT: usize = 3;
/// The link Ubiquiti's browser sign-in ends in. It belongs to WiFiman Desktop, so this app
/// only takes it over for the duration of a sign-in the user started here.
const LOGIN_SCHEME: &str = "wifiman-desktop-dl";
const WIFIMAN: &str = "ui.wifiman.desktop";
const OURSELVES: &str = "com.teleport-split-tunnel.app";
/// How long a browser sign-in may take before the link is handed back.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
/// The sign-in page may open the link more than once; repeats are swallowed for this long.
const LOGIN_GRACE: Duration = Duration::from_secs(20);

/// The sign-in link while this app holds it.
struct HeldLink {
    /// The sign-in waiting for its link; `None` once it has arrived.
    login: Option<BrowserLogin>,
    /// Who had the link before.
    previous: Option<String>,
    until: Instant,
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSCopyDefaultHandlerForURLScheme(scheme: CFStringRef) -> CFStringRef;
    fn LSSetDefaultHandlerForURLScheme(scheme: CFStringRef, bundle_id: CFStringRef) -> i32;
}

/// The bundle id of the app that opens `LOGIN_SCHEME` links.
fn link_handler() -> Option<String> {
    // SAFETY: the argument is a live CFString, and a non-null result is owned by the caller.
    unsafe {
        let handler = LSCopyDefaultHandlerForURLScheme(CFString::new(LOGIN_SCHEME).as_concrete_TypeRef());
        (!handler.is_null()).then(|| CFString::wrap_under_create_rule(handler).to_string())
    }
}

fn set_link_handler(bundle_id: &str) -> io::Result<()> {
    // SAFETY: both arguments are live CFStrings for the duration of the call.
    let status = unsafe {
        LSSetDefaultHandlerForURLScheme(
            CFString::new(LOGIN_SCHEME).as_concrete_TypeRef(),
            CFString::new(bundle_id).as_concrete_TypeRef(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("macOS refused the link handler ({status})")))
    }
}

/// Give the sign-in link back to whoever had it; WiFiman if that was nobody else.
fn release_link(previous: Option<String>) {
    let owner = previous
        .filter(|p| !p.eq_ignore_ascii_case(OURSELVES))
        .unwrap_or_else(|| WIFIMAN.into());
    let _ = set_link_handler(&owner);
}

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
    let sign_in = MenuItem::new("Sign In in Terminal…", true, None);
    let sign_in_browser = MenuItem::new("Sign In with Browser…", true, None);
    let routes = MenuItem::new("Edit Extra Routes…", true, None);
    let install = MenuItem::new("", true, None);
    let menu = Menu::new();
    menu.append_items(&[
        &status,
        &account,
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::separator(),
        &sign_in_browser,
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
    let mut held: Option<HeldLink> = None;
    // If an earlier run died mid-sign-in, the link is still ours; it is not ours to keep.
    if link_handler().is_some_and(|h| h.eq_ignore_ascii_case(OURSELVES)) {
        release_link(None);
    }
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
                } else if event.id == *sign_in_browser.id() {
                    // A sign-in already under way keeps its record of who had the link.
                    let previous = held.take().map_or_else(link_handler, |h| h.previous);
                    set_link_handler(OURSELVES)
                        .and_then(|()| BrowserLogin::start().map_err(io::Error::other))
                        .and_then(|(login, url)| {
                            let until = Instant::now() + LOGIN_TIMEOUT;
                            held = Some(HeldLink {
                                login: Some(login),
                                previous: previous.clone(),
                                until,
                            });
                            Command::new("/usr/bin/open").arg(url).status().map(drop)
                        })
                        .inspect_err(|_| release_link(previous))
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
            Event::Opened { urls } => {
                for url in urls.iter().filter(|u| u.scheme() == LOGIN_SCHEME) {
                    match &mut held {
                        Some(link) => {
                            // A repeat of a link already used is dropped, not passed on.
                            let Some(login) = link.login.take() else { continue };
                            link.until = Instant::now() + LOGIN_GRACE;
                            let (dir, link) = (dir.clone(), url.to_string());
                            thread::spawn(move || {
                                let saved = login
                                    .finish(&link, sso::load_session(&dir).ok().flatten())
                                    .and_then(|session| sso::save_session(&dir, &session).map(|()| session.user));
                                notify(&match saved {
                                    Ok(user) => format!("Signed in as {user}"),
                                    Err(e) => format!("Sign-in failed: {e}"),
                                });
                            });
                        }
                        // Not a sign-in started here: it is WiFiman's, so pass it on.
                        None => {
                            release_link(None);
                            let _ = Command::new("/usr/bin/open")
                                .args(["-b", WIFIMAN, url.as_str()])
                                .status();
                        }
                    }
                }
            }
            _ => return,
        }

        if held.as_ref().is_some_and(|link| Instant::now() >= link.until)
            && let Some(link) = held.take()
        {
            if link.login.is_some() {
                notify("Sign-in timed out");
            }
            release_link(link.previous);
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

/// A menu bar app has no window to report in, so the outcome of a sign-in is a notification.
fn notify(message: &str) {
    // The text goes into an AppleScript string literal.
    let text = message.replace(['\\', '"'], "'").replace(['\n', '\r'], " ");
    let script = format!("display notification \"{text}\" with title \"Teleport Split Tunnel\"");
    if Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .status()
        .is_err()
    {
        eprintln!("teleport-split-menubar: {message}");
    }
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
