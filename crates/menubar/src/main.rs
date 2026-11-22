//! The macOS menu bar frontend. It holds no logic of its own: it reads the
//! daemon's status file and edits the same config files as the CLI, which is
//! all a WinUI 3 frontend has to do as well.

use std::process::Command;
use std::time::{Duration, Instant};
use std::{fs, io, thread};

use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

use teleport_split::platform::STATUS_FILE;
use teleport_split::{DISABLED_FILE, ROUTES_FILE, Status, config_dir, read_routes};

const REFRESH: Duration = Duration::from_secs(2);

fn main() {
    let mut event_loop = EventLoopBuilder::<MenuEvent>::with_user_event().build();
    // A menu bar app: no Dock icon, no main window.
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| drop(proxy.send_event(event))));

    let status = MenuItem::new("", false, None);
    let split = CheckMenuItem::new("Split Tunnel", true, true, None);
    let routes = MenuItem::new("Edit Routes…", true, None);
    let install = MenuItem::new("", true, None);
    let menu = Menu::new();
    menu.append_items(&[
        &status,
        &PredefinedMenuItem::separator(),
        &split,
        &routes,
        &PredefinedMenuItem::separator(),
        &install,
        &PredefinedMenuItem::quit(None),
    ])
    .expect("a new menu accepts items");

    let mut tray = None;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH);
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
            Event::UserEvent(event) => {
                let result = if event.id == *split.id() {
                    set_split(split.is_checked())
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

        let dir = config_dir();
        let installed = fs::read_to_string(STATUS_FILE).ok();
        status.set_text(match installed.as_deref().map(str::parse::<Status>) {
            None => "Helper not installed".into(),
            Some(Ok(status)) => status.summary(),
            Some(Err(())) => "Helper status is unreadable".into(),
        });
        split.set_checked(!dir.join(DISABLED_FILE).exists());
        install.set_text(if installed.is_some() {
            "Reinstall Helper…"
        } else {
            "Install Helper…"
        });
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

fn set_split(on: bool) -> io::Result<()> {
    let dir = config_dir();
    if on {
        match fs::remove_file(dir.join(DISABLED_FILE)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    } else {
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(DISABLED_FILE), "")
    }
}

fn edit_routes() -> io::Result<()> {
    let dir = config_dir();
    let file = dir.join(ROUTES_FILE);
    if !file.exists() {
        fs::create_dir_all(&dir)?;
        fs::write(&file, read_routes(&dir)?)?;
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
