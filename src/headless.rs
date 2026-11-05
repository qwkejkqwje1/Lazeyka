//! Development only (cargo feature `headless`): runs the real UI with an off-screen
//! software renderer, driven by a command file, to test whole flows without a display.
//!
//! LAZEYKA_HEADLESS=/tmp/cmd — the file is polled, executed and removed. Commands:
//!   shot FILE.png | click X Y | scroll X Y DY | type TEXT | enter | wait MS | quit

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{EventLoopProxy, Key, Platform, PointerEventButton, WindowAdapter, WindowEvent};
use slint::{EventLoopError, LogicalPosition, PhysicalSize, PlatformError, Rgb8Pixel};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Job = Box<dyn FnOnce() + Send>;
type Queue = Arc<Mutex<Vec<Job>>>;

struct Proxy {
    q: Queue,
    quit: Arc<AtomicBool>,
}

impl EventLoopProxy for Proxy {
    fn quit_event_loop(&self) -> Result<(), EventLoopError> {
        self.quit.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn invoke_from_event_loop(&self, e: Job) -> Result<(), EventLoopError> {
        self.q.lock().unwrap().push(e);
        Ok(())
    }
}

struct Headless {
    window: Rc<MinimalSoftwareWindow>,
    start: Instant,
    q: Queue,
    quit: Arc<AtomicBool>,
    cmd: String,
    size: (u32, u32),
}

impl Headless {
    fn pump(&self) {
        let jobs: Vec<Job> = std::mem::take(&mut *self.q.lock().unwrap());
        for j in jobs {
            j();
        }
        slint::platform::update_timers_and_animations();
    }

    fn wait(&self, ms: u64) {
        let until = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < until && !self.quit.load(Ordering::SeqCst) {
            self.pump();
            std::thread::sleep(Duration::from_millis(8));
        }
    }

    fn shot(&self, path: &str) {
        let (w, h) = self.size;
        let mut buf = vec![Rgb8Pixel::default(); (w * h) as usize];
        self.window.request_redraw();
        self.window.draw_if_needed(|r| {
            r.render(&mut buf, w as usize);
        });
        let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
        for p in &buf {
            ppm.extend_from_slice(&[p.r, p.g, p.b]);
        }
        let tmp = format!("{path}.ppm");
        if std::fs::write(&tmp, ppm).is_ok() {
            let _ = std::process::Command::new("magick").arg(&tmp).arg(path).status();
            let _ = std::fs::remove_file(&tmp);
        }
    }

    fn exec(&self, line: &str) {
        let mut it = line.splitn(2, ' ');
        let (cmd, rest) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
        let nums: Vec<f32> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        let w = &self.window;
        match cmd {
            "shot" => self.shot(rest),
            "click" if nums.len() >= 2 => {
                let p = LogicalPosition::new(nums[0], nums[1]);
                w.dispatch_event(WindowEvent::PointerMoved { position: p });
                self.wait(30);
                w.dispatch_event(WindowEvent::PointerPressed { position: p, button: PointerEventButton::Left });
                self.wait(30);
                w.dispatch_event(WindowEvent::PointerReleased { position: p, button: PointerEventButton::Left });
                self.wait(60);
            }
            "move" if nums.len() >= 2 => {
                w.dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(nums[0], nums[1]) });
                self.wait(60);
            }
            "scroll" if nums.len() >= 3 => {
                let p = LogicalPosition::new(nums[0], nums[1]);
                w.dispatch_event(WindowEvent::PointerMoved { position: p });
                w.dispatch_event(WindowEvent::PointerScrolled { position: p, delta_x: 0.0, delta_y: nums[2] });
                self.wait(150);
            }
            "type" => {
                for c in rest.chars() {
                    let t: slint::SharedString = c.to_string().into();
                    w.dispatch_event(WindowEvent::KeyPressed { text: t.clone() });
                    w.dispatch_event(WindowEvent::KeyReleased { text: t });
                }
                self.wait(60);
            }
            "enter" => {
                let t: slint::SharedString = Key::Return.into();
                w.dispatch_event(WindowEvent::KeyPressed { text: t.clone() });
                w.dispatch_event(WindowEvent::KeyReleased { text: t });
                self.wait(60);
            }
            "wait" => self.wait(nums.first().copied().unwrap_or(500.0) as u64),
            "quit" => self.quit.store(true, Ordering::SeqCst),
            _ => eprintln!("headless: unknown command {line:?}"),
        }
    }
}

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }
    fn duration_since_start(&self) -> Duration {
        self.start.elapsed()
    }
    fn new_event_loop_proxy(&self) -> Option<Box<dyn EventLoopProxy>> {
        Some(Box::new(Proxy { q: self.q.clone(), quit: self.quit.clone() }))
    }
    fn run_event_loop(&self) -> Result<(), PlatformError> {
        while !self.quit.load(Ordering::SeqCst) {
            self.pump();
            if let Ok(text) = std::fs::read_to_string(&self.cmd) {
                let _ = std::fs::remove_file(&self.cmd);
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    self.exec(line);
                }
                let _ = std::fs::write(format!("{}.done", self.cmd), "");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

/// Installs the headless platform when LAZEYKA_HEADLESS is set. Returns true if active.
pub fn install() -> bool {
    let Ok(cmd) = std::env::var("LAZEYKA_HEADLESS") else { return false };
    let scale: f32 = std::env::var("LAZEYKA_SCALE").ok().and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    let size = ((400.0 * scale) as u32, (700.0 * scale) as u32);
    let p = Headless {
        window: window.clone(),
        start: Instant::now(),
        q: Arc::new(Mutex::new(Vec::new())),
        quit: Arc::new(AtomicBool::new(false)),
        cmd,
        size,
    };
    if slint::platform::set_platform(Box::new(p)).is_err() {
        return false;
    }
    window.dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor: scale });
    window.set_size(PhysicalSize::new(size.0, size.1));
    true
}
