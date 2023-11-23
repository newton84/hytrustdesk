use std::{
    collections::HashMap,
    iter::FromIterator,
    process::Child,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;
#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
    static ref CHILDREN : Children = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        let children: Children = Default::default();
        std::thread::spawn(move || check_zombie(children));
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        // frame.register_behavior("connection-manager", move || {
        //     Box::new(cm::SciterConnectionManager::new())
        // });
        // page = "cm.html"; //不显示连接管理窗口
        log::error!("Wrong command: {:?}", args);
        return;
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers()
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(id)
    }

    fn get_hostname(&self) -> String {
        get_hostname()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_hostname();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

pub fn check_zombie(children: Children) {
    let mut deads = Vec::new();
    loop {
        let mut lock = children.lock().unwrap();
        let mut n = 0;
        for (id, c) in lock.1.iter_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                deads.push(id.clone());
                n += 1;
            }
        }
        for ref id in deads.drain(..) {
            lock.1.remove(id);
        }
        if n > 0 {
            lock.0 = true;
        }
        drop(lock);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

#[inline]
pub fn new_remote(id: String, remote_type: String, force_relay: bool) {
    let mut lock = CHILDREN.lock().unwrap();
    let mut args = vec![format!("--{}", remote_type), id.clone()];
    if force_relay {
        args.push("".to_string()); // password
        args.push("--relay".to_string());
    }
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                return;
            }
        }
    }
    match crate::run_me(args) {
        Ok(child) => {
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
}

#[inline]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        //"data:image/png;base64,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".into()
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAAsTAAALEwEAmpwYAAAGGmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgOS4wLWMwMDEgNzkuYzAyMDRiMiwgMjAyMy8wMi8wOS0wNjoyNjoxNCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25zLmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIDI0LjYgKDIwMjMwNTIwLm0uMjE4MSA0ZTAyNDVmKSAgKFdpbmRvd3MpIiB4bXA6Q3JlYXRlRGF0ZT0iMjAyMy0xMS0yM1QxMDozNToxMSswODowMCIgeG1wOk1vZGlmeURhdGU9IjIwMjMtMTEtMjNUMTQ6MDc6MjYrMDg6MDAiIHhtcDpNZXRhZGF0YURhdGU9IjIwMjMtMTEtMjNUMTQ6MDc6MjYrMDg6MDAiIGRjOmZvcm1hdD0iaW1hZ2UvcG5nIiBwaG90b3Nob3A6Q29sb3JNb2RlPSIzIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjM0ZDJkMzU5LTAyNGMtYmY0MC05N2ZiLTRmMzNhOTI4NzZhNiIgeG1wTU06RG9jdW1lbnRJRD0iYWRvYmU6ZG9jaWQ6cGhvdG9zaG9wOjRmMjc2NzQwLWMyOGYtMGY0Ni05N2RhLWYzM2UzMjcyZTk1NCIgeG1wTU06T3JpZ2luYWxEb2N1bWVudElEPSJ4bXAuZGlkOjQzMzlkOWI5LTFjNzgtNWM0Ny1hZTI1LTY5ODBlMzVkOWU1MyI+IDx4bXBNTTpIaXN0b3J5PiA8cmRmOlNlcT4gPHJkZjpsaSBzdEV2dDphY3Rpb249ImNyZWF0ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NDMzOWQ5YjktMWM3OC01YzQ3LWFlMjUtNjk4MGUzNWQ5ZTUzIiBzdEV2dDp3aGVuPSIyMDIzLTExLTIzVDEwOjM1OjExKzA4OjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgMjQuNiAoMjAyMzA1MjAubS4yMTgxIDRlMDI0NWYpICAoV2luZG93cykiLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjM0ZDJkMzU5LTAyNGMtYmY0MC05N2ZiLTRmMzNhOTI4NzZhNiIgc3RFdnQ6d2hlbj0iMjAyMy0xMS0yM1QxNDowNzoyNiswODowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIDI0LjYgKDIwMjMwNTIwLm0uMjE4MSA0ZTAyNDVmKSAgKFdpbmRvd3MpIiBzdEV2dDpjaGFuZ2VkPSIvIi8+IDwvcmRmOlNlcT4gPC94bXBNTTpIaXN0b3J5PiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/Pkp3JB0AACAYSURBVHic7Z15lCRHfec/EXnU0fcx3dMzmlvXSOhCEiOBjQSC1cpG5nxiwTaYh/F68a533y62d7nkFZhd3rK28VssHuyiZyHAMpYwQkK7WDLg0YEuQAfoGElzaDRXd0/fdWZm7B+R1ZVVlVmVVZ3V0yPN973qroqI/OXxjfjF7xcR+QuBUizjacCAnUOw4WdQ7IfjX4b1g7DuP8PU85w7Os0VB/Nc0m+obZ7DMII04FEP1ZASDhX6tT05qunP9mRFlFNN8tqW0TIxdhkpEU4ephc9Dg9Y/LQ/xW5Z4oHpPjjvPnikD9x/AeIwbN0Hj/XD/g8BphZghkkVgCuhWITRbaAG+N3SI3zYmFGXTRkwKiFfBiE7uJm6cg2HJPmA48pqJm+FMhqyVnB/1TyxnF1WkAUGBeQcrlvMg9PDc6lFbplL8yWlOK4MkBHy6ikEAY6EjAPWNNeOXKR+kdqmvrowoy4TFpgGFESAfBX4tLoh/9NwSAcymh4aR1bIwcGfqkMZkVkd3l8VAqX8TyBVCnAE5CrHm2DlOZMCNxzaxAt94/x7IwflNIhGPV2nATwgDSUBAwfVF0WWP1wyQCgw7LoLjQNV8y80L66Mlod2KK+h4nQgIzRrxbJETe8cV4YAkLoCyxSDlsdfqkNck5Nc59jM1x9aWwE2QN/9cHaPumPR5FpXaPKbX2j4xaxl0muSElDxJ5r0CFEoF4qAucDV/S6P08Mu1+VYUO+bvM//koKzf09x2oK6Izslrl3IgPRinChwMWuZ9I5aepOya5L0SrE6jeAZICRbKfAYJmcjWarmjyqQ0Au89z/xPyYvUB/LT+u+Jc7FrBnSW8l6Baj3psWaGo36n1kE9xweeuAhLiv8vU6XTAJH4bx/VpdNjaiPFSebkF8x4gKGXH1e4oZcqxtrJmsF19SQtWJZASNuRcZgoJiqfuLIKGegZ45dFx7hT/gZ8HO/KvZNKX79VvXCzIjY3nDSUy19BbJOTEtvijIMKtj9RsanzuaYHDgG5z4i3lWyAuSfaukndUtvdi5lQD4POw7zpyM2iIueUWzcrX5SzrIrUkaMmuUpcL3Gi0xSc7TdMluUbSZPCjCkHihprWHWYEsPlAupo2TLlB8+zqC5+UG2LfWzSzrtn8AQsFCEqSUwpKLHAoHCC2qSOMKaqfWVPFiF7xg3kRf8Lar/Si4sFsGSgokBgWWI6n2dbISHJBoGVq/Nu8zJQ+qq4fOhNBf/JALdQg7OQX8KPnAhXDwhGMyAEALPqzsg5oUvQzTJWwVIAY4DL80q7t3j8YNnXQZ7DUb7DFxPIGJ6SK3QddKjMhSoFPSbvMVc3CkunJhUlOyQghFCpIS9s7BzFD7/FsEZw82usNXTWru4fAtcd4HB3/0MPnFHiXLBZHzYwlMg612ltU56HfLzMLCO88z1rtqy0DgjEKmWpYAji7BlAP7P2wVDKSh44KqTmepwKCBrwHUXWfTZHh+6KUfWypDJmGBKZMNsWIScNUJ6jUuYAmuBTVLk6VdWoEALy91xoVCCP3q9Jj/nagPwlUY+6HvKuXrG7ZpzU7z3QsGzLy7gFMp4ZQ/lRT/1RC13FVF8BR6UUOBKeqQSKi28xgI1xwQSZgtw4QRcua2a9UqGAIq+TfOeS1LIQoHFhQJu2W2oAGuVdNWYVPnhmpW00BOFYKkM24fAAEqv0JZfj4qi3zFhsaHXZfZ4kXTaQpoGSIGIsgrbVMtJqffIQ0ISTdWiQAM86PG7jNiuUIcwBKRCutmSAidkbrvbkAKE51EslnFKLlbaw7CM2kInAelBmO0aIQLlE59821eAKSElatOOFyHngC1hKA22ANt/7kUPnFXSRK4HjuPhuS7K1TaA8hSi5cwZrUnvcFyhbVl1eaFLwpoJ8qA6ICJanCwmFJpcy3+Oe+fh3gPw8BF4cRYmc1B0deUYSsPWfrh4HK7ZBmcNQQptrCm6XxGUpz+ep/SDiPmwOyY9okzcLrtVXmMFiHD/lr9EGTkdoCKmx2/N9x2Crz4BP9gHR/y1K6YFKVN3B0rBnhm47wDc8jjc0AfvPAM+vgt2DGh5S27YOrckUbX0WpG6VkkPZptRhVXDl2ThAWkJpoCXFuHju+EbT4MqwWAfbB6KVjCVVj5fgq89Cn//LHzujfAHF0CvAYvdrASBCxKqMT1J0leq3ptm+z/M0BrbZePOQxMFcOtz8Af3wPQcjA1Ctr/axURdRiW9z4bBcTi6BP/2LnjwENx8jZaddyHjnyPvdWesouI+nWykByEr6bGnQeMuE2tyeIX8Tz8A/+o2WCjB9jHImAH7IiZcD8aysGEEvvFT2PVNmClq8h89Bk9MQ0bGWOHUDipdIXU+dAc+euRhzWQ1yVP12VFl/TQzVn+ekEbwFGR9q+M//Ai+eB+MDEO/rd06pfSQcqUSCOFPy7Ygz1NgGbB1HB7dD++/C/7lNvjUfbBUgn94J1y7XRuKiSJuo1kDLT0qPdoLSLgbqFj6Evhvj2jyx0c1uUeWIO/o72kTLL/FugoKDhQdTfBwRueHVdrKyNn2Mdh9EP7vizCShYU8fPs5XQEMX2biCDNW1jDpQdRWgBgn7PT5CXQF+MFL8PF7gLTuu4fS8Nr1sHMENvfDaBb6LO3yFV04nodDi/DUJDx8GI4uwGgP9Nrh3YXj6YoylNaET9sw0RPr9laOLpMe2wuIK0PFGAiq6eNaCG+GjAGHluDdtwMFuGQzvHETXLYRzhmF0YwmzPG7AZTuAkyp0+eL8PgxuPMFuO0Z2D8Pm/p0mXqNIPDT/d8jaf2/XfsiNupGJdca6Q3ZgR+hXUAD6QlAAH/7rJ5e/ey74E2bYVO/VvEzBXh5ofm9pQxdWa7cAu8+Cz5zPzz4Emzs191DGLnKP3F/Ktl7abS0mjyulbbSDmXUZDcpZ9aUiUt6B5Wj6MH7zoa3nwEDGZjKwQuzOq9i49XPgAmqrbnkwsF5bRu8bgK+8Rvw2fvhu3t0eTPE8fcUYMBgkhUgjvUe49imWUnYBTGNe7k8fRnXG+iAfIVeYDmQ1otHXpjRs4qg3biiCyVPa1Lpq33TNwQ9qvmV0z97HNZn4ZNv0B5ErhxxXqUNyoEEK0Ak6VHPpkleTVaHMmqy43gldWU68ALad6ht36B7elYbaRUDT6B9/15L/09ViPeP86h6AgtlmCtrTTCagX3z8LF/gqk8DKbDz+sp3XX0NVvu1glCuoCG/CaHtirTLD+2pmhVLrQCNBUo/CFw1fZcgCHgSE67eqaEsgdDKRhOafJTsmrMhXUBQzaMKVgsw3RRv5r+X34E338GNo2ELN32UfbHFhKtACvp09cI6cGvLbyANpY/R8CWuvUezevf/RaMZ2DA1hWj7Gn13goCre6HbJgpwwMHAaUHeor+sjTHq/XzvXm4aEd1oihRtNACa5n0IEK6gJWTHoQU8PKSJvmMfhjz3b2ip8mPC4XuCnpMGLTgIxfBjT/1K0Uaemy9UKXysQ1tJ3zgHK1lEhsFbNEX135pIqNV8koNchVPhFlRtLGHhNuoHAJNfI8FO9Mwlta/S15nEzO2oe2A5+fh/efAVZu1rIGUnjJOGdroqxiTWzP6uEW32p0kjRojrlXBVlkJtPTY9FRsAKVaPJYVaAOFVs0bsvrh5/1W2CkRhoBjeW0LGALGe3UfX3C1cVh0qnMHI2m9dMz1ujM13NJyp0k6yZIeW0xIoXAvIMEuQNCeqm8GD93CFbDk6L7fllVLP23oEceUqVcXlX3XclUXrnabdD+93ZYelWfGKhg8ps1uIEmUvaoN4So9s5gxdSWoDAR5SudVDMskyTcMgeHH31lGi+exFkkPFom3KLSdk3cRntLkbwhM7ngeuGht0G0opbsaKWi6LmItkh6VHTkQFGkUnsCaINCVYDXIDqJyy88fLHLgUIkNp9n6XQDRWOZkID2ImgqQVECDVxI8pV1PgBvvmMIpKlK2HrlafhwnGenBQq1XBJ0AsoUfnKHdt8STXvUFUBlE/NKd03zr7hkmtvQgDQNp6JdDRade1AkkPYiuewFxoWh8KWQt4Nisw1/cPsV///pR+kdT9PbYGLaFYZkIQ4b7mKtsyLUtI6gBYp0wWKYLBqGHfjdAAA8/n+f23XMcOl5GSokhIXFHLsYNWKZgKedy/9M59r5YZHRDhqHBFEbaxs7YGLaJNCQCkUwLbXVdCZIe/NnaC6g7cdLkK/zJIOCGbx3l+v99RM8ZZ02wTR2Nos7gaikwqu+IW8kr/w3BcJ/J6edmMEwDwzaxMynstI1pmk1fCl1rpLfnBUSduAtGoCH0oM2Ndx/n+s+/RM/2LGM7Upi2jWlbGKaB8N/A7ei0rVy1JmWo1DshkKaBaZmYlolhaRugpgKcRKQHCzR0AaGkdxFpCdNLLn92yxHk+jTj69JYmTSprG5pwjTIO4K8o6+lrdcR67VB5diYmmD5UCGQQiA8iXQkwpPxK2RcdzpYgUR0meDXjKUnwZaz4lTCugJm6EGrbAQ+uifPy8fKbNiQxbRtUj1pevvTLHoW0wXJ5kHY3qvAA69ZHLqQ667PbtqTRN63WF6bpv8pVFzfL659UH9hTY6r2J2H5hR7DsPEoKQvI4gcHmkiqxofoA1ftmWUrDYxu+iClFiWiZW2yWRtJosW6bTJp6+Ga3bCul7f744ViLAxu+1LFvU/dPURcU4aE0Ep7VxfZZ3kwRnBbY+5/K97iyzlDcaHTLxWbmndiduOD9CNuQApBMKQCMPAsEwWHJN0SnLT+wQXb6ovfaL8RBHx/cRhxxj88TUmF2z0+MCXc6REit4eSz/L+lYaoR2bz5QGjL7KV09ArqylJfW+nRAKIQRCSqQhObYk+OivhpF/CmG4+nybj14heW7fIk6xjKq8ZxditNcnNVaAENKDlafHEjw/6U/NkpAy8N08ISBfFmweFFx77tpoZScLfufKFMNmidmZPE6xjBdYG9fAYyBB1hAeQXrwoKEMPLpfcc9zer41CZpsUyAQCAW5Epw2qFjfn4DgVxHGBk3WZR1mZwuUy2Vcx8MLBrEII1YFXw8PkxpykGVA1hZ89i6H6Zwia+i0TjRB8OLcoo61oxRIg64HoHqlwXEUTqlMuVj2Q9i51SnrMHfST6vdTUzRRAXoNM+DiQHBgRl491/neWxfGQs9lJtt81MJDfNX35nCSkkMQyKkwHO79BbvKxieAtdRKNfFcz0dwyjYiiJ4jT0UHISrBNvGLfYe9rjuS0tcsxMuO92gPy0oO171vGGy/T4jZQpyeY+b7pnh3seW2La1F7k86pdwQIdXA3xPtRK5DE+/vyFCOAgmtT0buMytB1vGLGbn4JuPLHHTjxZRxRJuyfFrH7U6PjhqqnRUccdVmIZg+7Ze7JSNlbIwhIGQIW7MKcSDHixp4DBqsC8ySFTowTUjFwKFpK/P4qytvRRyNuVCCdfRKqhVgGSFdv1MQyCkwExZ2OkUhmMipVwjnvZJhECDi+zJQziJ7ALijBAKhCbLNskaEjdjafJdhQpeTVMIpNQDQYZlYOR16z9VAdpH9amHrVULPaBuSVicg+ryhR/FwZASYRp6qHa56gVUUehYt6iRI6RAGGtlnG118eePwNXb4dyRFQqKYcgHYaqQxEjBkcl6IEdWwnI0YzBG5VKrv5r/hOKP/hm+cDsMfySBChCGJs+8uRfQqnsIKxOH/JDpzhPp9x/Nwd/8QscdePvp8Bs7Vu/cn3sIvvBDyG6DS9cnKLiJFoj2AjoxBlsWDslq5iauIp6dga88Abc+Cy9PAx587WH4yjvgI+d1//zXPwA3/BiMPtg6BFsHViiwmeqvJLc7DpAY6e3IaNWNrBC7X4abnoLvPA+z89DXC1vX6VPum4dP3w+/ubMa07Ab+Nf/CF95GMaGdTDsrQPV5edJoKEuRDz76CBRTQ4KLxyRtUIZSeL2PXDTL+DuveAWYbhfE6+UH0rWX562vqd7A1GHF+H934cfPQ8To/p9xmNesuq/hr+oZ1szDlB/UOwzRGStlPQEtUCuDH/zS93HP3RQp63vh3SfJr0mupiCUgE+cr4mJmnctgc+ei8cm4UtYzptrggbB+Dyjf5r7SuQvzz+E9MDgAS8gJqsNtzHqPzlm1gh+ZN53b/f8jQ8cwSw4bRB/e5BA/E+ZoowMaLVf5KYysOf7Iav/RxMG7av09FMpIDjS/Cec+G8dfo192zSFa8Fbx15ATVZCZAe/JpEb3DHC/Bbd8JCDlJZ2DxSjUHULFjk/BJ88jIdviYJOB7c+Dj8z0dh/xSMD2m7orLdTcnV+yH82g79JlQi3KuI7/VJ9V1As4OiDo51ES3yI4uuoAs4moOFWdi8obqar5WbqQCM1oGpY51/Cb75jO56Hn8Z0hnYtq766jro1n9oAd6yDd68BY7nYHylXkAEmvHWci5g1UlPQA2850z4zAaYLcYPEinQUUc/8xP44QF4q++X71ofr18+tKi3uLl7L/y/fbB/Gsy01j6VwNdBFBytlT74Gl3puqH5lx9luwNBiZCumv6MJ6NDDKXg9RNw69P6e9xT2BKUCXe+CHc+D/0ZOHcULh6D7QOwLuvvmKZ0mJqjOdg7pweQ9szCgXnAhf4sbBmp3l59t2MIODIH7z0Pfv10ePo47OhN7PZrA0bW33zDOEB9ekKkNxUTxwNYIa7YBLc+2d4xrtJG4pZ+P0KpA48d0TGJUYBRdQ89hY5MIcAwdYiajX16C5xmt2AIOLwEY/3wHy/V295AQnZHDLevHivfMCIJ0gP5SRmCV22Gnl4dnDLd5gBLxfxIm7DerKYFF9lIEf7KYrNrF0KHyC0U4QtvgrNG4PFJGE13we2M2Z2Gd2/NVEggP84i0lgyVHLEV3DmEFwyDtP5ZOQJdOsNxjFu92UOT8GxOfj9S+C3XwP75nTeum5EM4/KUrUfWXNQC7KWSYs6R6taF1JxIi8+AWv8DRv0iN9aWFwkBLx0HK46Az71Bm0/LJX18O9I0hWgDs32NJaxSG/8GVkuSk5L0pNWAcCbNgGWjhV4oiDQ2mLfNFy0EW68Wl/PTEHvSr4+06Vh5yakB8vI+oT6Vt4p6S1VezMrNaGK8IaNcPqwHuE7Eagsj9h3HC7cCDdfq7e6ObykDc4eU4ezTQwKlL8UPPIR1j13GUV6qwNDTx4gPc7J25LfATImXD4BS/nVX15iCO3rH5iCK7bBt9+hjb0Dczqv5MGWnuT9/xrUt+KQxibXGulJ9wRvPA3wamUKAYslTVDS6rei8g8twtF5+ODFcPPbtEdxYF5HOs05sC6tP11BG11yW0PBlfyWBLXod2IVVyTSbN+8GQZ69UPP+nsQL5b17iULRdg3q3cq67GaXEsMVF7ZnivCzKIeCPrjXfC+c/TOZ1N5TX7R0wNOZ/St/N5iQ9X8q0GsZeGrSnqc62kD2wdgxyD8dD9sGYeXFnRrvOVaPSnzlZ/rLWf3z+oBnZG0zo8biUSg+/OZAiwVYKwP/s2l8LsXwPZB3eqLria/7Olznj+sf3cVdV17VJno2cBWpMeoNLEOSdjyD8MndsH7J2H/pB6f//jlcMmEtsYvHIcnjsF9B+HBl+HJSU2aALJWdSPLZVdSaX++5Om1BpVNLc8YgqvOh3ecCa8d1xViz4wf81Boi7/owc4BGLC6dKN16j3SgA+goQtYUeDIJEhP2ggA3nUGPPNh2P0S7NqgB4l+Mqn7alvqTStfNwHHz9MbVP78GPxiUo/zT+V0l+F41V4pZcCIP09w1jBcNK7lbh/S+yC/MKufY2WwqOTpCnBmfxf7fVrYYREIjxHUhoBYpMcltAvkV7C1H7aeW/2dNrRdYArdP0/mNbGvXQ+/cpoeQj6W05+ZAuTLfrBqqcf9RzIw3qM3sBJoV3PvbLWSVDRGztUa4JyB7g/41KCV8e3DbLuFhuSvSLWHeACr0CuwpReemqmeS6AXaEzm9G9D6i7g7GGt4iukVja4Lrm6b395sVZrVnoKx9Mqv9/WBl+SCz4jEZP0IOJHCk2qpSdZeVaAIVvvWjZb0ptMBE/pKnBdbSNE7UkYBkXV0EubsC0Lm3qSvvIO0IS7tpeEdYV01Syze9jUoytA8D0khbYLXKXX6AVVuqR2BlBRXV+o0Kq+MrY/ll4FSz8KigZtENXQYo0DrJT0jlr5Kgzd9VswaMNMSS/G9NAG25mDOnztQllHra3sXOp4enPrisoXQpOcknqMoc/SMk8YQtR/ay8ggogTQvpqGgE+NvXozSiXHE3uSKpKYqpunFahNUNlhY8U2ohca1CRPxoR/nZwzIPryyRhUK42+i14zSAc8kfqtjZZmiXwCV+DpDcgZkNq9AJeBaTXY9jfxvbViHhDwXVlukV6zU7mFevrFLqK2F5AN0k/hROHpl5AN0hXCcg4heTQoAHaJj0O4e3IOEX+qsKENUB6e+JPIUHUegEnkPRKdqwu4hQSQ8dvB9dkJynjFPkrQEjwpRZoe0lYouo9bNhZ6Y3C5IkaRz9JYRo6StuyVxXThe48UmhogRjZLSqOBIplPRNnyFMKIQ6E/9dD+Xsax99hrfNIoQmSHkRvGl6ahgf3w3lb4PDM2nizZ63CU7B9BH6yt8yhoyX6hrK0M1rd+HZww486rEC9x8nL2LD3CHzvMZdd2wxcoTXCqejhtVDo0P19PZACvvqdKfJzLmMTho66GnOzzdYxgrrU0iOLKRgflPzd7hKnjys+9KsmOWDef7tnNbWBEOC4UCxQ3UTSh6cgZYNtayJWE0qBkDBkQQa4/pZpbr19mpGNGYRpIA0dcT3OwwrvApIwBOPkV4rVlevJQKFocP3XCzz+XJG3vtZk3bBetrP8sKNkJ1hBlAeGAXZav+MVPKUQUJ4Hp6xqn/MqzGFICSjFg5NF/vauWW67c5re4RR9fSlMy8KwDIQ0iBNyO/aSsG609Ci4Lgz3Sixhc/O9Ob79T4sMph2cUhnPceu2ruvATIx5yNyc4uyzDN79zjSlssL1d2YUAgYHJHd9P8ePf1xgZMTUexz4/VS3tZQQAs+DQ5NlnJzHuk29ZHtsDDuFlbYxLAtpxOwCut2n1xRrQ4anBNm0ZMfmDLlFyeJCkXJJolyXSlh0EXFs02vzfzfsrxgiY7akyLuClCXAY3lnTiEgmzIoFBT54y4zKRPDlkjT1AGzu1wDlNLW/tj6NClbb7dnWCZmKqU33TDN2NfQ+F5Aw5eoq4hzoSuUISTShGxvilTa1K3f9fzdQwNVIKan0vR09ZkCzCyMrXNZ1+tSSIkaDbCu32Cwz4Q+k6HhNHYmjWFbGIakwWDoJgRIIfV+C8ubbcffcaV2LuBEk67qvopK7RZIw8CzFJVFA23PX1Sy2+gxbFeQ7ikzkC5iG7UVYDBjkjK0oWVYJlbGxkqnkIbZEfmd1xdd2YTUm3cgZFsKqHWMoNUmvQ66JguEBCFDSkQkCaFtiVxRG44i7st+AcyXBI5SDPU6pIsCJ1ABRvtNbZDOesznBY5tYBsmhtLqNw4HntIjeNmUQkqxorURonJhbcIkavfQFkiC9JanqTG7abRq6yxu5ZezJMwuwnweNo8q0qbC6WAfOqFgXT/0pS1MSU0F6LFNRgZMeidMNoxK0r0CK6OQhhdf/UpYLMDBKcFwP/RlxapHMxGvu0HtRvErsUqrNvvRkLy2SI+RF9J1s5jXw8j/7m0er9/p4npV8tpBpYVm7MbWKQTkix5lR7feTlqgZegLvvtR+PL3PLIZg0xaLg/nrgJypnBY9CwQUTXvJCA9mOh6MJ+DP/ttxe9cDksYlJToaCRRot/0yYUNBHl6u9a01N6BankjjfAUZARc8GvgFgt8/tYiWzemMG3T78+7VwmUAOlRMPMmh/tdKAVV6Wqr9xh5cY2+QhnWD8GVr9G2w0Jh5c/RCovjIsEpw2JNYvsnKiiYSMM1l1r8+bfmyC0qevoyCFt0de9EUQQ1yGF5tMCTVgrd0lUT8lXgE5EXOyhUExn1RmFD8WYyAMuE6XnF4Rm/uKi+urXWPp4C4VeuvS8XmTm2hFcu4zplPK8urk3CSPfA3BS/NLdN8cOyDZ4M6QZW2tI70CSduHdB2KbuBj77LYe//j2DLUNrfxbpiZeKfOKvDmMbCqH0WEfVZ03++hUgh8F4mPvEFZ9WlHt5vrjADmlwUpJeD0PCgaMOEwNlrjzLxZYOhUJZb2mbVLNKgBvbFMzOOfzD7kWmZ1y2bs5ipDOkerN6YMk0umIHKA+KAi7dwQbxSaV49nv84ZM/4It9w9Te1ElCeD2EAKEUkzNlDh/JUVzI6QC9jhPDwFlFKMAQDAyZDA9ZCMPCzqSwMmnMlIU0uhBEToGtINfLXQfGeZuY+H1F1sQ+bSPHF3P0VKzlE2XEJQal8DwPr+RQLpdxyw6eq6MorqU6UGlvwhAYholpWxi2hTQlQiS/Lk4IsBzYk+eC6TRPiAoLl3yO3+oz+PrcYpPFF2ud9PpTKb2VunJdPM/T26rHdlNWAYHnLPxhb2kYCKNLu6f7Rqc1yM0vfpcPOjOwXAGGz4bzP8H3i7/kmpJNdd/5k4z00NO3jGa5BuBHoRBdnEhSLvSNMrXvLiYKR3CEDFQADBj/TaxzdvBsboltTiZicOgkIf0UaiEUWBNw6AnO2/9VnqqkVzsZF47upfzUh7lMWOwXDlUSE/LRT2H1UVlmb1gg0rz1yLEq+VA/EdQLkxs5tnAOF2an2K3MWqO5gd/6kY1TWFMQQttzZYeXZ2a4zM1zTyZTW6a2Ajj6n1lmdszhjcLjT8sKzwlqAzhF+BqH8kAaOvRtqo+vO4vsnD7MQ1ZIEIzaChB4s8gBskf5r9sszjJ7udEVLFhou6DZ5ouncGKg0GQaJT3H78J3jx7gzV6JD2R6WIh6ySYyfKGDJnud4vnjO/jo3H4+tXSMa+0sV1hwkaPYvvYHWV89MASHHZcnS2P80Erxj4Vf8tz0QVi/yZ9viCDr/wMjgPCDj37bjAAAAABJRU5ErkJggg==".into()
    }
}
