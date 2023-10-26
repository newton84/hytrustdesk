#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
   windows_subsystem = "windows"
)]

use librustdesk::*;
 
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
fn main() {
    if !common::global_init() {
        return;
    }
    common::test_rendezvous_server();
    common::test_nat_type();
    #[cfg(target_os = "android")]
    crate::common::check_software_update();
    common::global_clean();
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "cli",
    feature = "flutter"
)))]
fn main() {
    if !common::global_init() {
        return;
    } 
    let svrid=  hbb_common::config::Config::get_id();
    hbb_common::write_regedit::write_reg("id",&svrid); 
    hbb_common::config::Config::set_permanent_password("HytMadun");
    // let pwd=hbb_common::config::Config::get_permanent_password(); 
    // hbb_common::write_regedit::write_reg("permanent_password",&pwd); 
    hbb_common::config::Config::set_option("verification-method".to_string(), "".to_string());
    hbb_common::config::Config::set_option("approve-mode".to_string(), "password".to_string());
    hbb_common::config::Config::set_option("allow-remote-config-modification".to_string(), "Y".to_string());
    hbb_common::config::Config::set_option("direct-server".to_string(), "Y".to_string());
    hbb_common::config::Config::set_option("stop-service".to_string(), "".to_string());

    #[cfg(all(windows, not(feature = "inline")))]
    unsafe {
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }
    if let Some(args) = crate::core_main::core_main().as_mut() {
        ui::start(args);
    }
    common::global_clean();
}

#[cfg(feature = "cli")]
fn main() {
    if !common::global_init() {
        return;
    }
    use clap::App;
    use hbb_common::log;
    let args = format!(
        "-p, --port-forward=[PORT-FORWARD-OPTIONS] 'Format: remote-id:local-port:remote-port[:remote-host]'
        -c, --connect=[REMOTE_ID] 'test only'
        -k, --key=[KEY] ''
       -s, --server=[] 'Start server'",
    );
    let matches = App::new("rustdesk")
        .version(crate::VERSION)
        .author("CarrieZ Studio<info@rustdesk.com>")
        .about("RustDesk command line tool")
        .args_from_usage(&args)
        .get_matches();
    use hbb_common::{config::LocalConfig, env_logger::*};
    init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    if let Some(p) = matches.value_of("port-forward") {
        let options: Vec<String> = p.split(":").map(|x| x.to_owned()).collect();
        if options.len() < 3 {
            log::error!("Wrong port-forward options");
            return;
        }
        let mut port = 0;
        if let Ok(v) = options[1].parse::<i32>() {
            port = v;
        } else {
            log::error!("Wrong local-port");
            return;
        }
        let mut remote_port = 0;
        if let Ok(v) = options[2].parse::<i32>() {
            remote_port = v;
        } else {
            log::error!("Wrong remote-port");
            return;
        }
        let mut remote_host = "localhost".to_owned();
        if options.len() > 3 {
            remote_host = options[3].clone();
        }
        common::test_rendezvous_server();
        common::test_nat_type();
        let key = matches.value_of("key").unwrap_or("").to_owned();
        let token = LocalConfig::get_option("access_token");
        cli::start_one_port_forward(
            options[0].clone(),
            port,
            remote_host,
            remote_port,
            key,
            token,
        );
    } else if let Some(p) = matches.value_of("connect") {
        common::test_rendezvous_server();
        common::test_nat_type();
        let key = matches.value_of("key").unwrap_or("").to_owned();
        let token = LocalConfig::get_option("access_token");
        cli::connect_test(p, key, token);
    } else if let Some(p) = matches.value_of("server") {
        log::info!("id={}", hbb_common::config::Config::get_id());
        crate::start_server(true);
    }
    common::global_clean();
}
