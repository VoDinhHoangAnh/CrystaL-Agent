use crystal_agent::{Agent, Config, Controller, Service, Store};
use std::{env, error::Error, process};

fn main() {
    if let Err(error) = entry() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn entry() -> Result<(), Box<dyn Error>> {
    let cfg = Config::Config::load()?;
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
        return Ok(());
    };
    #[cfg(windows)]
    if command == "service" {
        return Service::run_service(cfg);
    }
    match command.as_str() {
        "run" => Agent::run(cfg),
        "status" => Agent::status(&cfg),
        "validate-sources" => {
            let statuses = Controller::BruteForce::validate_sources(&cfg)
                .into_iter()
                .chain(Controller::NetworkLogin::validate_sources(&cfg))
                .chain(Controller::Process::validate_sources(&cfg));
            for status in statuses {
                println!(
                    "group={} category={} channel={} present={} sample={} access_denied={}",
                    status.group,
                    status.category,
                    status.channel,
                    status.channel_present,
                    status.sample_found,
                    status.access_denied
                );
            }
            Ok(())
        }
        "process" if args.next().as_deref() == Some("trace") => {
            let selector = args
                .next()
                .ok_or("usage: crystal-agent process trace <PID|GUID>")?;
            let repo = Store::JsonSnapshot::open(&cfg.json_path)?;
            let trace = Controller::Process::trace(&repo, &selector)?;
            println!("{}", serde_json::to_string_pretty(&trace)?);
            Ok(())
        }
        "install" => Service::install(),
        "uninstall" => Service::uninstall(),
        "start" => Service::start(),
        "stop" => Service::stop(),
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => Err(format!("unknown command: {other}").into()),
    }
}

fn usage() {
    println!(
        "crystal-agent Rust commands:\n  run\n  status\n  validate-sources\n  process trace <PID|GUID>\n  install | uninstall | start | stop"
    );
}
