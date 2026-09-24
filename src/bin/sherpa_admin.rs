//! Administration of himalaya-sherpa. Run by the human, as root.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use chrono::NaiveDate;
use clap::{Parser, Subcommand, ValueEnum};
use himalaya_sherpa::admin::{self, Layout, SetupOptions, Via};
use himalaya_sherpa::config::Config;
use himalaya_sherpa::scan::ScanOptions;

fn parse_date(s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|e| format!("expected YYYY-MM-DD: {e}"))
}

#[derive(Parser)]
#[command(
    name = "sherpa-admin",
    version,
    about = "Set up and operate the himalaya-sherpa email gate."
)]
struct Cli {
    /// Service user that holds the credentials and runs himalaya.
    #[arg(long, global = true, default_value = "sherpa")]
    service_user: String,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the service user, directories, sudo rule and agent command.
    Setup {
        /// User the agent runs as.
        #[arg(long)]
        agent_user: String,
        /// himalaya binary to install for the gate (default: found in PATH or the agent's ~/.local/bin).
        #[arg(long)]
        himalaya: Option<PathBuf>,
        /// himalaya configuration to import (default: the agent's, if no config is installed yet).
        #[arg(long)]
        import_config: Option<PathBuf>,
        /// Fill secrets by running the imported password commands as the agent user.
        #[arg(long)]
        import_secrets: bool,
        /// Also make the client available at this path, as a symlink created by the agent
        /// user (e.g. the agent's ~/.local/bin/himalaya). Repeatable.
        #[arg(long)]
        link: Vec<PathBuf>,
        /// Print what would be done without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Accept a himalaya binary, sherpa build or config the agent could have modified.
        #[arg(long)]
        allow_untrusted: bool,
    },
    /// Manage account secrets.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Check the installation and the privilege boundary.
    Doctor {
        #[arg(long)]
        agent_user: String,
    },
    /// Review messages the agent tried to send.
    #[command(subcommand)]
    Review(ReviewCmd),
    /// Check, test, edit and install the policy.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Show the last entries of the audit log.
    Log {
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Validate a policy and run its examples (default: the installed policy).
    Check { file: Option<PathBuf> },
    /// Show how a policy treats real messages (.eml files, or one on stdin).
    Test {
        /// Policy to use (default: the installed policy).
        #[arg(long)]
        policy: Option<PathBuf>,
        files: Vec<PathBuf>,
    },
    /// Dry-run a policy against real mail: which messages would it catch?
    Scan {
        /// Candidate policy (default: the installed policy).
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Show only messages the candidate treats differently from the installed policy.
        #[arg(long)]
        compare: bool,
        #[arg(short = 'a', long)]
        account: Option<String>,
        /// Mailbox to scan (repeatable; default: inbox).
        #[arg(short = 'm', long = "mailbox")]
        mailboxes: Vec<String>,
        /// First day to include (YYYY-MM-DD).
        #[arg(long, value_parser = parse_date)]
        since: Option<NaiveDate>,
        /// Last day to include (YYYY-MM-DD).
        #[arg(long, value_parser = parse_date)]
        until: Option<NaiveDate>,
        /// Only the last N days (shorthand for --since).
        #[arg(long, conflicts_with = "since")]
        days: Option<u32>,
        /// Maximum messages per mailbox, most recent first.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Messages fetched in parallel (each is one connection to the server).
        #[arg(long, default_value_t = 4)]
        jobs: usize,
        /// List every scanned message, not only the matched (or changed) ones.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Edit the installed policy; it is installed only if it passes its checks.
    Edit,
    /// Check a policy file, show the changes, and install it.
    Install {
        file: PathBuf,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a password (prompted, or read from stdin).
    Set { name: String },
    /// List stored secrets (names only).
    List,
}

#[derive(Clone, Copy, ValueEnum)]
enum ViaArg {
    Send,
    Draft,
}

#[derive(Subcommand)]
enum ReviewCmd {
    /// List messages waiting for approval.
    #[command(visible_alias = "ls")]
    List {
        /// Include messages already handled.
        #[arg(long)]
        all: bool,
    },
    /// Show a message and its metadata.
    Show { id: String },
    /// Approve a message: send it, or put it in Drafts to send yourself.
    Approve {
        id: String,
        #[arg(long, value_enum, default_value = "send")]
        via: ViaArg,
    },
    /// Deny a message. The agent sees it as denied, with the reason.
    Deny {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

fn load() -> Result<Config> {
    Config::load(&Config::default_path())
}

fn run(cli: Cli) -> Result<bool> {
    let service = cli.service_user.as_str();
    match cli.command {
        Cmd::Setup {
            agent_user,
            himalaya,
            import_config,
            import_secrets,
            link,
            dry_run,
            allow_untrusted,
        } => {
            admin::setup(&SetupOptions {
                agent_user,
                service_user: service.into(),
                himalaya,
                import_config,
                import_secrets,
                links: link,
                dry_run,
                allow_untrusted,
            })?;
        }
        Cmd::Secret(SecretCmd::Set { name }) => {
            admin::require_root()?;
            let secret = if std::io::stdin().is_terminal() {
                rpassword::prompt_password(format!("Password for `{name}`: "))?
            } else {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.lines().next().unwrap_or_default().to_string()
            };
            if secret.is_empty() {
                anyhow::bail!("empty password; nothing stored");
            }
            let user = nix::unistd::User::from_name(service)?.ok_or_else(|| anyhow::anyhow!("no user {service}"))?;
            admin::write_secret(&Layout::default(), &user, &name, &secret)?;
            println!("Stored secret `{name}`.");
        }
        Cmd::Secret(SecretCmd::List) => {
            admin::require_root()?;
            let mut names: Vec<String> = std::fs::read_dir(Layout::default().secrets())?
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.starts_with('.'))
                .collect();
            names.sort();
            for n in names {
                println!("{n}");
            }
        }
        Cmd::Doctor { agent_user } => return admin::doctor(&agent_user, service),
        Cmd::Review(cmd) => {
            admin::drop_to(service)?;
            let cfg = load()?;
            match cmd {
                ReviewCmd::List { all } => admin::review_list(&cfg, all)?,
                ReviewCmd::Show { id } => admin::review_show(&cfg, &id)?,
                ReviewCmd::Approve { id, via } => admin::review_approve(
                    &cfg,
                    &id,
                    match via {
                        ViaArg::Send => Via::Send,
                        ViaArg::Draft => Via::Draft,
                    },
                )?,
                ReviewCmd::Deny { id, reason } => admin::review_deny(&cfg, &id, reason)?,
            }
        }
        Cmd::Policy(cmd) => {
            let installed = Config::default_path();
            return match cmd {
                PolicyCmd::Check { file } => admin::policy_check(file.as_ref().unwrap_or(&installed)),
                PolicyCmd::Test { policy, files } => {
                    admin::policy_test(policy.as_ref().unwrap_or(&installed), &files)?;
                    Ok(true)
                }
                PolicyCmd::Scan {
                    policy,
                    compare,
                    account,
                    mailboxes,
                    since,
                    until,
                    days,
                    limit,
                    jobs,
                    all,
                    json,
                } => {
                    let since =
                        since.or_else(|| days.map(|d| chrono::Local::now().date_naive() - chrono::Days::new(d.into())));
                    admin::policy_scan(
                        service,
                        admin::ScanRequest {
                            policy,
                            compare,
                            all,
                            json,
                            options: ScanOptions {
                                account,
                                mailboxes,
                                since,
                                until,
                                limit,
                                jobs,
                            },
                        },
                    )
                }
                PolicyCmd::Edit => admin::policy_edit(service),
                PolicyCmd::Install { file, yes } => admin::policy_install(service, &file, yes),
            };
        }
        Cmd::Log { lines } => {
            admin::drop_to(service)?;
            admin::show_log(&load()?, lines)?;
        }
    }
    Ok(true)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
