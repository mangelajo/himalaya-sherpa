//! Command line of the agent-facing `sherpa` gate: a strict subset of the himalaya
//! v2 command line. Anything not declared here (e.g. `-c`, `--log-level`, the raw
//! protocol commands, file-path arguments) is rejected by the parser.

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "himalaya",
    version,
    about = "Email access through himalaya-sherpa, a policy gate in front of himalaya.",
    long_about = "Email access through himalaya-sherpa, a policy gate in front of himalaya.\n\n\
        The commands mirror himalaya's. Credentials are held by the gate; sending may \
        require human approval, and messages with one-time codes, password resets and \
        similar content are withheld or redacted. Run `himalaya policy` to see the rules."
)]
pub struct Cli {
    /// Override the default account.
    #[arg(short = 'a', long, global = true)]
    pub account: Option<String>,
    /// Enable JSON output.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Cmd,
}

// Parsed once per request, so the size difference between variants does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Manage mailboxes.
    #[command(subcommand, visible_alias = "mbox")]
    Mailbox(MailboxCmd),
    /// List and search envelopes.
    #[command(subcommand)]
    Envelope(EnvelopeCmd),
    /// Manage flags.
    #[command(subcommand)]
    Flag(FlagCmd),
    /// Read, compose, send and organize messages.
    #[command(subcommand, visible_alias = "msg")]
    Message(MessageCmd),
    /// List and download attachments.
    #[command(subcommand)]
    Attachment(AttachmentCmd),
    /// List accounts.
    #[command(subcommand)]
    Account(AccountCmd),
    /// Status of messages you sent through the gate.
    #[command(subcommand)]
    Outbox(OutboxCmd),
    /// Show the email policy that applies to you.
    Policy,
}

#[derive(Debug, Subcommand)]
pub enum MailboxCmd {
    /// List mailboxes.
    #[command(visible_alias = "ls")]
    List {
        /// Populate per-mailbox message counts.
        #[arg(long)]
        counts: bool,
        /// Maximum width of the rendered table.
        #[arg(short = 'w', long)]
        max_width: Option<usize>,
    },
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Mailbox name or alias (default: inbox).
    #[arg(short = 'm', long)]
    pub mailbox: Option<String>,
    /// Page number, starting from 1.
    #[arg(short = 'p', long)]
    pub page: Option<u32>,
    /// Maximum number of envelopes per page.
    #[arg(short = 's', long)]
    pub page_size: Option<u32>,
    /// Maximum width of the rendered table.
    #[arg(short = 'w', long)]
    pub max_width: Option<usize>,
    /// Show recipients instead of senders.
    #[arg(short = 'r', long)]
    pub recipient: bool,
    /// Populate the has-attachment field.
    #[arg(long)]
    pub has_attachment: bool,
}

#[derive(Debug, Subcommand)]
pub enum EnvelopeCmd {
    /// List envelopes, most recent first.
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Search envelopes: `from <p>`, `to <p>`, `subject <p>`, `date <d>`, `after <d>`,
    /// `flag <f>`, combined with `and`/`or`/`not`, sorted with `order by ...`.
    #[command(visible_alias = "sr")]
    Search {
        #[command(flatten)]
        list: ListArgs,
        /// Filter and/or sort query.
        query: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FlagName {
    Seen,
    Answered,
    Flagged,
    Draft,
}

impl FlagName {
    pub fn as_str(self) -> &'static str {
        match self {
            FlagName::Seen => "seen",
            FlagName::Answered => "answered",
            FlagName::Flagged => "flagged",
            FlagName::Draft => "draft",
        }
    }
}

#[derive(Debug, Args)]
pub struct FlagArgs {
    /// Mailbox name or alias (default: inbox).
    #[arg(short = 'm', long)]
    pub mailbox: Option<String>,
    /// Flag(s) to apply. Repeat to pass several.
    #[arg(short = 'f', long = "flag", required = true)]
    pub flags: Vec<FlagName>,
    /// Message identifier(s).
    #[arg(required = true)]
    pub ids: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum FlagCmd {
    /// Add flag(s) to message(s).
    Add(FlagArgs),
    /// Replace flag(s) of message(s).
    Set(FlagArgs),
    /// Remove flag(s) from message(s).
    #[command(visible_alias = "rm")]
    Remove(FlagArgs),
}

#[derive(Debug, Args)]
pub struct ComposeArgs {
    /// Sender address (default: the account's).
    #[arg(long)]
    pub from: Option<String>,
    /// Recipient address(es). Repeat or comma-separate.
    #[arg(short = 't', long)]
    pub to: Vec<String>,
    /// Carbon-copy recipient(s).
    #[arg(long)]
    pub cc: Vec<String>,
    /// Blind carbon-copy recipient(s).
    #[arg(long)]
    pub bcc: Vec<String>,
    /// Subject line.
    #[arg(short = 's', long)]
    pub subject: Option<String>,
    /// Inline body. Without it, the body is read from stdin.
    #[arg(long)]
    pub body: Option<String>,
    /// Signature appended after the body.
    #[arg(long)]
    pub signature: Option<String>,
    /// Attach a file. Repeat for several.
    #[arg(long)]
    pub attach: Vec<String>,
    /// Append a copy of the composed message to this mailbox.
    #[arg(long)]
    pub save: Option<String>,
    /// Send the composed message (subject to the send policy).
    #[arg(long)]
    pub send: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PostingStyle {
    Top,
    Bottom,
}

#[derive(Debug, Args)]
pub struct QuoteArgs {
    /// Mailbox of the source message (default: inbox).
    #[arg(short = 'm', long)]
    pub mailbox: Option<String>,
    /// Where the quoted source goes relative to your body.
    #[arg(short = 'P', long)]
    pub posting_style: Option<PostingStyle>,
    /// Headline placed before the quoted source body.
    #[arg(short = 'Q', long)]
    pub quote_headline: Option<String>,
}

#[derive(Debug, Args)]
pub struct MoveArgs {
    /// Source mailbox (default: inbox).
    #[arg(short = 'f', long)]
    pub from: Option<String>,
    /// Destination mailbox.
    #[arg(short = 't', long, required = true)]
    pub to: String,
    /// Message identifier(s).
    #[arg(required = true)]
    pub ids: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum MessageCmd {
    /// Read a message. Does not mark it seen unless `--seen` is given.
    Read {
        id: String,
        #[arg(short = 'm', long)]
        mailbox: Option<String>,
        /// Output the raw RFC 5322 message.
        #[arg(long)]
        raw: bool,
        /// Mark the message as seen.
        #[arg(long)]
        seen: bool,
    },
    /// Send a raw RFC 5322 message read from stdin (subject to the send policy).
    Send {
        /// Also append a copy to this mailbox once actually sent.
        #[arg(long)]
        save: Option<String>,
    },
    /// Add a raw RFC 5322 message read from stdin to a mailbox.
    #[command(visible_alias = "save")]
    Add {
        #[arg(short = 'm', long, required = true)]
        mailbox: String,
        /// Flag(s) to set on the new message.
        #[arg(short = 'f', long = "flag", num_args = 0..)]
        flags: Vec<FlagName>,
        /// Also send the message (subject to the send policy).
        #[arg(long)]
        send: bool,
    },
    /// Compose a new message. Prints it, or routes it with `--save` / `--send`.
    #[command(visible_alias = "write")]
    Compose(ComposeArgs),
    /// Reply to a message.
    Reply {
        id: String,
        #[command(flatten)]
        quote: QuoteArgs,
        #[command(flatten)]
        compose: ComposeArgs,
    },
    /// Forward a message.
    #[command(visible_alias = "fwd")]
    Forward {
        id: String,
        #[command(flatten)]
        quote: QuoteArgs,
        #[command(flatten)]
        compose: ComposeArgs,
    },
    /// Move message(s) to another mailbox.
    #[command(visible_alias = "mv")]
    Move(MoveArgs),
    /// Copy message(s) to another mailbox.
    #[command(visible_alias = "cp")]
    Copy(MoveArgs),
    /// Delete message(s) (moved to trash first).
    #[command(visible_alias = "rm")]
    Delete {
        #[arg(short = 'm', long)]
        mailbox: Option<String>,
        #[arg(required = true)]
        ids: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AttachmentCmd {
    /// List the attachments of a message.
    #[command(visible_alias = "ls")]
    List {
        id: String,
        #[arg(short = 'm', long)]
        mailbox: Option<String>,
        /// Include inline parts.
        #[arg(short = 'i', long)]
        inline: bool,
    },
    /// Download attachments. They are saved in a directory chosen by the gate.
    #[command(visible_alias = "dl")]
    Download {
        id: String,
        /// Attachment identifier(s) (default: all).
        attachment_ids: Vec<String>,
        /// Directory to save them in (default: the current directory).
        #[arg(short = 'd', long)]
        dir: Option<String>,
        #[arg(short = 'm', long)]
        mailbox: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AccountCmd {
    /// List the accounts you can use.
    #[command(visible_alias = "ls")]
    List,
}

#[derive(Debug, Subcommand)]
pub enum OutboxCmd {
    /// List messages you sent and their status.
    #[command(visible_alias = "ls")]
    List,
    /// Show one outbox message.
    Show { id: String },
}
