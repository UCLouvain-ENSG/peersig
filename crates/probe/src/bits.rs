//! Windows: downloads that the Background Intelligent Transfer Service
//! (BITS) makes for other programs (Dell's updater, Edge's component
//! updater, OneDrive's). Their ClientHellos leave from the BITS service, a
//! svchost, not from the program that asked for the download. Windows logs
//! which program created each job and which URL each transfer fetches (the
//! Microsoft-Windows-Bits-Client provider, which the capture session
//! enables beside the packet capture: `capture::etw`). A ClientHello from
//! the BITS service to a host that one of its jobs is downloading from is
//! credited to the program that created that job, the way a delegated
//! socket is on macOS (`attrib::Resolver::bits_delegate`).
//!
//! Times are Unix seconds: the events' times and the packets' times, both
//! the system's clock.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// How long after its last news a job still accounts for BITS's
/// connections to its hosts: a stop event can come before the last
/// connection's ClientHello is read, and events and packets can arrive a
/// little out of order.
const LINGER: f64 = 120.0;
/// Jobs forgotten after this long without news (a job cancelled while the
/// probe was not running never says it ended).
const FORGET: f64 = 6.0 * 3600.0;
const MAX_JOBS: usize = 4096;

/// A job's creator: its executable and pid.
pub type Creator = (String, u32);

#[derive(Debug, Clone, Default)]
struct Job {
    creator: Option<Creator>,
    /// Lower-case host names of the job's URLs.
    hosts: Vec<String>,
    /// Transfers started and not stopped.
    transferring: u32,
    /// Last news of the job.
    last: f64,
}

/// BITS jobs, by job id.
#[derive(Debug, Default)]
pub struct Jobs {
    jobs: HashMap<u128, Job>,
}

/// The jobs the capture session has heard of (filled by the ETW thread).
pub static JOBS: LazyLock<Mutex<Jobs>> = LazyLock::new(|| Mutex::new(Jobs::default()));

impl Jobs {
    fn job(&mut self, id: u128, t: f64) -> &mut Job {
        if self.jobs.len() >= MAX_JOBS && !self.jobs.contains_key(&id) {
            self.forget(t);
            if self.jobs.len() >= MAX_JOBS {
                self.jobs.clear();
            }
        }
        let j = self.jobs.entry(id).or_default();
        j.last = j.last.max(t);
        j
    }

    fn add_host(&mut self, id: u128, url: &str, t: f64) {
        let Some(h) = host_of(url) else { return };
        let j = self.job(id, t);
        if !j.hosts.contains(&h) {
            j.hosts.push(h);
        }
    }

    /// Event 3: a program created the job.
    pub fn created(&mut self, id: u128, path: &str, pid: u32, t: f64) {
        if !path.is_empty() {
            self.job(id, t).creator = Some((path.to_string(), pid));
        }
    }

    /// Event 16403: a program added a file (its URL) to the job. It names
    /// the job's creator when the job was created before the probe started.
    pub fn file_added(&mut self, id: u128, url: &str, adder: Option<Creator>, t: f64) {
        let j = self.job(id, t);
        if j.creator.is_none() {
            j.creator = adder;
        }
        self.add_host(id, url, t);
    }

    /// Event 59: a transfer of the job started.
    pub fn transfer_started(&mut self, id: u128, url: &str, t: f64) {
        self.job(id, t).transferring += 1;
        self.add_host(id, url, t);
    }

    /// Events 60 and 61: a transfer stopped (61: with an error).
    pub fn transfer_stopped(&mut self, id: u128, url: &str, t: f64) {
        let j = self.job(id, t);
        j.transferring = j.transferring.saturating_sub(1);
        self.add_host(id, url, t);
    }

    /// Events 4 and 5: the job completed, or was cancelled.
    pub fn ended(&mut self, id: u128, t: f64) {
        self.job(id, t).transferring = 0;
    }

    fn forget(&mut self, t: f64) {
        self.jobs.retain(|_, j| t - j.last < FORGET);
    }

    /// The program a BITS connection to `host` at `t` was made for: the
    /// creator of the jobs downloading from that host, when they all have
    /// the same one. A host no job names (a redirect: g.live.com sends the
    /// download on to oneclient.sfx.ms) goes to the creator of the jobs
    /// transferring right then, again only when there is one. Anything else
    /// (unknown creators, two programs) credits no one.
    pub fn creator(&mut self, host: &str, t: f64) -> Option<Creator> {
        self.forget(t);
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let recent = |j: &&Job| j.transferring > 0 || t - j.last <= LINGER;
        let by_host: Vec<&Job> = self.jobs.values().filter(recent).filter(|j| j.hosts.contains(&host)).collect();
        if !by_host.is_empty() {
            return same_creator(&by_host);
        }
        let busy: Vec<&Job> = self.jobs.values().filter(|j| j.transferring > 0).collect();
        same_creator(&busy)
    }
}

/// The one creator of `jobs` (by executable), if every job has it.
fn same_creator(jobs: &[&Job]) -> Option<Creator> {
    let first = jobs.first()?.creator.clone()?;
    jobs.iter().all(|j| j.creator.as_ref().is_some_and(|c| c.0.eq_ignore_ascii_case(&first.0))).then_some(first)
}

/// The host of a URL (`https://user@Host.example:8443/x` -> `host.example`),
/// lower case, without the brackets of an IPv6 literal.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?;
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        hostport.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DELL: &str = r"C:\Program Files (x86)\Dell\UpdateService\ServiceShell.exe";
    const ONEDRIVE: &str = r"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe";

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://dellupdater.dell.com/non_du/x.cab").as_deref(), Some("dellupdater.dell.com"));
        assert_eq!(host_of("http://u:p@Downloads.Dell.com:8443?x").as_deref(), Some("downloads.dell.com"));
        assert_eq!(host_of("https://[2001:db8::1]:443/x").as_deref(), Some("2001:db8::1"));
        assert_eq!(host_of("C:\\local\\file"), None);
    }

    /// The sequence the Bits-Client log shows for a Dell update check.
    #[test]
    fn credits_the_job_creator() {
        let mut j = Jobs::default();
        j.created(1, DELL, 9448, 100.0);
        j.file_added(1, "https://dellupdater.dell.com/non_du/DellOptimizer/AppConfigSettings.cab", None, 100.1);
        j.transfer_started(1, "https://dellupdater.dell.com/non_du/DellOptimizer/AppConfigSettings.cab", 100.2);
        assert_eq!(j.creator("dellupdater.dell.com", 100.3), Some((DELL.to_string(), 9448)));
        assert_eq!(j.creator("DellUpdater.Dell.com.", 100.3).map(|c| c.1), Some(9448));
        // After the transfer, for a while (the connection's last ClientHello
        // can be read after the stop event), then no more.
        j.transfer_stopped(1, "https://dellupdater.dell.com/non_du/DellOptimizer/AppConfigSettings.cab", 101.0);
        j.ended(1, 101.0);
        assert!(j.creator("dellupdater.dell.com", 150.0).is_some());
        assert_eq!(j.creator("dellupdater.dell.com", 101.0 + LINGER + 1.0), None);
    }

    /// A redirect: the job names g.live.com, BITS then connects to
    /// oneclient.sfx.ms while that job, alone, is transferring.
    #[test]
    fn redirects_go_to_the_job_transferring() {
        let mut j = Jobs::default();
        j.created(2, ONEDRIVE, 4242, 10.0);
        j.transfer_started(2, "https://g.live.com/1rewlive5skydrive/x", 10.0);
        assert_eq!(j.creator("oneclient.sfx.ms", 10.5).map(|c| c.0), Some(ONEDRIVE.to_string()));
        j.transfer_stopped(2, "https://g.live.com/1rewlive5skydrive/x", 11.0);
        // Nothing transferring: an unknown host credits no one.
        assert_eq!(j.creator("oneclient.sfx.ms", 11.5), None);
    }

    #[test]
    fn ambiguous_or_unknown_credits_no_one() {
        let mut j = Jobs::default();
        // Two programs download from the same host.
        j.created(1, DELL, 1, 0.0);
        j.transfer_started(1, "https://cdn.example.com/a", 0.0);
        j.created(2, ONEDRIVE, 2, 0.0);
        j.transfer_started(2, "https://cdn.example.com/b", 0.0);
        assert_eq!(j.creator("cdn.example.com", 1.0), None);
        // Two programs transferring: a host no job names is not guessed.
        assert_eq!(j.creator("elsewhere.example.com", 1.0), None);
        // A job created before the probe started, with no file event: unknown.
        let mut k = Jobs::default();
        k.transfer_started(3, "https://dellupdater.dell.com/x", 0.0);
        assert_eq!(k.creator("dellupdater.dell.com", 1.0), None);
        // Its file event names who added the file.
        k.file_added(3, "https://dellupdater.dell.com/x", Some((DELL.into(), 7)), 1.0);
        assert_eq!(k.creator("dellupdater.dell.com", 1.5).map(|c| c.1), Some(7));
    }

    #[test]
    fn old_jobs_are_forgotten() {
        let mut j = Jobs::default();
        j.created(1, DELL, 1, 0.0);
        j.transfer_started(1, "https://dellupdater.dell.com/x", 0.0);
        // Never stopped (the probe missed the event): forgotten after FORGET.
        assert!(j.creator("dellupdater.dell.com", FORGET - 1.0).is_some());
        assert_eq!(j.creator("dellupdater.dell.com", FORGET + 1.0), None);
        assert!(j.jobs.is_empty());
    }
}
