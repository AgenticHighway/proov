#[cfg(target_os = "macos")]
use crate::scan_cache::RootCursor;
use crate::scan_cache::ScanCache;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;

pub const MACOS_FSEVENTS_BACKEND: &str = "macos_fsevents_v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRoot {
    pub path: PathBuf,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootRefreshAction {
    ReuseCached,
    Rescan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootCursorUpdate {
    pub root_path: String,
    pub backend_type: String,
    pub cursor_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRefreshPlan {
    pub root: DiscoveryRoot,
    pub action: RootRefreshAction,
    pub cursor_update: Option<RootCursorUpdate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayOutcome {
    Unchanged,
    Changed,
    MustRescan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MacosCursorToken {
    last_event_id: u64,
    device_id: u64,
}

pub fn plan_root_refresh(
    cache: Option<&ScanCache>,
    roots: &[DiscoveryRoot],
) -> Vec<RootRefreshPlan> {
    let Some(cache) = cache else {
        return roots
            .iter()
            .cloned()
            .map(|root| rescan_plan(root, None))
            .collect();
    };

    #[cfg(target_os = "macos")]
    {
        roots
            .iter()
            .cloned()
            .map(|root| plan_macos_root_refresh(cache, root))
            .collect()
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cache;
        roots
            .iter()
            .cloned()
            .map(|root| rescan_plan(root, None))
            .collect()
    }
}

fn rescan_plan(root: DiscoveryRoot, cursor_update: Option<RootCursorUpdate>) -> RootRefreshPlan {
    RootRefreshPlan {
        root,
        action: RootRefreshAction::Rescan,
        cursor_update,
    }
}

fn reuse_plan(root: DiscoveryRoot, cursor_update: Option<RootCursorUpdate>) -> RootRefreshPlan {
    RootRefreshPlan {
        root,
        action: RootRefreshAction::ReuseCached,
        cursor_update,
    }
}

fn root_cursor_update(root_path: &str, token: &MacosCursorToken) -> Option<RootCursorUpdate> {
    serde_json::to_string(token)
        .ok()
        .map(|cursor_token| RootCursorUpdate {
            root_path: root_path.to_string(),
            backend_type: MACOS_FSEVENTS_BACKEND.to_string(),
            cursor_token,
        })
}

fn plan_from_cursor_state(
    root: DiscoveryRoot,
    previous: Option<MacosCursorToken>,
    current: Option<MacosCursorToken>,
    replay: Result<ReplayOutcome, ()>,
) -> RootRefreshPlan {
    let root_path = root.path.to_string_lossy().to_string();
    let cursor_update = current
        .as_ref()
        .and_then(|token| root_cursor_update(&root_path, token));
    let Some(current) = current else {
        return rescan_plan(root, None);
    };
    let Some(previous) = previous else {
        return rescan_plan(root, cursor_update);
    };
    if previous.device_id != current.device_id {
        return rescan_plan(root, cursor_update);
    }
    if previous.last_event_id >= current.last_event_id {
        return reuse_plan(root, cursor_update);
    }

    match replay {
        Ok(ReplayOutcome::Unchanged) => reuse_plan(root, cursor_update),
        Ok(ReplayOutcome::Changed | ReplayOutcome::MustRescan) => rescan_plan(root, cursor_update),
        Err(()) => rescan_plan(root, None),
    }
}

#[cfg(target_os = "macos")]
fn plan_macos_root_refresh(cache: &ScanCache, root: DiscoveryRoot) -> RootRefreshPlan {
    let root_path = root.path.to_string_lossy().to_string();
    let previous = load_macos_cursor(cache, &root_path);
    let current = current_cursor_token(&root.path);
    let replay = match (&previous, &current) {
        (Some(previous), Some(current))
            if previous.device_id == current.device_id
                && previous.last_event_id < current.last_event_id =>
        {
            replay_root_since(&root.path, previous.last_event_id)
        }
        _ => Ok(ReplayOutcome::Changed),
    };

    plan_from_cursor_state(root, previous, current, replay.map_err(|_| ()))
}

#[cfg(target_os = "macos")]
fn load_macos_cursor(cache: &ScanCache, root_path: &str) -> Option<MacosCursorToken> {
    match cache.load_root_cursor(root_path, MACOS_FSEVENTS_BACKEND) {
        Ok(Some(RootCursor { cursor_token, .. })) => serde_json::from_str(&cursor_token).ok(),
        Ok(None) => None,
        Err(_) => None,
    }
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn current_cursor_token(root_path: &Path) -> Option<MacosCursorToken> {
    use fsevent_sys::FSEventsGetCurrentEventId;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(root_path).ok()?;
    Some(MacosCursorToken {
        last_event_id: unsafe { FSEventsGetCurrentEventId() },
        device_id: metadata.dev(),
    })
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn replay_root_since(root_path: &Path, last_event_id: u64) -> Result<ReplayOutcome, String> {
    use core_foundation::array::CFArray;
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use dispatch2::DispatchQueue;
    use fsevent_sys::{
        kFSEventStreamCreateFlagNoDefer, kFSEventStreamCreateFlagUseCFTypes,
        kFSEventStreamCreateFlagWatchRoot, kFSEventStreamEventFlagEventIdsWrapped,
        kFSEventStreamEventFlagHistoryDone, kFSEventStreamEventFlagKernelDropped,
        kFSEventStreamEventFlagMustScanSubDirs, kFSEventStreamEventFlagRootChanged,
        kFSEventStreamEventFlagUserDropped, FSEventStreamContext, FSEventStreamCreate,
        FSEventStreamInvalidate, FSEventStreamRelease, FSEventStreamSetDispatchQueue,
        FSEventStreamStart, FSEventStreamStop,
    };
    use std::ffi::c_void;
    use std::ptr;
    use std::slice;
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct ReplayState {
        changed: bool,
        must_rescan: bool,
    }

    struct ReplayContext {
        state: Mutex<ReplayState>,
        done_tx: Mutex<Option<mpsc::Sender<()>>>,
    }

    extern "C" fn replay_callback(
        _stream_ref: *mut c_void,
        info: *mut c_void,
        num_events: usize,
        event_paths: *mut c_void,
        event_flags: *const u32,
        _event_ids: *const u64,
    ) {
        let context = unsafe { &*(info as *const ReplayContext) };
        let flags = unsafe { slice::from_raw_parts(event_flags, num_events) };
        let paths = unsafe { CFArray::<CFString>::wrap_under_get_rule(event_paths as _) };
        let mut saw_history_done = false;
        let mut state = context.state.lock().unwrap();

        for (index, flag) in flags.iter().enumerate() {
            if (flag & kFSEventStreamEventFlagHistoryDone) != 0 {
                saw_history_done = true;
                continue;
            }
            if (flag
                & (kFSEventStreamEventFlagMustScanSubDirs
                    | kFSEventStreamEventFlagUserDropped
                    | kFSEventStreamEventFlagKernelDropped
                    | kFSEventStreamEventFlagEventIdsWrapped
                    | kFSEventStreamEventFlagRootChanged))
                != 0
            {
                state.must_rescan = true;
            }
            if paths.get(index as isize).is_some() {
                state.changed = true;
            }
        }
        drop(state);

        if saw_history_done {
            if let Some(tx) = context.done_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
    }

    let root = root_path.to_string_lossy().to_string();
    let watched = CFArray::from_CFTypes(&[CFString::new(&root)]);
    let queue = DispatchQueue::new("com.agentichighway.proov.scan-refresh", None);
    let (done_tx, done_rx) = mpsc::channel();
    let context = Box::new(ReplayContext {
        state: Mutex::new(ReplayState::default()),
        done_tx: Mutex::new(Some(done_tx)),
    });
    let raw_context = Box::into_raw(context);
    let stream_context = FSEventStreamContext {
        version: 0,
        info: raw_context as *mut c_void,
        retain: None,
        release: None,
        copy_description: None,
    };
    let stream = unsafe {
        FSEventStreamCreate(
            ptr::null(),
            replay_callback,
            &stream_context,
            watched.as_concrete_TypeRef(),
            last_event_id.saturating_add(1),
            0.0,
            kFSEventStreamCreateFlagUseCFTypes
                | kFSEventStreamCreateFlagWatchRoot
                | kFSEventStreamCreateFlagNoDefer,
        )
    };
    if stream.is_null() {
        unsafe {
            drop(Box::from_raw(raw_context));
        }
        return Err("failed to create FSEvents replay stream".to_string());
    }

    unsafe {
        FSEventStreamSetDispatchQueue(stream, &queue);
    }
    if unsafe { FSEventStreamStart(stream) } == 0 {
        unsafe {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            drop(Box::from_raw(raw_context));
        }
        return Err("failed to start FSEvents replay stream".to_string());
    }

    let wait_result = done_rx.recv_timeout(Duration::from_millis(250));
    unsafe {
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
    }
    let context = unsafe { Box::from_raw(raw_context) };
    let state = context.state.into_inner().unwrap();

    match wait_result {
        Ok(()) => {
            if state.must_rescan {
                Ok(ReplayOutcome::MustRescan)
            } else if state.changed {
                Ok(ReplayOutcome::Changed)
            } else {
                Ok(ReplayOutcome::Unchanged)
            }
        }
        Err(_) => Err("timed out waiting for FSEvents replay".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(path: &str, origin: &str) -> DiscoveryRoot {
        DiscoveryRoot {
            path: PathBuf::from(path),
            origin: origin.to_string(),
        }
    }

    #[test]
    fn plan_from_cursor_state_reuses_cached_when_root_is_unchanged() {
        let plan = plan_from_cursor_state(
            root("/tmp/root", "host"),
            Some(MacosCursorToken {
                last_event_id: 10,
                device_id: 7,
            }),
            Some(MacosCursorToken {
                last_event_id: 12,
                device_id: 7,
            }),
            Ok(ReplayOutcome::Unchanged),
        );

        assert_eq!(plan.action, RootRefreshAction::ReuseCached);
        assert!(plan.cursor_update.is_some());
    }

    #[test]
    fn plan_from_cursor_state_rescans_on_device_change() {
        let plan = plan_from_cursor_state(
            root("/tmp/root", "home"),
            Some(MacosCursorToken {
                last_event_id: 10,
                device_id: 7,
            }),
            Some(MacosCursorToken {
                last_event_id: 12,
                device_id: 8,
            }),
            Ok(ReplayOutcome::Unchanged),
        );

        assert_eq!(plan.action, RootRefreshAction::Rescan);
        assert!(plan.cursor_update.is_some());
    }

    #[test]
    fn plan_from_cursor_state_does_not_advance_cursor_on_failed_replay() {
        let plan = plan_from_cursor_state(
            root("/tmp/root", "host"),
            Some(MacosCursorToken {
                last_event_id: 10,
                device_id: 7,
            }),
            Some(MacosCursorToken {
                last_event_id: 12,
                device_id: 7,
            }),
            Err(()),
        );

        assert_eq!(plan.action, RootRefreshAction::Rescan);
        assert!(plan.cursor_update.is_none());
    }

    #[test]
    fn plan_root_refresh_without_cache_rescans_all_roots() {
        let plans = plan_root_refresh(None, &[root("/tmp/root", "host")]);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].action, RootRefreshAction::Rescan);
        assert!(plans[0].cursor_update.is_none());
    }
}
