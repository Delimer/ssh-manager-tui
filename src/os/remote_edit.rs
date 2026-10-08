//! Remote editing over the existing system-sftp worker. No shell or SSH backend.
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::sftp::{SftpFailure, nonce};

#[derive(Debug, Clone)]
pub struct EditorCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl EditorCommand {
    pub fn from_env() -> Result<Self, String> {
        Self::choose(
            std::env::var("VISUAL").ok().as_deref(),
            std::env::var("EDITOR").ok().as_deref(),
        )
    }

    fn choose(visual: Option<&str>, editor: Option<&str>) -> Result<Self, String> {
        let value = visual
            .filter(|s| !s.trim().is_empty())
            .or_else(|| editor.filter(|s| !s.trim().is_empty()))
            .ok_or("set VISUAL or EDITOR to a blocking editor (for example: code --wait)")?;
        Self::parse(value)
    }

    /// Whitespace-separated arguments, with single/double quoted groups. Keep
    /// backslashes literal (Windows executable paths). No shell expansion.
    fn parse(value: &str) -> Result<Self, String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quote = None;
        let mut started = false;
        for c in value.chars() {
            if c.is_control() {
                return Err("editor command contains a control character".into());
            }
            if quote == Some(c) {
                quote = None;
            } else if quote.is_none() && matches!(c, '\'' | '"') {
                quote = Some(c);
                started = true;
            } else if quote.is_none() && c.is_whitespace() {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            } else {
                word.push(c);
                started = true;
            }
        }
        if quote.is_some() {
            return Err("unclosed quote in VISUAL/EDITOR".into());
        }
        if started {
            words.push(word);
        }
        if words.first().is_none_or(|s| s.is_empty()) {
            return Err("empty editor command".into());
        }
        Ok(Self {
            program: words.remove(0),
            args: words,
        })
    }

    pub fn command(&self, file: &Path) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args).arg(file);
        command
    }
}

#[derive(Debug, Clone)]
pub struct EditPaths {
    pub root: PathBuf,
    pub local: PathBuf,
    pub original: PathBuf,
    pub remote: String,
}

impl EditPaths {
    pub fn create(remote: String, name: &str) -> Result<Self, String> {
        literal_path(&remote)?;
        let root = std::env::temp_dir()
            .join(crate::secure_fs::temp_name("sshm-edit").map_err(|e| e.to_string())?);
        // create_dir is exclusive; Unix mode is private from the moment of creation.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .map_err(|e| e.to_string())?;
        }
        #[cfg(not(unix))]
        fs::create_dir(&root).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        crate::secure_fs::restrict_acl(&root);
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_control() || "<>:\"/\\|?*".contains(c) {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        // Prefix avoids Windows device names, dot-only names and baseline collisions.
        let safe_name = format!("edit-{}", safe_name.trim_end_matches([' ', '.']));
        Ok(Self {
            local: root.join(safe_name),
            original: root.join("original"),
            root,
            remote,
        })
    }

    pub fn cleanup(&self) -> io::Result<()> {
        fs::remove_dir_all(&self.root)
    }
}

#[derive(Debug, Clone)]
pub enum EditOperation {
    Download(EditPaths),
    /// Compare edited content, then re-download the remote file and compare it
    /// with the snapshot the user last approved before staging an upload.
    Save {
        paths: EditPaths,
        expected: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub enum EditOutcome {
    Downloaded,
    Unchanged,
    Uploaded,
    Conflict { snapshot: PathBuf },
}

#[derive(Debug, Clone)]
pub enum EditPhase {
    Downloading,
    Ready,
    Saving,
    Conflict(PathBuf),
}

pub struct RemoteEdit {
    pub paths: EditPaths,
    pub command: EditorCommand,
    pub phase: EditPhase,
}

/// OpenSSH makeargv escapes globs inside quoted arguments. Double backslashes
/// survive both tokenization and glob/undo_glob_escape; quotes stay literal.
/// Always quote, even names without whitespace. Never permit a batch line break.
fn literal_path(path: &str) -> Result<String, String> {
    if path.is_empty() || path.chars().any(char::is_control) {
        return Err("unsupported empty/control-character path".into());
    }
    let path = if path.starts_with('-') {
        format!("./{path}")
    } else {
        path.into()
    };
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn local_path(path: &Path) -> Result<String, String> {
    literal_path(path.to_str().ok_or("local path is not Unicode")?)
}

/// Bounded-memory byte comparison, independent of timestamps and file length.
pub fn same_content(a: &Path, b: &Path) -> io::Result<bool> {
    let mut a = BufReader::new(File::open(a)?);
    let mut b = BufReader::new(File::open(b)?);
    loop {
        let left = a.fill_buf()?;
        let right = b.fill_buf()?;
        if left.is_empty() || right.is_empty() {
            return Ok(left.is_empty() && right.is_empty());
        }
        let n = left.len().min(right.len());
        if left[..n] != right[..n] {
            return Ok(false);
        }
        a.consume(n);
        b.consume(n);
    }
}

/// Parse the mode from the exact-file `ls -l` response. Refuse links, directories,
/// special files and unrecognized output instead of editing an ambiguous target.
fn file_mode(output: &str) -> Result<u32, String> {
    let mode = output
        .lines()
        .find_map(|line| {
            let mode = line.split_whitespace().next()?;
            (mode.starts_with('-') && mode.len() == 10).then_some(mode.as_bytes())
        })
        .ok_or("remote target is not a regular file or its permissions could not be read")?;
    let mut bits = 0;
    for (i, c) in mode[1..].iter().enumerate() {
        let allowed = match i % 3 {
            0 => b"r-".as_slice(),
            1 => b"w-".as_slice(),
            _ => b"x-sStT".as_slice(),
        };
        if !allowed.contains(c) {
            return Err("unrecognized remote permissions".into());
        }
        if matches!(c, b'r' | b'w' | b'x' | b's' | b't') {
            bits |= 1 << (8 - i);
        }
        if matches!(c, b's' | b'S') {
            bits |= if i == 2 { 0o4000 } else { 0o2000 };
        }
        if matches!(c, b't' | b'T') {
            bits |= 0o1000;
        }
    }
    Ok(bits)
}

fn fetch(
    paths: &EditPaths,
    dest: &Path,
    run: &mut impl FnMut(&str) -> Result<String, SftpFailure>,
) -> Result<u32, SftpFailure> {
    let remote = literal_path(&paths.remote)?;
    // Check type first; downloading a FIFO can block indefinitely.
    let mode = file_mode(&run(&format!("ls -l {remote}\n"))?)?;
    run(&format!("get {remote} {}\n", local_path(dest)?))?;
    Ok(mode)
}

pub fn run_operation(
    operation: EditOperation,
    mut run: impl FnMut(&str) -> Result<String, SftpFailure>,
) -> Result<EditOutcome, SftpFailure> {
    match operation {
        EditOperation::Download(paths) => {
            fetch(&paths, &paths.original, &mut run)?;
            fs::copy(&paths.original, &paths.local).map_err(|e| e.to_string())?;
            Ok(EditOutcome::Downloaded)
        }
        EditOperation::Save { paths, expected } => {
            if same_content(&paths.original, &paths.local).map_err(|e| e.to_string())? {
                return Ok(EditOutcome::Unchanged);
            }
            let snapshot = paths.root.join(format!("remote-{}", nonce()));
            let mode = fetch(&paths, &snapshot, &mut run)?;
            if !same_content(&expected, &snapshot).map_err(|e| e.to_string())? {
                return Ok(EditOutcome::Conflict { snapshot });
            }
            let suffix = nonce();
            let temp = format!("{}.sshm-part-{suffix}", paths.remote);
            let backup = format!("{}.sshm-bak-{suffix}", paths.remote);
            let (local, remote, tmp, bak) = (
                local_path(&paths.local)?,
                literal_path(&paths.remote)?,
                literal_path(&temp)?,
                literal_path(&backup)?,
            );
            // Same backup swap as the browser, but the original MUST exist and its
            // move MUST succeed. A failure leaves the edited local file untouched.
            let script = format!(
                "put {local} {tmp}\nchmod {mode:o} {tmp}\nrename {remote} {bak}\nrename {tmp} {remote}\n-rm {bak}\n"
            );
            run(&script).map_err(|mut e| {
                e.msg = format!("{}; remote recovery paths: {temp}, {backup}", e.msg);
                e
            })?;
            Ok(EditOutcome::Uploaded)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> EditPaths {
        EditPaths::create("/remote/file.txt".into(), "file.txt").unwrap()
    }

    #[test]
    fn editor_priority_arguments_and_windows_paths() {
        let c = EditorCommand::choose(Some("code --wait"), Some("vim")).unwrap();
        assert_eq!(c.program, "code");
        assert_eq!(c.args, ["--wait"]);
        let c = EditorCommand::choose(
            Some(" "),
            Some(r#""C:\Program Files\Notepad++\notepad++.exe" -multiInst -nosession"#),
        )
        .unwrap();
        assert_eq!(c.program, r"C:\Program Files\Notepad++\notepad++.exe");
        let path = Path::new("file with пробел and 'quote.txt");
        assert_eq!(c.command(path).get_args().last().unwrap(), path.as_os_str());
        assert!(EditorCommand::choose(None, None).is_err());
        assert!(EditorCommand::parse("vim 'unclosed").is_err());
        assert!(EditorCommand::parse("vim\nrm").is_err());
    }

    #[test]
    fn unchanged_content_never_contacts_server() {
        let p = paths();
        fs::write(&p.original, "same").unwrap();
        fs::write(&p.local, "same").unwrap();
        let result = run_operation(
            EditOperation::Save {
                paths: p.clone(),
                expected: p.original.clone(),
            },
            |_| panic!("unchanged file must not connect"),
        );
        assert!(matches!(result.unwrap(), EditOutcome::Unchanged));
        p.cleanup().unwrap();
    }

    #[test]
    fn content_comparison_detects_same_size_changes_and_large_files() {
        let p = paths();
        let mut bytes = vec![7u8; 100_000];
        fs::write(&p.original, &bytes).unwrap();
        fs::write(&p.local, &bytes).unwrap();
        assert!(same_content(&p.original, &p.local).unwrap());
        bytes[99_999] = 8;
        fs::write(&p.local, &bytes).unwrap();
        assert!(!same_content(&p.original, &p.local).unwrap());
        fs::write(&p.local, []).unwrap();
        assert!(!same_content(&p.original, &p.local).unwrap());
        p.cleanup().unwrap();
    }

    #[test]
    fn conflict_and_failed_upload_keep_local_edits() {
        let p = paths();
        fs::write(&p.original, "before").unwrap();
        fs::write(&p.local, "edited").unwrap();
        let mut puts = 0;
        let mut transport = |script: &str| -> Result<String, SftpFailure> {
            if script.starts_with("ls ") {
                return Ok("-rw-r----- 1 u g 6 Jan 1 2026 file.txt\n".into());
            }
            if script.starts_with("get ") {
                let dest = script.rsplit('"').nth(1).unwrap();
                fs::write(dest, "remote changed").unwrap();
                return Ok(String::new());
            }
            puts += 1;
            Err("disconnected during put".to_string().into())
        };
        let result = run_operation(
            EditOperation::Save {
                paths: p.clone(),
                expected: p.original.clone(),
            },
            &mut transport,
        )
        .unwrap();
        let EditOutcome::Conflict { snapshot } = result else {
            panic!("expected conflict")
        };
        assert_eq!(fs::read_to_string(&p.local).unwrap(), "edited");
        let err = run_operation(
            EditOperation::Save {
                paths: p.clone(),
                expected: snapshot,
            },
            &mut transport,
        )
        .unwrap_err();
        assert!(err.msg.contains("recovery paths"));
        assert_eq!(puts, 1);
        assert_eq!(fs::read_to_string(&p.local).unwrap(), "edited");
        p.cleanup().unwrap();
    }

    #[test]
    fn literal_paths_modes_and_unique_private_directories() {
        assert_eq!(literal_path("a 'b\" c").unwrap(), "\"a 'b\\\" c\"");
        assert!(literal_path("/tmp/a\nput x y").is_err());
        assert_eq!(
            file_mode("-rwsr-x--T 1 u g 0 Jan 1 2026 x").unwrap(),
            0o5750
        );
        assert!(file_mode("lrwxrwxrwx 1 u g 0 Jan 1 2026 x -> y").is_err());
        let a = paths();
        let b = paths();
        assert_ne!(a.root, b.root);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&a.root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        a.cleanup().unwrap();
        b.cleanup().unwrap();
    }
}
