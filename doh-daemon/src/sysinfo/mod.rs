use std::{fs, io};
use std::path::Path;

pub fn get_process_name(pid: u32) -> io::Result<String> {
    // Validate PID
    if pid == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "PID cannot be 0"));
    }

    // Try reading from /proc/<pid>/comm (preferred, contains only the process name)
    let comm_path = format!("/proc/{}/comm", pid);
    if Path::new(&comm_path).exists() {
        let name = fs::read_to_string(&comm_path)?
            .trim()
            .to_string();
        if !name.is_empty() {
            return Ok(name);
        }
    }

    // Fallback to /proc/<pid>/cmdline if comm is unavailable or empty
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if Path::new(&cmdline_path).exists() {
        let cmdline = fs::read(&cmdline_path)?;
        // cmdline is null-separated; take the first part (process name)
        let name = cmdline
            .split(|&b| b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).to_string())
            .unwrap_or_default();
        if !name.is_empty() {
            return Ok(name);
        }
    }

    // Return error if neither file provided a valid name
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("No valid process name found for PID {}", pid),
    ))
}