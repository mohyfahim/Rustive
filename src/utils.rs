use log::debug;
use std::io::{self, ErrorKind};
use std::process::{Output, Stdio};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::select;
use tokio::time::{self, Duration};

use crate::errors::RustiveError;

/// Executes a shell script asynchronously with the given arguments and timeout.
///
/// Assumes the script is executable (e.g., has execute permissions and a shebang like #!/bin/sh).
/// Returns the process output (including stdout, stderr, and exit status) on success.
/// If the execution times out, the process is killed and an io::Error with ErrorKind::TimedOut is returned.
///
/// # Arguments
/// * `script_path` - The path to the shell script.
/// * `args` - A vector of arguments to pass to the script.
/// * `timeout_duration` - The maximum duration to allow the script to run.
///
/// # Returns
/// * `Ok(Output)` - The output of the process if it completes within the timeout.
/// * `Err(io::Error)` - If spawning fails, I/O error occurs, or timeout is reached.
pub async fn execute_shell_script(
    script_path: &str,
    args: Vec<String>,
    timeout_duration: Duration,
) -> Result<Output, RustiveError> {
    let mut cmd = Command::new(script_path);
    cmd.args(args.clone());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    let mut stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stderr = child.stderr.take().expect("Failed to open stderr");

    let read_stdout = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf).await;
        buf
    });

    let read_stderr = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });

    debug!("run: {} {:?}", script_path, args);

    let status = select! {
        res = child.wait() => {
            match res {
                Ok(status) => {
                    debug!("runsss: {} {:?}", script_path, args);
                    status},
                Err(e) => {
                    debug!("runeee: {} {:?}", script_path, args);
                    let _ = read_stdout.await;
                    let _ = read_stderr.await;
                    return Err(RustiveError::CommandExecutionFailed(script_path.to_string()));
                }
            }
        }
        _ =time::sleep(timeout_duration) => {
            debug!("Timeout is occurred");
            let _ = child.kill().await;
            // Wait for the process to exit after kill
            let _ = child.wait().await;
            // Await reads to clean up, even though we're not using the output
            let _ = read_stdout.await;
            let _ = read_stderr.await;
            return Err(RustiveError::Timeout);
        }
    };

    debug!("run end");

    let stdout_buf = read_stdout
        .await
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    let stderr_buf = read_stderr
        .await
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    Ok(Output {
        status,
        stdout: stdout_buf,
        stderr: stderr_buf,
    })
}
