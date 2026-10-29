#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const FIXTURES_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
    const RETRY_INTERVAL: Duration = Duration::from_millis(50);
    const UNREACHABLE_UPSTREAM: &str = "127.0.0.1:9";

    struct RunningProxy {
        process: Child,
    }

    impl Drop for RunningProxy {
        fn drop(&mut self) {
            if let Err(error) = self.process.kill() {
                eprintln!("failed to stop the proxy: {error}");
            }
            if let Err(error) = self.process.wait() {
                eprintln!("failed to reap the proxy: {error}");
            }
        }
    }

    fn unused_local_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|address| address.port())
            .expect("no free local port")
    }

    fn start_proxy(https_port: u16, http_port: u16) -> RunningProxy {
        let process = Command::new(env!("CARGO_BIN_EXE_host-proxy"))
            .env(
                "HOST_PROXY_ROUTES",
                format!("example.org={UNREACHABLE_UPSTREAM}"),
            )
            .env(
                "HOST_PROXY_CERTIFICATES",
                format!(
                    "{FIXTURES_DIRECTORY}/example.org.cert.pem:{FIXTURES_DIRECTORY}/example.org.key.pem"
                ),
            )
            .env("HOST_PROXY_HTTPS_ADDRESSES", format!("127.0.0.1:{https_port}"))
            .env("HOST_PROXY_HTTP_ADDRESSES", format!("127.0.0.1:{http_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start host-proxy");
        RunningProxy { process }
    }

    fn connect_when_listening(port: u16, proxy: &mut RunningProxy) -> TcpStream {
        let started_at = Instant::now();
        loop {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
                return stream;
            }
            if let Some(status) = proxy.process.try_wait().expect("failed to poll host-proxy") {
                panic!("host-proxy exited before listening: {status}");
            }
            assert!(
                started_at.elapsed() < STARTUP_TIMEOUT,
                "host-proxy never listened on port {port}"
            );
            thread::sleep(RETRY_INTERVAL);
        }
    }

    fn exchange(mut stream: TcpStream, request: &str) -> String {
        stream
            .set_read_timeout(Some(STARTUP_TIMEOUT))
            .expect("failed to set a read timeout");
        stream
            .write_all(request.as_bytes())
            .expect("failed to send the request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("failed to read the response");
        response
    }

    #[test]
    fn accepted_connections_are_answered() {
        let (https_port, http_port) = (unused_local_port(), unused_local_port());
        let mut proxy = start_proxy(https_port, http_port);

        for attempt in ["first", "second"] {
            let stream = connect_when_listening(http_port, &mut proxy);
            let response = exchange(
                stream,
                "GET /quotes?page=2 HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n",
            );

            assert!(
                response.starts_with("HTTP/1.1 301"),
                "the {attempt} request got {response:?}"
            );
            assert!(
                response
                    .to_ascii_lowercase()
                    .contains("location: https://example.org/quotes?page=2"),
                "the {attempt} request got {response:?}"
            );
        }
    }
}
