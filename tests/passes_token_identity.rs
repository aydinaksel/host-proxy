#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::{Duration, Instant};

    use openssl::sha::sha256;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    const FIXTURES_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    const HOSTNAME: &str = "example.org";
    const TENANT_HEADER: &str = "X-Scope-OrgID";
    const PUSH_PATH: &str = "/loki/api/v1/push";
    const QUERY_PATH: &str = "/loki/api/v1/query_range";
    const PAN_TOKEN: &str = "pan-ingest-token";
    const PAN_IDENTITY: &str = "fbrmarble.pan";
    const ATLAS_TOKEN: &str = "atlas-ingest-token";
    const ATLAS_IDENTITY: &str = "chichek.atlas";
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
    const UPSTREAM_SILENCE: Duration = Duration::from_millis(500);
    const RETRY_INTERVAL: Duration = Duration::from_millis(50);

    struct RunningProxy {
        process: Child,
        digest_file_path: PathBuf,
    }

    impl Drop for RunningProxy {
        fn drop(&mut self) {
            if let Err(error) = self.process.kill() {
                eprintln!("failed to stop the proxy: {error}");
            }
            if let Err(error) = self.process.wait() {
                eprintln!("failed to reap the proxy: {error}");
            }
            if let Err(error) = std::fs::remove_file(&self.digest_file_path) {
                eprintln!("failed to remove the digest file: {error}");
            }
        }
    }

    fn unused_local_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|address| address.port())
            .expect("no free local port")
    }

    fn hexadecimal_digest(token: &str) -> String {
        sha256(token.as_bytes())
            .iter()
            .fold(String::new(), |mut digest, byte| {
                write!(digest, "{byte:02x}").expect("writing to a String cannot fail");
                digest
            })
    }

    fn write_digest_file(https_port: u16) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "host-proxy-identity-digests-{}-{https_port}",
            std::process::id()
        ));
        let contents = format!(
            "{} {PAN_IDENTITY}\n{} {ATLAS_IDENTITY}\n",
            hexadecimal_digest(PAN_TOKEN),
            hexadecimal_digest(ATLAS_TOKEN)
        );
        std::fs::write(&path, contents).expect("failed to write the digest file");
        path
    }

    fn start_upstream() -> (u16, Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind the upstream");
        let port = listener
            .local_addr()
            .expect("the upstream has no address")
            .port();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let request_head = answer_upstream_request(stream);
                if sender.send(request_head).is_err() {
                    return;
                }
            }
        });
        (port, receiver)
    }

    fn answer_upstream_request(stream: TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut request_head = String::new();
        let mut line = String::new();
        while reader.read_line(&mut line).is_ok_and(|length| length > 0) && line != "\r\n" {
            request_head.push_str(&line);
            line.clear();
        }
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(error) = reader.get_mut().write_all(response.as_bytes()) {
            eprintln!("the upstream failed to answer: {error}");
        }
        request_head
    }

    fn start_proxy(https_port: u16, upstream_port: u16) -> RunningProxy {
        let digest_file_path = write_digest_file(https_port);
        let route = format!(
            "{HOSTNAME}=127.0.0.1:{upstream_port}!bearer-sha256={}!paths={PUSH_PATH}!identity-header={TENANT_HEADER}",
            digest_file_path.display()
        );
        let process = Command::new(env!("CARGO_BIN_EXE_host-proxy"))
            .env("HOST_PROXY_ROUTES", route)
            .env(
                "HOST_PROXY_CERTIFICATES",
                format!(
                    "{FIXTURES_DIRECTORY}/example.org.cert.pem:{FIXTURES_DIRECTORY}/example.org.key.pem"
                ),
            )
            .env("HOST_PROXY_HTTPS_ADDRESSES", format!("127.0.0.1:{https_port}"))
            .env("HOST_PROXY_HTTP_ADDRESSES", format!("127.0.0.1:{}", unused_local_port()))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start host-proxy");
        RunningProxy {
            process,
            digest_file_path,
        }
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

    fn send_over_tls(stream: TcpStream, request: &str) -> String {
        let mut connector_builder =
            SslConnector::builder(SslMethod::tls()).expect("failed to build a TLS connector");
        connector_builder.set_verify(SslVerifyMode::NONE);
        let mut tls_stream = connector_builder
            .build()
            .connect(HOSTNAME, stream)
            .expect("the TLS handshake failed");
        tls_stream
            .write_all(request.as_bytes())
            .expect("failed to send the request");
        let mut response = String::new();
        if let Err(error) = tls_stream.read_to_string(&mut response) {
            eprintln!("the response ended uncleanly: {error}");
        }
        response
    }

    fn request(method: &str, path: &str, token: &str, extra_headers: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {HOSTNAME}\r\nAuthorization: Bearer {token}\r\n\
             {extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    fn tenant_headers_in(request_head: &str) -> Vec<String> {
        request_head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case(TENANT_HEADER))
            .map(|(_, value)| value.trim().to_string())
            .collect()
    }

    #[test]
    fn the_upstream_sees_only_the_identity_of_the_presented_token() {
        let (upstream_port, upstream_requests) = start_upstream();
        let https_port = unused_local_port();
        let mut proxy = start_proxy(https_port, upstream_port);

        let forged = request(
            "POST",
            PUSH_PATH,
            PAN_TOKEN,
            &format!("{TENANT_HEADER}: {ATLAS_IDENTITY}\r\n"),
        );
        let response = send_over_tls(connect_when_listening(https_port, &mut proxy), &forged);
        assert!(response.starts_with("HTTP/1.1 204"), "got {response:?}");
        let pan_request = upstream_requests
            .recv_timeout(STARTUP_TIMEOUT)
            .expect("the push never reached the upstream");
        assert_eq!(tenant_headers_in(&pan_request), vec![PAN_IDENTITY]);

        let atlas = request("POST", PUSH_PATH, ATLAS_TOKEN, "");
        let response = send_over_tls(connect_when_listening(https_port, &mut proxy), &atlas);
        assert!(response.starts_with("HTTP/1.1 204"), "got {response:?}");
        let atlas_request = upstream_requests
            .recv_timeout(STARTUP_TIMEOUT)
            .expect("the push never reached the upstream");
        assert_eq!(tenant_headers_in(&atlas_request), vec![ATLAS_IDENTITY]);
    }

    #[test]
    fn a_valid_token_cannot_reach_a_path_outside_the_allowed_ones() {
        let (upstream_port, upstream_requests) = start_upstream();
        let https_port = unused_local_port();
        let mut proxy = start_proxy(https_port, upstream_port);

        for path in [QUERY_PATH, "/loki/api/v1/push/../query_range", "/"] {
            let query = request("GET", path, PAN_TOKEN, "");
            let response = send_over_tls(connect_when_listening(https_port, &mut proxy), &query);
            assert!(
                response.starts_with("HTTP/1.1 403"),
                "{path} got {response:?}"
            );
        }
        assert!(
            upstream_requests.recv_timeout(UPSTREAM_SILENCE).is_err(),
            "a forbidden path reached the upstream"
        );
    }

    #[test]
    fn an_unknown_token_is_refused_before_the_upstream() {
        let (upstream_port, upstream_requests) = start_upstream();
        let https_port = unused_local_port();
        let mut proxy = start_proxy(https_port, upstream_port);

        let unknown = request("POST", PUSH_PATH, "unknown-token", "");
        let response = send_over_tls(connect_when_listening(https_port, &mut proxy), &unknown);
        assert!(response.starts_with("HTTP/1.1 401"), "got {response:?}");
        assert!(
            upstream_requests.recv_timeout(UPSTREAM_SILENCE).is_err(),
            "an unauthenticated push reached the upstream"
        );
    }
}
