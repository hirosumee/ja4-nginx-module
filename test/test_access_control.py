import subprocess
import pytest
from pathlib import Path
import time
import re
import sys

# Pinned curl image for reproducible TLS stack
CURL_IMG = "alpine/curl:8.14.1@sha256:4007cdf991c197c3412b5af737a916a894809273570b0c2bb93d295342fc23a2"
# URL for curl
URL = "https://localhost"
# Path to nginx.conf on host
NGINX_CONF_PATH = Path(__file__).parent.parent / "nginx_utils" / "nginx.conf"

@pytest.fixture(scope="module")
def restore_nginx_conf():
    if not NGINX_CONF_PATH.exists():
        pytest.fail(f"nginx.conf not found at {NGINX_CONF_PATH}")
    original_conf = NGINX_CONF_PATH.read_text()
    yield
    NGINX_CONF_PATH.write_text(original_conf)
    reload_nginx()

def reload_nginx():
    # reload nginx in the container
    subprocess.run(["docker", "exec", "ja4-nginx", "/etc/nginx/sbin/nginx", "-s", "reload"], check=True)

def run_curl(args: list[str] = None) -> str:
    if args is None:
        args = []
    # Use -k for insecure (self-signed cert), -sS for silent but errors
    # Note: capturing stdout means we get the body.
    curl_cmd = f"curl -k -sS {' '.join(args)} {URL}"
    cmd = [
        "docker", "run", "--rm", "--network", "host", CURL_IMG,
        "sh", "-lc", curl_cmd
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def get_fingerprints():
    # We need to get fingerprints initially.
    # The default nginx.conf uses 'return 200' which is fine for this initial fetch IF we haven't injected deny rules yet.
    # The 'run_curl' output contains the body.
    output = run_curl(["-v"]) # -v to see headers if needed, but run_curl returns stdout (body)
    
    # We'll rely on the default config's body output for initial discovery
    ja4_m = re.search(r"JA4: (\S+)", output)
    ja4h_m = re.search(r"JA4H: (\S+)", output)
    ja4one_m = re.search(r"JA4one: (\S+)", output)
    
    if not (ja4_m and ja4h_m and ja4one_m):
        # Fallback: maybe we are in the "headers" mode?
        # But initially we restore default conf which has body.
        pytest.fail(f"Could not get fingerprints from body. Output:\n{output}")
        
    return ja4_m.group(1), ja4h_m.group(1), ja4one_m.group(1)

def test_access_control(restore_nginx_conf):
    # Get current fingerprints using default config
    print("Getting fingerprints...")
    ja4, ja4h, ja4one = get_fingerprints()
    print(f"Captured JA4: {ja4}, JA4H: {ja4h}, JA4one: {ja4one}")

    # Now we overwrite nginx.conf with a version that DOES NOT use 'return'
    # so that Access Phase is not skipped.
    # We will use 'root' to serve static file and 'add_header' to verify presence.
    
    # Ensure index.html exists
    # We use multiple commands to be robust against different paths.
    # The container mounts nginx.conf at /etc/nginx/conf/nginx.conf (based on docker-compose).
    # So certificates are at /etc/nginx/conf/server.crt
    
    setup_cmd = (
        "mkdir -p /etc/nginx/html && "
        "echo 'ok' > /etc/nginx/html/index.html"
    )
    subprocess.run(["docker", "exec", "ja4-nginx", "sh", "-c", setup_cmd], check=True)

    def write_test_conf(directives):
        conf = f"""
worker_processes  1;
events {{
    worker_connections  1024;
}}
http {{
    include       mime.types;
    default_type  application/octet-stream;
    
    server {{
        listen       443 ssl;
        server_name  localhost;

        ssl_certificate      /etc/nginx/conf/server.crt;
        ssl_certificate_key  /etc/nginx/conf/server.key;

        location / {{
            {directives}
            
            add_header X-JA4 $http_ssl_ja4;
            add_header X-JA4H $http_ssl_ja4h;
            add_header X-JA4one $http_ssl_ja4one;
            
            root /etc/nginx/html;
            index index.html;
        }}
    }}
}}
"""
        NGINX_CONF_PATH.write_text(conf)
        reload_nginx()
        time.sleep(1)

    # 1. Block JA4
    print("\n[TEST] Blocking JA4...")
    write_test_conf(f"ja4_deny {ja4};")
    output = run_curl(["-v"]) # capture stderr for headers? run_curl captures stdout.
    # We need to capture stderr to see headers/status with -v, 
    # OR simpler: check stdout (body). 
    # If 403, body is usually standard 403 page.
    # checking output for "403 Forbidden" title or text is still valid.
    # But run_curl only returns stdout.
    # Let's check run_curl implementation. 
    # It returns result.stdout. -sS sends error to stderr. 
    # If 403, curl usually prints the error page body to stdout.
    # So checking for "403 Forbidden" in output (body) is correct.
    
    if "403 Forbidden" not in output and "<title>403 Forbidden</title>" not in output:
        # Debug: print what we got
        print(f"DEBUG Output: {output}")
        # Could be that we didn't receive the body?
        # But standard Nginx 403 page has body.
        pytest.fail(f"Expected 403 Forbidden, got success/other.")
    print("PASS: JA4 blocked")

    # 2. Allow JA4, deny all
    print("\n[TEST] Allowing JA4 + deny all...")
    write_test_conf(f"ja4_allow {ja4};\n            ja4_deny all;")
    output = run_curl(["-i"]) # -i for GET with headers
    if "200" not in output: 
        print(f"DEBUG Output: {output}")
        pytest.fail("Expected 200 OK")
    if f"X-JA4: {ja4}" not in output:
         pytest.fail("Expected X-JA4 header")
    print("PASS: JA4 allowed")
    
    # 3. Block JA4H
    print("\n[TEST] Blocking JA4H...")
    write_test_conf(f"ja4h_deny {ja4h};")
    output = run_curl()
    if "403 Forbidden" not in output:
        pytest.fail("Expected 403 Forbidden")
    print("PASS: JA4H blocked")

    # 4. Allow JA4H, deny all
    print("\n[TEST] Allowing JA4H + deny all...")
    write_test_conf(f"ja4h_allow {ja4h};\n            ja4h_deny all;")
    output = run_curl(["-i"])
    if "200" not in output:
        pytest.fail("Expected 200 OK")
    if f"X-JA4H: {ja4h}" not in output:
        pytest.fail("Expected X-JA4H header")
    print("PASS: JA4H allowed")

    # 5. Block JA4one
    print("\n[TEST] Blocking JA4one...")
    write_test_conf(f"ja4one_deny {ja4one};")
    output = run_curl()
    if "403 Forbidden" not in output:
        pytest.fail("Expected 403 Forbidden")
    print("PASS: JA4one blocked")

    # 6. Allow JA4one, deny all
    print("\n[TEST] Allowing JA4one + deny all...")
    write_test_conf(f"ja4one_allow {ja4one};\n            ja4one_deny all;")
    output = run_curl(["-i"])
    if "200" not in output:
        pytest.fail("Expected 200 OK")
    if f"X-JA4one: {ja4one}" not in output:
        pytest.fail("Expected X-JA4one header")
    print("PASS: JA4one allowed")

