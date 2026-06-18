import json
import base64
import os
import time
import hashlib
import logging
import sqlite3
import urllib.request
import socket
import threading

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [cert-watcher] %(message)s'
)

ACME_PATH = '/app/acme.json'
CERTS_DIR = '/app/certs'
DB_PATH = '/app/db/x-ui.db'
DOCKER_SOCK = '/var/run/docker.sock'
CONTAINER_NAME = '3xui_app'
ACME_CHECK_INTERVAL = 3600
# With this
ERROR_TRIGGERS = [
    'failed to parse certificate',
    'both file and bytes are empty',
    'failed to build TLS config',
]


def get_file_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None


def extract_certs(acme_path, certs_dir):
    extracted = []
    try:
        with open(acme_path) as f:
            data = json.load(f)

        for resolver, resolver_data in data.items():
            certs = resolver_data.get('Certificates', [])
            if not certs:
                logging.warning(f'No certificates found in resolver: {resolver}')
                continue

            for c in certs:
                domain = c['domain']['main']
                domain_dir = os.path.join(certs_dir, domain)
                os.makedirs(domain_dir, exist_ok=True)

                cert_path = os.path.join(domain_dir, 'fullchain.pem')
                key_path = os.path.join(domain_dir, 'privkey.pem')

                with open(cert_path, 'w') as f:
                    f.write(base64.b64decode(c['certificate']).decode())

                with open(key_path, 'w') as f:
                    f.write(base64.b64decode(c['key']).decode())

                logging.info(f'Extracted cert for: {domain} → {domain_dir}')
                extracted.append({
                    'domain': domain,
                    'cert': f'/root/cert/{domain}/fullchain.pem',
                    'key': f'/root/cert/{domain}/privkey.pem'
                })

    except Exception as e:
        logging.error(f'Failed to extract certs: {e}')

    return extracted


def update_xray_inbounds(db_path, extracted):
    if not extracted:
        return False

    updated_any = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT id, remark, stream_settings FROM inbounds")
        rows = cursor.fetchall()

        for row_id, remark, stream_json in rows:
            try:
                stream = json.loads(stream_json)
                tls = stream.get('tlsSettings', {})
                certs = tls.get('certificates', [])

                if not certs:
                    continue

                domain_info = extracted[0]
                cert_file = domain_info['cert']
                key_file = domain_info['key']

                for cert in certs:
                    old_cert = cert.get('certificateFile', 'empty')
                    old_key = cert.get('keyFile', 'empty')
                    cert['certificateFile'] = cert_file
                    cert['keyFile'] = key_file
                    logging.info(f'Inbound {row_id} ({remark}) cert: {old_cert} → {cert_file}')
                    logging.info(f'Inbound {row_id} ({remark}) key:  {old_key} → {key_file}')

                stream['tlsSettings']['certificates'] = certs
                cursor.execute(
                    "UPDATE inbounds SET stream_settings = ? WHERE id = ?",
                    (json.dumps(stream), row_id)
                )
                updated_any = True

            except Exception as e:
                logging.error(f'Failed to update inbound {row_id}: {e}')

        conn.commit()
        conn.close()
        logging.info('Database updated successfully')

    except Exception as e:
        logging.error(f'Failed to connect to database: {e}')

    return updated_any


def docker_request(method, path, body=None):
    """Make a raw HTTP request to Docker unix socket"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(DOCKER_SOCK)
        sock.settimeout(10)

        headers = f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n'
        if body:
            headers += f'Content-Length: {len(body)}\r\n'
        headers += '\r\n'

        sock.sendall(headers.encode())
        if body:
            sock.sendall(body.encode())

        response = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()
        return response.decode(errors='ignore')
    except Exception as e:
        logging.error(f'Docker request failed: {e}')
        return ''


def restart_3xui():
    logging.info('Restarting 3xui_app...')
    response = docker_request('POST', f'/containers/{CONTAINER_NAME}/restart')
    if '204' in response:
        logging.info('3xui_app restarted successfully')
    else:
        logging.warning(f'Unexpected restart response: {response[:100]}')


def get_container_id():
    """Get container ID for log streaming"""
    try:
        response = docker_request('GET', f'/containers/{CONTAINER_NAME}/json')
        data = json.loads(response.split('\r\n\r\n', 1)[1].split('\r\n', 1)[-1])
        return data['Id']
    except Exception as e:
        logging.error(f'Failed to get container ID: {e}')
        return None


def stream_container_logs(extracted_ref, stop_event):
    logging.info('Starting log watcher for 3xui_app...')
    last_fix_time = 0
    cooldown = 30

    while not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(DOCKER_SOCK)
            sock.settimeout(60)

            request = (
                f'GET /containers/{CONTAINER_NAME}/logs'
                f'?follow=1&stdout=1&stderr=1&tail=0 HTTP/1.1\r\n'
                f'Host: localhost\r\n\r\n'
            )
            sock.sendall(request.encode())

            # Skip HTTP headers
            header = b''
            while b'\r\n\r\n' not in header:
                header += sock.recv(1)

            status_line = header.decode(errors='ignore').split('\r\n')[0]
            logging.info(f'Docker log stream response: {status_line}')

            # Detect if multiplexed or raw stream
            is_multiplexed = 'multiplexed' in header.decode(errors='ignore').lower()
            is_raw = 'raw-stream' in header.decode(errors='ignore')
            logging.info(f'Stream type: {"multiplexed" if is_multiplexed else "raw"}')

            logging.info('Connected to 3xui_app log stream — watching for cert errors...')

            buffer = b''
            while not stop_event.is_set():
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk

                    # Process complete lines
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        log_line = line.decode(errors='ignore').strip()

                        # Strip docker frame header if multiplexed (8 bytes)
                        if is_multiplexed and len(log_line) > 8:
                            try:
                                frame_size = int.from_bytes(line[4:8], 'big')
                                log_line = line[8:8 + frame_size].decode(errors='ignore').strip()
                            except Exception:
                                pass

                        if not log_line:
                            continue

                        logging.debug(f'3xui: {log_line}')

                        if any(trigger in log_line for trigger in ERROR_TRIGGERS):
                            now = time.time()
                            if now - last_fix_time > cooldown:
                                logging.warning(f'Cert error detected: {log_line}')
                                logging.info('Fixing cert paths and restarting 3xui...')
                                time.sleep(2)
                                updated = update_xray_inbounds(DB_PATH, extracted_ref['data'])
                                if updated:
                                    restart_3xui()
                                last_fix_time = time.time()
                            else:
                                logging.info('Cert error detected but in cooldown — skipping')

                except socket.timeout:
                    continue

            sock.close()

        except Exception as e:
            logging.error(f'Log stream error: {e}')
            time.sleep(5)
    """Stream 3xui container logs and react to cert errors"""
    logging.info('Starting log watcher for 3xui_app...')

    # cooldown to avoid repeated restarts
    last_fix_time = 0
    cooldown = 30

    while not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(DOCKER_SOCK)
            sock.settimeout(60)

            # Stream logs since now, follow mode
            request = (
                f'GET /containers/{CONTAINER_NAME}/logs'
                f'?follow=1&stdout=1&stderr=1&tail=0 HTTP/1.1\r\n'
                f'Host: localhost\r\n\r\n'
            )
            sock.sendall(request.encode())

            # Skip HTTP headers
            header = b''
            while b'\r\n\r\n' not in header:
                header += sock.recv(1)

            logging.info('Connected to 3xui_app log stream')

            buffer = b''
            while not stop_event.is_set():
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk

                    # Docker log stream has 8-byte header per frame
                    while len(buffer) >= 8:
                        frame_size = int.from_bytes(buffer[4:8], 'big')
                        if len(buffer) < 8 + frame_size:
                            break

                        log_line = buffer[8:8 + frame_size].decode(errors='ignore').strip()
                        buffer = buffer[8 + frame_size:]

                        if log_line:
                            logging.debug(f'3xui: {log_line}')

                        # React to cert error
                        if any(trigger in log_line for trigger in ERROR_TRIGGERS):
                            now = time.time()
                            if now - last_fix_time > cooldown:
                                logging.warning(f'Cert error detected: {log_line}')
                                logging.info('Fixing cert paths and restarting 3xui...')
                                time.sleep(2)  # let 3xui finish writing DB
                                updated = update_xray_inbounds(DB_PATH, extracted_ref['data'])
                                if updated:
                                    restart_3xui()
                                last_fix_time = time.time()
                            else:
                                logging.info('Cert error detected but in cooldown — skipping')

                except socket.timeout:
                    continue

            sock.close()

        except Exception as e:
            logging.error(f'Log stream error: {e}')
            time.sleep(5)  # reconnect after error


def main():
    logging.info('Starting cert watcher...')

    for path in [ACME_PATH, DB_PATH]:
        while not os.path.exists(path):
            logging.info(f'Waiting for {path}...')
            time.sleep(5)

    logging.info('Waiting for 3xui to initialize...')
    time.sleep(10)

    # Initial cert extraction
    extracted = extract_certs(ACME_PATH, CERTS_DIR)
    update_xray_inbounds(DB_PATH, extracted)

    # Shared reference so log watcher thread always has latest certs
    extracted_ref = {'data': extracted}

    last_acme_hash = get_file_hash(ACME_PATH)
    last_acme_check = time.time()

    # Start log watcher in background thread
    stop_event = threading.Event()
    log_thread = threading.Thread(
        target=stream_container_logs,
        args=(extracted_ref, stop_event),
        daemon=True
    )
    log_thread.start()

    logging.info(f'Watching acme.json every {ACME_CHECK_INTERVAL}s')
    logging.info(f'Watching 3xui logs for: {ERROR_TRIGGERS}')

    # Main loop — only checks acme.json for renewal
    while True:
        time.sleep(60)
        now = time.time()

        if now - last_acme_check >= ACME_CHECK_INTERVAL:
            current_acme_hash = get_file_hash(ACME_PATH)
            if current_acme_hash != last_acme_hash:
                logging.info('acme.json changed — extracting new certs...')
                extracted = extract_certs(ACME_PATH, CERTS_DIR)
                extracted_ref['data'] = extracted  # update shared ref
                update_xray_inbounds(DB_PATH, extracted)
                restart_3xui()
                last_acme_hash = current_acme_hash
            else:
                logging.info('acme.json unchanged')
            last_acme_check = now


if __name__ == '__main__':
    main()