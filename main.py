import json
import sqlite3
import time
import subprocess
import re
from threading import Thread

with open("config.json") as config_file:
    config = json.load(config_file)

interface = config["interface"]
server_port = config["server_port"]
request_limit = config["request_limit"]
time_window = config["time_window"]
base_timeout = config["base_timeout"]
initial_ban_duration = config["initial_ban_duration"]
db_path = config["db_path"]
log_file = config["log_file"]

blocked_ips = []

result = subprocess.run(
    ["iptables", "-L", "INPUT", "-v", "-n"], capture_output=True, text=True
)
rules = result.stdout.splitlines()
for rule in rules:
    if "DROP" in rule or "REJECT" in rule:
        match = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", rule)
        if match:
            blocked_ips.append(match.group(1))


def get_db_connection():
    return sqlite3.connect(db_path, check_same_thread=False)


conn = get_db_connection()
cursor = conn.cursor()

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS requests (
    ip TEXT,
    timestamp INTEGER
)
"""
)
cursor.execute(
    """
CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    ban_end INTEGER,
    ban_duration INTEGER
)
"""
)
cursor.execute(
    """
CREATE TABLE IF NOT EXISTS ban_count (
    ip TEXT PRIMARY KEY,
    timeout INTEGER,
    ban_number INTEGER
)    
"""
)
conn.commit()


def is_blocked(ip):
    return ip in blocked_ips


def log_message(message):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
    with open(log_file, "a") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")


def ban_ip(ip, duration, ban_number, timeout):
    ban_end = int(time.time()) + duration
    cursor.execute(
        """
    INSERT OR REPLACE INTO bans (ip, ban_end, ban_duration) VALUES (?, ?, ?)
    """,
        (
            ip,
            ban_end,
            duration,
        ),
    )
    cursor.execute(
        """
    INSERT OR REPLACE INTO ban_count (ip, timeout, ban_number) VALUES (?, ?, ?)
    """,
        (
            ip,
            timeout,
            ban_number,
        ),
    )
    conn.commit()
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    blocked_ips.append(ip)
    log_message(f"IP {ip} banned for {duration} seconds | happened {ban_number} times.")


def unban_ip(ip, conn, cursor):
    cursor.execute("DELETE FROM bans WHERE ip = ?", (ip,))
    conn.commit()
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    blocked_ips.remove(ip)
    log_message(f"IP {ip} unbanned.")


def monitor_bans():
    conn = get_db_connection()
    cursor = conn.cursor()
    while True:
        current_time = int(time.time())
        cursor.execute("SELECT ip FROM bans WHERE ban_end <= ?", (current_time,))
        to_unban = cursor.fetchall()
        for ip in to_unban:
            unban_ip(ip[0], conn, cursor)
        time.sleep(1)


def process_request(ip):
    current_time = int(time.time())
    cursor.execute(
        """
    INSERT INTO requests (ip, timestamp) VALUES (?, ?)
    """,
        (
            ip,
            current_time,
        ),
    )
    conn.commit()

    cursor.execute(
        """
    SELECT COUNT(*) FROM requests WHERE ip = ? AND timestamp >= ?
    """,
        (
            ip,
            current_time - time_window,
        ),
    )
    request_count = cursor.fetchone()[0]

    if request_count > request_limit and not is_blocked(ip):
        cursor.execute(
            """
        SELECT ban_duration FROM bans WHERE ip = ?
        """,
            (ip,),
        )
        result = cursor.fetchone()

        if result:  # IP było już banowane
            duration = int(result[0])
        else:
            duration = initial_ban_duration

        cursor.execute(
            """
        SELECT ban_number FROM ban_count WHERE ip = ?
        """,
            (ip,),
        )
        result = cursor.fetchone()
        if result:
            ban_number = int(result[0])
        else:
            ban_number = 0
        ban_number += 1
        new_duration = duration * pow(2, ban_number)
        if new_duration > 2147483647:
            new_duration = 2147483647

        timeout = int(time.time()) + base_timeout

        ban_ip(ip, new_duration, ban_number, timeout)


def delete_old_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    while True:
        current_time = int(time.time())
        cursor.execute(
            """
        DELETE FROM requests WHERE timestamp <= ?
        """,
            (current_time - 24 * 60 * 60,),
        )
        conn.commit()
        time.sleep(60)


def monitor_traffic():
    log_message("Started monitoring traffic.")

    with subprocess.Popen(
        ["tail", "-f", "/var/log/syslog"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as proc:
        try:
            for line in iter(proc.stdout.readline, b""):
                line = line.decode("utf-8").strip()

                if "SRC=" in line and f"DPT={server_port}" in line:
                    match = re.search(r"SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                    if match:
                        ip = match.group(1)
                        process_request(ip)
        except Exception as e:
            log_message(f"Error in monitor_traffic: {str(e)}")
        finally:
            proc.terminate()
            log_message("Stopped monitoring traffic.")


def monitor_timeout():
    conn = get_db_connection()
    cursor = conn.cursor()
    while True:
        cursor.execute(
            """
            SELECT ip, timeout, ban_number FROM ban_count WHERE timeout <= ?
        """,
            (int(time.time()),),
        )
        result = cursor.fetchall()
        for row in result:
            ip = row[0]
            timeout = int(row[1]) + base_timeout
            number = int(row[2]) - 1
            if number <= 0:
                cursor.execute(
                    """
                    DELETE FROM ban_count WHERE ip = ?
                """,
                    (ip,),
                )
                conn.commit()
            else:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO ban_count (ip, timeout, ban_number) VALUES (?, ?, ?)
                """,
                    (ip, timeout, number),
                )
                conn.commit()


if __name__ == "__main__":
    try:
        ban_thread = Thread(target=monitor_bans, daemon=True)
        ban_thread.start()
        timeout_thread = Thread(target=monitor_timeout, daemon=True)
        timeout_thread.start()

        monitor_traffic()

    except KeyboardInterrupt:
        log_message("Script terminated.")
    except Exception as e:
        log_message(f"Error: {e.with_traceback()}")
    finally:
        conn.close()
