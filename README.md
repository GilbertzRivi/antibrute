# Port Request Rate Limiter

A Python script designed to monitor incoming network traffic and block requests from IP addresses that exceed a configurable request rate on a specific port. This project uses `iptables` to dynamically block and unblock IPs, ensuring protection against DoS attacks or abusive traffic.

## Features

- **Dynamic IP Blocking:** Automatically bans IP addresses exceeding a predefined request rate.
- **Configurable Time Windows:** Monitor and enforce request limits over a specific time frame.
- **Incremental Ban Durations:** Implements exponential backoff for repeated offenders.
- **Logging:** Logs all ban/unban activities and requests for monitoring and auditing.
- **SQL-Based Tracking:** Uses SQLite to manage requests, bans, and timeout configurations.

## Requirements

- Python 3.x
- SQLite3
- `iptables` with proper permissions
- Linux-based operating system (for `iptables` compatibility)

## Prerequisites

### 1. Set Up `iptables` Logging

Ensure `iptables` is configured to log incoming traffic on the monitored port. For example, to log traffic on port `8080`:

    sudo iptables -A INPUT -p tcp --dport 8080 -j LOG --log-prefix "MONITORED TRAFFIC: "

### 2. Run with `sudo`

The script requires elevated privileges to modify `iptables` rules. Ensure you run the script with `sudo`:

    sudo python3 main.py

## Configuration

The script uses a `config.json` file for customization. Below are the configurable parameters:

- `interface`: Network interface to monitor (e.g., `eth0`).
- `server_port`: The target port for monitoring traffic.
- `request_limit`: Maximum allowed requests per `time_window` before banning.
- `time_window`: Time duration (in seconds) for rate-limiting.
- `base_timeout`: Base timeout for reducing ban counters.
- `initial_ban_duration`: Initial ban duration (in seconds).
- `db_path`: Path to the SQLite database file.
- `log_file`: Path to the log file.

### Example `config.json`

    {
        "interface": "eth0",
        "server_port": "8080",
        "request_limit": 100,
        "time_window": 60,
        "base_timeout": 300,
        "initial_ban_duration": 60,
        "db_path": "traffic_monitor.db",
        "log_file": "monitor.log"
    }

## Usage

1. Ensure you have the necessary privileges to manage `iptables`.
2. Create and configure the `config.json` file.
3. Run the script with `sudo`:
4. Monitor the `log_file` for real-time updates on traffic and bans.

## How It Works

1. **Traffic Monitoring:** The script uses the Linux `syslog` to monitor network traffic for the specified port.
2. **Request Tracking:** Each request is logged in an SQLite database.
3. **Rate Limiting:** If an IP exceeds the request limit within the defined time window, it is banned using `iptables`.
4. **Ban Management:** Expired bans are lifted automatically, and repeat offenders face exponentially longer bans.

## Limitations

- Only supports Linux systems due to the dependency on `iptables`.
- Requires access to system logs (`/var/log/syslog`).

## License

This project is open-source and available under the MIT License.

## Contribution

Feel free to open issues or submit pull requests to improve this project!
