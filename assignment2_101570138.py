"""
Author: Anthony Huete-Jacobs
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# This dictionary stores common port numbers and their service names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3:
    # Using @property and @target.setter lets the program control how the private target value is accessed and updated.
    # This is better than direct attribute access because validation can be added in one place without changing the rest
    # of the code. In this class, the setter prevents an empty target from being stored.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
            return
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1:
# PortScanner reuses code from NetworkTool through inheritance, so it does not need to rewrite the target storage,
# property methods, or the base cleanup behavior. For example, PortScanner calls super().__init__(target) to use the
# parent constructor and automatically gets access to the target property defined in NetworkTool.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None

        # Q4:
        # Without try-except, a socket error on an unreachable target or a connection problem could stop the whole scan.
        # That would make the program crash before the remaining ports are checked. Exception handling keeps the program
        # running and reports which port caused the problem.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            try:
                self.scan_results.append((port, status, service_name))
            finally:
                self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock is not None:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2:
    # Threading lets the scanner check many ports at nearly the same time instead of waiting for each connection attempt
    # to finish one by one. If 1024 ports were scanned sequentially, the scan could take much longer because each closed
    # or timed-out port would delay the next check. Using threads makes the scan faster and more efficient.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def save_results(target, results):
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
            """
        )

        for port, status, service in results:
            cursor.execute(
                """
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn is not None:
            conn.close()


def load_past_scans():
    if not os.path.exists("scan_history.db"):
        print("No past scans found.")
        return

    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
            return

        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
    except sqlite3.Error:
        print("No past scans found.")
    finally:
        if conn is not None:
            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    while True:
        try:
            start_port = int(input("Enter starting port number (1-1024): "))
            if start_port < 1 or start_port > 1024:
                print("Port must be between 1 and 1024.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    while True:
        try:
            end_port = int(input("Enter ending port number (1-1024): "))
            if end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
                continue
            if end_port < start_port:
                print("End port must be greater than or equal to start port.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    show_history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if show_history == "yes":
        load_past_scans()


# Q5:
# One useful new feature would be a service summary that groups only the open ports by service name and shows how many
# open ports belong to each service category. This could use a list comprehension to first filter open results and then
# a nested if-statement to count known services differently from "Unknown" ones. Diagram: See diagram_101570138.png in the repository root.
