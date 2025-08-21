# Scan-It

**Scan-It** is a lightweight, multi-threaded TCP port scanner written in Python. It is designed for network reconnaissance and penetration testing, providing a fast and customizable scanning experience similar to Nmap, but smaller and beginner-friendly.

---

## Features

- Scan top 1000 TCP ports by default (based on Nmap default scan list)
- Option to scan custom port ranges
- Multi-threaded scanning for faster results
- Adjustable number of threads and scan speed (slow, medium, fast)
- Mini man page built-in for quick usage instructions
- Outputs open ports in real-time

---

## Installation

Clone this repository:
```bash
git clone https://github.com/FaroukAbbas1/Scan-It.git
cd Scan-It
```

## Usage
```bash
python3 scan_it.py <target> [options]
```
## Arguments
Option:
<target> : Target host to scan (IP address or domain)
-p, --ports : Port range to scan (example: 20-1024). Default: top 1000 TCP ports
-t, --threads : Number of threads to use. Default depends on chosen speed preset
-s, --speed : Scan speed: slow, medium (default), fast. Adjusts timeout and number of threads

## Examples
Scan top 1000 ports on a target using default settings:
```bash
python3 scan_it.py 192.168.1.1
```
Scan a custom range of ports with 50 threads and fast speed:
```bash
python3 scan_it.py 192.168.1.1 -p 20-500 -t 50 -s fast
```
## Requirements
- Python 3.6 or higher

## Notes
- This tool is for educational and authorized testing purposes only. Use it responsibly and only on networks you own or have explicit permission to scan.
- Open ports will be displayed in real-time. Closed or filtered ports are silently ignored for speed.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
- Farouk Abbas
- GitHub: https://github.com/FaroukAbbas1
- Email: faroukabbas646@gmail.com


