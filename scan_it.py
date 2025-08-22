#!/usr/bin/env python3
"""
Scan-It: Mini TCP Port Scanner
Author: Your Name
GitHub: https://github.com/yourusername/Scan-It
Description: Lightweight, multi-threaded TCP port scanner with customizable ports, threads, and speed presets.
"""

import socket        # For network connections
import threading     # For multi-threaded scanning
import argparse      # For command-line arguments
from datetime import datetime


print("=== Scan-It ===")


# mini man page

parser = argparse.ArgumentParser(description="Scan-It: Mini TCP Port Scanner")
parser.add_argument("host", help="Target host to scan (IP or domain)")
parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 20-500). Default: top 1000 ports")
parser.add_argument("-t", "--threads", type=int, help="Number of threads to use (default based on speed)")
parser.add_argument("-s", "--speed", choices=["slow", "medium", "fast"], default="medium",
                    help="Scan speed: slow, medium, fast (affects threads & timeout)")
args = parser.parse_args()

host = args.host


# Top 1000 TCP ports

top_ports = [
    1,3,7,9,13,17,19,20,21,22,23,25,26,37,53,79,80,81,82,83,84,85,88,89,90,99,100,106,
    109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,
    256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,
    464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,
    616,617,625,631,636,646,647,648,666,667,668,683,687,691,700,705,711,714,720,722,
    726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,
    981,987,990,992,993,995,999,1000,1001,1007,1009,1010,1021,1100,1102,1104,1105,
    1106,1107,1110,1111,1112,1113,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,
    1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,
    1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1233,1234,1236,1244,
    1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,
    1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1525,1529,1533,
    1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1723,
    1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,
    1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,
    2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,
    2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,
    2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,
    2366,2381,2382,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,
    2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,
    2920,2967,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3050,3052,
    3058,3060,3065,3066,3071,3077,3128,3168,3211,3221,3260,3268,3269,3283,3300,3306,
    3322,3323,3324,3389,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,
    3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,
    3905,3914,3918,3920,3945,3960,3961,3962,3971,3986,3995,3998,4000,4001,4002,4003,
    4004,4005,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,
    4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5009,5030,5033,5050,
    5051,5054,5060,5061,5080,5087,5100,5101,5120,5190,5200,5214,5221,5222,5225,5226,
    5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5501,5502,5544,5550,5555,5560,
    5566,5631,5633,5666,5678,5679,5718,5719,5722,5723,5800,5801,5802,5810,5811,5815,
    5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,
    5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,
    6002,6003,6004,6005,6006,6007,6009,6010,6025,6050,6055,6059,6100,6101,6106,6112,
    6123,6129,6156,6346,6389,6502,6510,6543,6565,6566,6567,6580,6646,6666,6667,6668,
    6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,
    7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,
    7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,
    8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,
    8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,
    8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8834,8880,
    8883,8888,8899,8994,9000,9001,9002,9003,9009,9010,9040,9050,9060,9080,9081,9090,
    9091,9099,9100,9101,9102,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,
    9503,9535,9575,9593,9594,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9968,
    9998,9999,10000
]


# Determine ports to scan

if args.ports:
    try:
        start_port, end_port = map(int, args.ports.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
        ports_to_scan = list(range(start_port, end_port+1))
    except:
        print("Invalid port range. Use format: start-end (1-65535)")
        exit()
else:
    ports_to_scan = top_ports  # default top 1000 ports


# Speed

speed_settings = {
    "slow": {"threads": 10, "timeout": 1.5},
    "medium": {"threads": 50, "timeout": 1.0},
    "fast": {"threads": 100, "timeout": 0.5}
}

speed = args.speed
timeout = speed_settings[speed]["timeout"]

# Override threads if user specified
threads_count = args.threads if args.threads else speed_settings[speed]["threads"]


# Resolve hostname
try:
    target_ip = socket.gethostbyname(host)
except socket.gaierror:
    print("Hostname could not be resolved!")
    exit()


# Scan Banner
print("-" * 50)
print(f"Target: {host} ({target_ip})")
print(f"Ports: {ports_to_scan[0]}-{ports_to_scan[-1]} (Total: {len(ports_to_scan)})")
print(f"Threads: {threads_count} | Speed: {speed}")
print("Scan started at: " + str(datetime.now()))
print("-" * 50)


# Store open ports
open_ports = []


# Port scanning function
def scan_port(port):
    """
    Tries to connect to the target IP at the given port.
    If connection succeeds, the port is open.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout based on speed
        if s.connect_ex((target_ip, port)) == 0:  # connect_ex returns 0 if port is open
            print(f"[OPEN] Port {port}")
            open_ports.append(port)
        s.close()
    except:
        pass  # Ignore closed/unreachable ports


# Thread worker
def thread_worker(port_list):
    for port in port_list:
        scan_port(port)


# Split ports for threads
def chunks(lst, n):
    """Split list into n-sized chunks for threads"""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

port_chunks = list(chunks(ports_to_scan, max(1, len(ports_to_scan)//threads_count)))
threads = []


# Launch threads
for chunk in port_chunks:
    t = threading.Thread(target=thread_worker, args=(chunk,))
    threads.append(t)
    t.start()

# Wait for all threads to finish
for t in threads:
    t.join()


# Scan completed
print("-" * 50)
print(f"Scan completed at: {datetime.now()}")
if open_ports:
    print(f"Open ports on {host}: {sorted(open_ports)}")
else:
    print(f"No open ports found on {host}")
print("-" * 50)
