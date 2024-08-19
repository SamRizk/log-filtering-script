# MIT License
#
# Copyright (c) 2024 Samir Rizk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Author: Samir Rizk
# Date: 14/8/2024
# Copyright: 2024 Samir Rizk. All rights reserved.

import re
import sys

# Define the system calls we want to analyze
syscalls_to_analyze = [
    'open', 'openat', 'read', 'write', 'execve', 'SystemCall', 'close', 'mmap', 
    'munmap', 'fstat', 'lseek', 'ioctl', 'socket', 'connect', 'bind', 'send', 
    'recv', 'sendto', 'recvfrom', 'fork', 'vfork', 'clone', 'wait4', 'exit', 
    'kill', 'getpid', 'getppid', 'stat', 'lstat', 'access', 'unlink', 'chmod', 
    'chown', 'rename', 'dup', 'dup2', 'pipe', 'poll', 'select', 'gettimeofday', 
    'settimeofday', 'clock_gettime', 'clock_settime', 'brk', 'sbrk', 'mprotect', 
    'sched_yield', 'nanosleep', 'sysinfo', 'times'
]

# Check if the user provided the log file path
if len(sys.argv) < 2:
    print("Usage: python script_name.py <log_file_path>")
    sys.exit(1)

# Get the log file path from the command-line argument
log_file_path = sys.argv[1]

# Dictionary to store syscall data using sets for unique entries
syscall_data = {syscall: set() for syscall in syscalls_to_analyze}

# Regex patterns to match each syscall
patterns = {
    'open': re.compile(r'open\("([^"]+)", ([^)]+)\) = (.+)'),
    'openat': re.compile(r'openat\(([^)]+)\) = (.+)'),
    'read': re.compile(r'read\(([^)]+)\) = (.+)'),
    'write': re.compile(r'write\(([^)]+)\) = (.+)'),
    'execve': re.compile(r'execve\("([^"]+)", ([^)]+)\) = (.+)'),
    'SystemCall': re.compile(r'\[SystemCall\]\s+Running:\s+([^ ]+)'),
    'close': re.compile(r'close\(([^)]+)\) = (.+)'),
    'mmap': re.compile(r'mmap\(([^)]+)\) = (.+)'),
    'munmap': re.compile(r'munmap\(([^)]+)\) = (.+)'),
    'fstat': re.compile(r'fstat\(([^)]+)\) = (.+)'),
    'lseek': re.compile(r'lseek\(([^)]+)\) = (.+)'),
    'ioctl': re.compile(r'ioctl\(([^)]+)\) = (.+)'),
    'socket': re.compile(r'socket\(([^)]+)\) = (.+)'),
    'connect': re.compile(r'connect\(([^)]+)\) = (.+)'),
    'bind': re.compile(r'bind\(([^)]+)\) = (.+)'),
    'send': re.compile(r'send\(([^)]+)\) = (.+)'),
    'recv': re.compile(r'recv\(([^)]+)\) = (.+)'),
    'sendto': re.compile(r'sendto\(([^)]+)\) = (.+)'),
    'recvfrom': re.compile(r'recvfrom\(([^)]+)\) = (.+)'),
    'fork': re.compile(r'fork\(\) = (.+)'),
    'vfork': re.compile(r'vfork\(\) = (.+)'),
    'clone': re.compile(r'clone\(([^)]+)\) = (.+)'),
    'wait4': re.compile(r'wait4\(([^)]+)\) = (.+)'),
    'exit': re.compile(r'exit\(([^)]+)\) = (.+)'),
    'kill': re.compile(r'kill\(([^)]+)\) = (.+)'),
    'getpid': re.compile(r'getpid\(\) = (.+)'),
    'getppid': re.compile(r'getppid\(\) = (.+)'),
    'stat': re.compile(r'stat\("([^"]+)"\) = (.+)'),
    'lstat': re.compile(r'lstat\("([^"]+)"\) = (.+)'),
    'access': re.compile(r'access\("([^"]+)", ([^)]+)\) = (.+)'),
    'unlink': re.compile(r'unlink\("([^"]+)"\) = (.+)'),
    'chmod': re.compile(r'chmod\("([^"]+)", ([^)]+)\) = (.+)'),
    'chown': re.compile(r'chown\("([^"]+)", ([^)]+)\) = (.+)'),
    'rename': re.compile(r'rename\("([^"]+)", "([^"]+)"\) = (.+)'),
    'dup': re.compile(r'dup\(([^)]+)\) = (.+)'),
    'dup2': re.compile(r'dup2\(([^)]+), ([^)]+)\) = (.+)'),
    'pipe': re.compile(r'pipe\(([^)]+)\) = (.+)'),
    'poll': re.compile(r'poll\(([^)]+)\) = (.+)'),
    'select': re.compile(r'select\(([^)]+)\) = (.+)'),
    'gettimeofday': re.compile(r'gettimeofday\(([^)]+)\) = (.+)'),
    'settimeofday': re.compile(r'settimeofday\(([^)]+)\) = (.+)'),
    'clock_gettime': re.compile(r'clock_gettime\(([^)]+)\) = (.+)'),
    'clock_settime': re.compile(r'clock_settime\(([^)]+)\) = (.+)'),
    'brk': re.compile(r'brk\(([^)]+)\) = (.+)'),
    'sbrk': re.compile(r'sbrk\(([^)]+)\) = (.+)'),
    'mprotect': re.compile(r'mprotect\(([^)]+)\) = (.+)'),
    'sched_yield': re.compile(r'sched_yield\(\) = (.+)'),
    'nanosleep': re.compile(r'nanosleep\(([^)]+)\) = (.+)'),
    'sysinfo': re.compile(r'sysinfo\(([^)]+)\) = (.+)'),
    'times': re.compile(r'times\(([^)]+)\) = (.+)')
}

# Process the log file
with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as log_file:
    for line in log_file:
        for syscall, pattern in patterns.items():
            match = pattern.search(line)
            if match:
                syscall_data[syscall].add(match.group(1))  # Capture the relevant data

# Output the results
for syscall, calls in syscall_data.items():
    print(f"\nSyscall: {syscall}\n{'-'*40}")
    for call in sorted(calls):
        print(call)
