#!/usr/bin/env python3

#
# Copyright (c) 2024 Gaba <gabriel.correasb@protonmail.com>
#

import re
import datetime
from collections import defaultdict
from sqlalchemy.orm import Session
from models import SessionLocal, SuspiciousAttempt
import sys

# Configuration vars
LOG_FILE = "/var/log/auth.log"
FAILED_THRESHOLD = 5
TIME_WINDOW = 300 # secods (5 min)

# Using a regex pattern here to capture failed SSH attempts to machine:
# Typical auth log line example:
# "Jul 7 13:20:10 server sshd[12345]: Failed password for root from 200.2.293.1 port 8923 ssh2"

failed_pattern = re.compile(
	r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]: Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

# A helper to convert log timestamp (Mmm DD HH:MM:SS) to a datetime object
def parse_log_time(month, day, timestr):
	# We don't have year info in syslog, so assuming its the current year
	# This might cause issues at year boundaries but is acceptable for a POC
	current_year = datetime.datetime.now().year
	# Convert month abbreviation to number
	month_map = {
		'Jan':1, 'Feb':2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6,
		'Jul':7, 'Aug':8, 'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12
	}
	mon = month_map[month]
	day = int(day)
	h, m, s = (int(x) for x in timestr.split(':'))
	return datetime.datetime(current_year, mon, day, h, m, s)

def detect_brute_force():
	attempts_by_ip = defaultdict(list)

	try:
		with open(LOG_FILE, 'r') as file:
			for line in file:
				match = failed_pattern.search(line)
				if match:
					month = match.group('month')
					day = match.group('day')
					time_str = match.group('time')
					ip = match.group('time')
					attempt_time = parse_log_time(month, day, time_str)
					attempts_by_ip[ip].append(attempt_time)
	except FileNotFoundError:
		# Handle gracefully in production
		pass

	suspicious_entries = []
	for ip, times in attempts_by_ip.items():
		# Sorting times here
		times.sort()
		
		# Check sliding window
		for i in range(len(times)):
			# Look ahead to see how many attempts fall in the last TIME_WINDOW seconds
			c = 1
			j_end = i
			for j in range(i+1, len(times)):
				if (times[j] - times[i]).total_seconds() <= TIME_WINDOW:
					c += 1
					j_end = j
				else:
					break
			if c > FAILED_THRESHOLD:
				suspicious_entries.append((ip, c, times[i], times[j_end]))

	return suspicious_entries

def store_suspicious():
	"""
	Detect and store suspicious attempts in DB.
	"""
	suspicious = detect_brute_force()
	db: Session = SessionLocal()
	for ip, count, start_time, end_time in suspicious:
		# Check if entry already exists to avoid duplicates (simple approach)
		exists = db.query(SuspiciousAttempt).filter_by(ip=ip, start_time=start_time, end_time=end_time).first()
		if not exists:
			attempt = SuspiciousAttempt(ip=ip, count=count, start_time=start_time, end_time=end_time)
			db.add(attempt)
	db.commit()
	db.close()