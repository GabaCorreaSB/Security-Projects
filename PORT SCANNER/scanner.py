#!/usr/bin/env python3

#
# Copyright (c) 2024 Gaba <gabriel.correasb@protonmail.com>
#

import asyncio
import socket
import argparse
import re

# A small known service signature map for demonstration purposes:
# This could be expanded or replaced with a more robust fingerprinting system.
SERVICE_SIGNATURES = [
	(re.compile(rb"(OpenSSH[_ ]([\d\.]+))", re.I), "OpenSSH"),
	(re.compile(rb"(Apache\/([\d\.]+))", re.I), "Apache HTTPD"),
	(re.compile(rb"(nginx\/([\d\.]+))", re.I), "nginx"),
	(re.compile(rb"^220.*?FTP", re.I), "FTP Server"),
	(re.compile(rb"^SSH-([\d\.]+)", re.I), "SSH Server")
]


async def scan_port(host: str, port: int, timeout: float = 2.0):
	"""
	Attempt to connect to a given port. If open, try banner grabbing.
	Returns a tuple: (port, is_open, service_info, vulns)
	"""
	try:
		reader, writer = await asyncio.wait_for(
			asyncio.open_connection(host, port)
			timeout=timeout
		)
		# Try banner grabbing:
		# Many services send a banner upon connection. If not, we can attempt a small probe.
		# Going just try to read a small amount of data
		writer.write(b"\r\n\r\n")
		await writer.drain()
		await asyncio.sleep(0.5)
		banner = await reader.read(1024)
		writer.close()
		await writer.wait_closed()

		## TODO
		#service_name, version, vulns = identify_service_vulns(banner)
		return port, True, #(service_name, version), vulns TODO
	except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
		return port, False, (None, None), []

def identify_service_vulns(banner: bytes):
	"""
	Try to identify the service and its version from the banner using regex
	Return (service_name, version, vulns)
	"""
	service_name = "Unknown"
	version = None
	
	for pattern, svc_name in SERVICE_SIGNATURES:
		match = pattern.search(banner)
		if match:
			service_name = svc_name
			# Attempt to extract a version from the pattern groups if present
			if match.groups():
				# Look for a version-like group
				for group in match.groups():
					if group and re.match(rb"[\d\.]+", group):
						version = group.decode("utf-8")
						break
			break

	# vulns = find_vulns(service_name, version) TODO
	return service_name, version #, vulns

def find_vulns(service_name, version):
	"""
	Check known vulnerabilites for the identified service and version
	"""
	pass

async def scan_host(host: str, ports: list):
	"""
	Scan multiple ports on a single host concurrently
	"""
	tasks = [asyncio.create_task(scan_port(host, port)) for port in ports]
	results = await asyncio.gather(*tasks)
	return results

def main():
	pass

if __name__ == "__main__":
	main()