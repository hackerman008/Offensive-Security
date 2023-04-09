''' 
	usage: <filename> <scan Type> <IP> <port:optional> <ICMP_use> <number_of_threads> 
	scan type: SYN, FIN, XMAS	
    IP: <192.168.xxx.xxx>
    port: <x, x-xxxx>
    ICMP_use: <ICMP_y,ICMP_n>
    num_of_threads: <1-100>

'''

from scapy.all import IP,ICMP,TCP,sr
import sys
import threading
from socket import getservbyname, getservbyport
import time

temp_array = [0] * 65537			#store status if open or close aka. 1 or 0
temp_array2 = [0] * 65537			#store port number
temp_array_flags = [0] * 65537		#store flag

def icmp_probe(ip):
	icmp_packet = IP(dst=ip)/ICMP()
	resp_packet = sr1(icmp_packet, timeout=10)
	return resp_packet != None
	
def syn_scan(ip, port, scan_type):
	if sys.argv[1] == 'SYN':
		scan_value = 'S'
	elif sys.argv[1] == 'FIN':
		scan_value = 'F'
	elif sys.argv[1] == 'XMAS':
		scan_value = 'FPU'

	packet = IP(dst=ip)/TCP(dport=int(port), flags=scan_value, options=[('Timestamp', (0,0))])
	ans,uns = sr(packet, timeout=1, verbose=0)

	if scan_type == 'SYN':
		if len(uns) > 0:
			return 0
		elif len(ans) > 0:
			return ans
	elif scan_type == 'XMAS' or scan_type == 'FIN':
		#do this
		if len(uns) > 0:		#if the packet is unanswered 
			return 0			
			
			
def threaded_syn_scan(ip, start_port, end_port, scan_type):
	for port in range(start_port, end_port+1):
		response_packet = syn_scan(ip, port, scan_type)
		if scan_type == 'SYN':
			if response_packet:
				temp_array2[port] = str(response_packet[0].answer[TCP].sport)
				temp_array_flags[port] = str(response_packet[0].answer[TCP].flags)
				if temp_array_flags[port] == 'SA':
					temp_array[port] = 1
			else:
				temp_array[port] = 2
		elif scan_type == 'XMAS' or scan_type == 'FIN':
			#do this
			if response_packet == 0:
				temp_array[port] = 2				#for XMAS andFIN scan no response indicated open|filtered port
			elif response_packet:
				temp_array_flags[port] = str(response_packet[0].answer[TCP].flags)
				if temp_array_flags[port] == 'RA':
					continue							#response does not matter if RA flags set
				

#multithreaded port scanner
def multithreaded_scanner_port_range(ip, start_port, end_port, num_threads, scan_type):				
	num_of_ports_to_scan = end_port - start_port
	temp_numerator = num_of_ports_to_scan//num_threads
	if num_of_ports_to_scan < 200:
		t1 = threading.Thread(target=threaded_syn_scan, args=(ip, start_port, end_port, scan_type))
		t1.start()
		t1.join()
	else:
		start_port_1 = start_port
		end_port_1 = start_port_1 + 1
		t = [0] * num_threads
		for i in range(0, num_threads):
			t[i] = threading.Thread(target=threaded_syn_scan, args=(ip, start_port_1, end_port_1, scan_type))
			t[i].start()
			start_port_1 = end_port_1 + 1
			end_port_1 = start_port_1 + temp_numerator
				
		for i in range(0, num_threads):
			t[i].join()		
	
def portScanSyn(ip, port, num_threads, scan_type):

	count_unanswd_port = 0
	if port == 'all':
		max_port = 65536
		
		start = time.time()
		multithreaded_scanner_port_range(ip, 1, max_port, num_threads, scan_type)			#scan
		end = time.time()
		
		print("Ports scanned: " + str(max_port) + "\n")
		print("IP\t\t" + "Return Flag\t"  + "Port\t" + "Status\t\t" + "Service\n" )
		for port in range(1, max_port):
			if scan_type == 'SYN':
				if temp_array[port] == 1:
					try:
						print(str(ip) + "\t" + temp_array_flags[port] + "\t\t" + str(port) + "\t" + "open" + "\t\t" + getservbyport(int(temp_array2[port])) + "\n")
					except:
						print(str(ip) + "\t" + temp_array_flags[port] + "\t\t" + str(port) + "\t" + "open" + "\t\t" + temp_array2[port] + "\n")
								
				elif temp_array[port] == 2:
					count_unanswd_port = count_unanswd_port + 1

			elif scan_type == 'XMAS' or scan_type == 'FIN':
				if temp_array[port] == 2:
					try:
						print(str(ip) + "\t" + "None" + "\t\t" + str(port) + "\t" + "open|filtered" + "\t" + getservbyport(int(port)) + "\n")
					except:
						print(str(ip) + "\t" + "None" + "\t\t" + str(port) + "\t" + "open|filtered" + "\t" + str(port) + "\n")
					count_unanswd_port = count_unanswd_port + 1
				continue
				 
		print("Total unanswered ports: " + str(count_unanswd_port))
		print("total time taken to scan: ", end-start)
			
	elif '-' in port:
		port_range = port.split('-')
		start_port = int(port_range[0])
		end_port = int(port_range[1])
		
		start = time.time()
		multithreaded_scanner_port_range(ip, start_port, end_port, num_threads, scan_type)
		end = time.time()
		total_ports_scanned = end_port - start_port
		print("Ports scanned: " + str(total_ports_scanned) + "\n")
		print("IP\t\t" + "Return Flag\t"  + "Port\t" + "Status\t\t" + "Service\n" )
		for port in range(start_port, end_port + 1):
			if scan_type == 'SYN':
				if temp_array[port] == 1:
					try:				
						print(str(ip) + "\t" + temp_array_flags[port] + "\t\t" + str(port) + "\t" + "open" + "\t\t" + getservbyport(int(temp_array2[port])) + "\n")
					except:
						print(str(ip) + "\t" + temp_array_flags[port] + "\t\t" + str(port) + "\t" + "open" + "\t\t" + temp_array2[port] + "\n")

				elif temp_array[port] == 2:
					count_unanswd_port = count_unanswd_port + 1
				
			elif scan_type == 'XMAS' or scan_type == 'FIN':
				if temp_array[port] == 2:
					try:
						print(str(ip) + "\t" + "None" + "\t\t" + str(port) + "\t" + "open|filtered" + "\t" + getservbyport(int(port)) + "\n")
					except:
						print(str(ip) + "\t" + "None" + "\t\t" + str(port) + "\t" + "open|filtered" + "\t" + str(port) + "\n")
					count_unanswd_port = count_unanswd_port + 1
				continue
							
		print("Total unanswered ports: " + str(count_unanswd_port))
		print("total time taken to scan: ", end-start)
			
	else:
		start = time.time()
		response_packet = syn_scan(ip, port, scan_type)
		end = time.time()
		port_to_scan = int(port)
		print("IP\t\t" + "Return Flag\t"  + "Port\t" + "Status\t\t" + "Service\n" )
		if scan_type == 'SYN':
			if response_packet:
				temp_array2[port_to_scan] = str(response_packet[0].answer[TCP].sport)					#basically port  number aka service will be extracted from this
				temp_array_flags[port_to_scan] = str(response_packet[0].answer[TCP].flags)				#flag 
				try:				
					print(str(ip) + "\t" + temp_array_flags[port] + "\t\t" + str(port) + "\t" + "open" + "\t\t" + getservbyport(int(temp_array2[port])) + "\n")
				except:
					print(str(ip) + "\t" + temp_array_flags[port] + "\t\t" + str(port) + "\t" + "open" + "\t\t" + temp_array2[port] + "\n")

			else:
				count_unanswd_port = count_unanswd_port + 1
				print("Total unanswered ports: " + str(count_unanswd_port))
				print("total time taken to scan: ", end-start)
		elif scan_type == 'XMAS' or scan_type == 'FIN':
			if response_packet == 0:
				try:
					print(str(ip) + "\t" + "None" + "\t\t" + str(port) + "\t" + "open|filtered" + "\t" + getservbyport(int(port)) + "\n")
				except:
					print(str(ip) + "\t" + "None" + "\t\t" + str(port) + "\t" + "open|filtered" + "\t" + str(port) + "\n")
				count_unanswd_port = count_unanswd_port + 1
				print("Total unanswered ports: " + str(count_unanswd_port))
				print("total time taken to scan: ", end-start)
			

		#normal_scan(ip, port)
	

if __name__ == "__main__":

	if len(sys.argv) != 6:
		print("usage: <filename> <scan Type> <IP> <port/port_range> <ICMP_use> <number_of_threads> ")
		exit(0)
	else:
		ip = sys.argv[2]
		port = sys.argv[3]
		ICMP_use = sys.argv[4]
		num_threads = sys.argv[5]
		scan_type = sys.argv[1]
		
	print("Scanning:\n")
	print("IP: " + ip + "\n")
	print("Port: " + port + "\n")
	print("Scan Type: " + scan_type + "\n")
	print("Threads: " + num_threads + "\n")
	
	
	if sys.argv[1] == "SYN":
		if ICMP_use == 'ICMP_y':
			if(icmp_probe(ip)):
				portScanSyn(ip, port, int(num_threads), scan_type)
			else:
				print("ICMP probe failed. Try scan without ICMP probe")
		elif ICMP_use == 'ICMP_n':
			portScanSyn(ip, port, int(num_threads), scan_type)
			
	if sys.argv[1] == "FIN":
		if ICMP_use == 'ICMP_y':
			if(icmp_probe(ip)):
				portScanSyn(ip, port, int(num_threads), scan_type)
			else:
				print("ICMP probe failed. Try scan without ICMP probe")
		elif ICMP_use == 'ICMP_n':
			portScanSyn(ip, port, int(num_threads), scan_type)

	if sys.argv[1] == "XMAS":
		if ICMP_use == 'ICMP_y':
			if(icmp_probe(ip)):
				portScanSyn(ip, port, int(num_threads), scan_type)
			else:
				print("ICMP probe failed. Try scan without ICMP probe")
		elif ICMP_use == 'ICMP_n':
			portScanSyn(ip, port, int(num_threads), scan_type)
			

			
			
			
	
	
	
	
		
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
