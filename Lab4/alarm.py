#!/usr/bin/python3

from scapy.all import *
import argparse
import base64


incident_number =0
ftp_credentials = {}

def packetcallback(packet):
  try:
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts
    # if packet[TCP].dport == 21:
    #   print("HTTP (web) traffic detected!")
    #   print(packet[IP].src)
    #   print(packet[IP].dst)
      
    global incident_number
    
    
    if packet.haslayer(TCP): 
      
      
      
      #Packet Scan
      
      # NULL SCAN
      if packet[TCP].flags == 0:
        incident_number += 1
        print(f'ALERT #{incident_number}: NULL scan is detected from {packet[IP].src} (TCP)!')
 
       # FIN SCAN       
      elif packet[TCP].flags == 'F':
        incident_number += 1
        print(f'ALERT #{incident_number}: FIN scan is detected from {packet[IP].src} (TCP)!')

      # Xmas SCAN        
      elif packet[TCP].flags == 'FPU':
        incident_number += 1
        print(f'ALERT #{incident_number}: Xmas scan is detected from {packet[IP].src} (TCP)!')
        
              
      if packet[TCP].dport == 445:
        incident_number += 1
        print(f'ALERT #{incident_number}: Someone scanning for Server Message Block (SMB) protocol from {packet[IP].src} (TCP)!')  
          
      elif packet[TCP].dport == 3389:
        incident_number += 1
        print(f'ALERT #{incident_number}: Someone scanning for Remote Desktop Protocol (RDP) protocol from {packet[IP].src} (TCP)!')
    
      elif packet[TCP].dport == 5900:
        incident_number += 1
        print(f'ALERT #{incident_number}: Someone scanning for Virtual Network Computing (VNC) protocol from {packet[IP].src} (TCP)!')
      
      
      
      
        
    if TCP in packet and packet[TCP].payload:
        # Decode the payload directly from the TCP layer

        payload = packet[TCP].load.decode("ascii").strip()

        # Username and Password Detection
        
        # HTTP Basic Authentication Detection
        if "Authorization: Basic" in payload:
          basic_auth_prefix = "Authorization: Basic "
          start = payload.find(basic_auth_prefix) + len(basic_auth_prefix)
          end = payload.find('\r\n', start)
          encoded_credentials = payload[start:end]
          decoded_credentials = base64.b64decode(encoded_credentials).decode('ascii')
          username, password = decoded_credentials.split(':', 1)
          incident_number += 1
          print(f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (HTTP) from {packet[IP].src} (username:{username}, password:{password})")

        # FTP Credentials Detection

        global ftp_credentials
        source_ip = packet[IP].src
        source_port = packet[TCP].sport
               
        
        if "USER" in payload:
          username = payload.split('USER ')[1].split('\r\n')[0]
          ftp_credentials[(source_ip, source_port)] = username
        if "PASS" in payload:
          password = payload.split('PASS ')[1].split('\r\n')[0]
          username = ftp_credentials.get((source_ip, source_port), None)
          if username:
            incident_number += 1
            print(f"ALERT #{incident_number}: FTP Usernames and Passwords detected from {packet[IP].src} (username:{username}, password:{password})")
            del ftp_credentials[(source_ip, source_port)]
              
        # IMAP Credentials Detection
        if "LOGIN" in payload:
          parts = payload.split('LOGIN ')[1].split(' ')
          if len(parts) >= 2:
            username = parts[0].strip('"')
            password = parts[1].strip('"').split('\r\n')[0]
            incident_number += 1
            print(f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (IMAP) from {packet[IP].src} (username:{username}, password:{password})")

      
        # Nikto Scan
        if "Nikto" in payload:
          incident_number += 1
          print(f'ALERT #{incident_number}: Nikto scan is detected from {packet[IP].src} (TCP)!')            
    
      

      
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    #print(e)
    pass

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")