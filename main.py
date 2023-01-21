#pip libs
from tqdm import tqdm
import requests
#standar libs
import random
import socket
import time
import os
import re

def clear_screen():
    os.system(['clear','cls'][os.name == 'nt'])

def check_ip(ip):
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(pattern, ip):
        return True
    else:
        return False

def check_url(url):
    pattern = r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    if re.match(pattern, url):
        return True
    else:
        return False

print("###################")
print("Security Testing Script")
loopEnd = False
while(loopEnd == False):
  choice = input("#1 Test connection with known bad IPs.\n#2 Test connection with known bad URLs.\n#3 Test TOR Exits Nodes.\n#0 Exit.\nChoice:")
  if int(choice) == 1:#
    urls = [
        'http://opendbl.net/lists/etknown.list',
        'http://opendbl.net/lists/talos.list',
        'https://mirai.security.gives/data/ip_list.txt'
    ]
    saved_files = []
    for url in tqdm(urls, desc="Downloading Samples"):
        response = requests.get(url)
        if response.status_code == 200:
            file_name = url.split("/")[-1]
            with open(file_name, "w") as f:
                f.write(response.text)
                saved_files.append(file_name)
    sampleIP  = []
    for file in saved_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for i in range(5):
                randomIP  = random.choice(lines)
                if check_ip(randomIP):
                    sampleIP.append(randomIP)
    sampleIP = [x.strip() for x in sampleIP]
    ports = [80, 22, 443]
    myFile = open("IP_Results.txt", mode="a+")
    for ip in tqdm(sampleIP, desc="Testing 15 samples from Cisco Talos, EmergingThreats and Mirai, results saved to IP_Results.txt"):
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                current_time = time.strftime("%X")
                resultUP = "Timestamp:"+str(current_time)+" IP:"+str(ip)+ " : Port:"+ str(port)+ " test SUCCESSFUL\n"
                myFile.write(resultUP)
            else:
                current_time = time.strftime("%X")
                resultDOWN = "Timestamp:"+str(current_time)+" IP:"+str(ip)+ " : Port:"+ str(port)+ " test FAILED\n"
                myFile.write(resultDOWN)
            sock.close()
    for file_name in saved_files:
        os.remove(file_name)
    clear_screen()
  elif int(choice) == 2: #Bad URLs
    urls = 'https://openphish.com/feed.txt'
    saved_files = []
    print("Downloading Samples")
    response = requests.get(urls)
    if response.status_code == 200:
        file_name = urls.split("/")[-1]
        with open(file_name, "w") as f:
            f.write(response.text)
            saved_files.append(file_name)
    sampleURL  = []
    for file in saved_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for i in range(15):
                randomURL  = random.choice(lines)
                if check_url(randomURL):
                    sampleURL.append(randomURL)
    sampleURL = [x.strip() for x in sampleURL]
    myFile = open("URL_Results.txt", mode="a+")
    for url in tqdm(sampleURL, desc="Testing 15 samples from OpenPhish results saved to URL_Results.txt"):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                current_time = time.strftime("%X")
                resultUP = "Timestamp:" + str(current_time) + " URL:" + str(url) +" test SUCCESSFUL\n"
                myFile.write(resultUP)
            else:
                current_time = time.strftime("%X")
                resultDOWN = "Timestamp:" + str(current_time) + " URL:" + str(url) +" test FAILED\n"
                myFile.write(resultDOWN)
        except Exception as e:
            continue
    for file_name in saved_files:
        os.remove(file_name)
    clear_screen()
  elif int(choice) == 3:
    urls = 'https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst'
    saved_files = []
    print("Downloading Samples")
    response = requests.get(urls)
    if response.status_code == 200:
        file_name = urls.split("/")[-1]
        with open(file_name, "w") as f:
            f.write(response.text)
            saved_files.append(file_name)
    sampleTOR  = []
    for file in saved_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for i in range(15):
                randomIP  = random.choice(lines)
                if check_ip(randomIP):
                    sampleTOR.append(randomIP)
    sampleTOR = [x.strip() for x in sampleTOR]
    ports = [80, 443]
    myFile = open("TOR_Results.txt", mode="a+")
    for ip in tqdm(sampleTOR, desc="Testing 15 TOR Exits Nodes, results saved to TOR_Results.txt"):
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                current_time = time.strftime("%X")
                resultUP = "Timestamp:"+str(current_time)+" IP:"+str(ip)+ " : Port:"+ str(port)+ " test SUCCESSFUL\n"
                myFile.write(resultUP)
            else:
                current_time = time.strftime("%X")
                resultDOWN = "Timestamp:"+str(current_time)+" IP:"+str(ip)+ " : Port:"+ str(port)+ " test FAILED\n"
                myFile.write(resultDOWN)
            sock.close()
    for file_name in saved_files:
        os.remove(file_name)
    clear_screen()
  elif int(choice) == 0:
      print("bye :D")
      exit()
  else:
      print("-----")
      os.system('cls')


