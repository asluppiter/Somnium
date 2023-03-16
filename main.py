#pip libs
from tqdm import tqdm
import requests
from art import *
#standard libs
import string
import random
import socket
import time
import os
import re
import subprocess
import platform
#funcs
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

def known_IP():
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
            try:
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
            except Exception as e:
                current_time = time.strftime("%X")
                resultDOWN = "Timestamp:" + str(current_time) + " IP:" + str(ip) + " : Port:" + str(port) + " test FAILED\n"
                myFile.write(resultDOWN)
                continue
    for file_name in saved_files:
        os.remove(file_name)
    aprint("random")
    clear_screen()

def known_phish():
    urls = 'https://openphish.com/feed.txt'
    saved_files = []
    print("Downloading Samples")
    response = requests.get(urls)
    if response.status_code == 200:
        file_name = urls.split("/")[-1]
        with open(file_name, "w") as f:
            f.write(response.text)
            saved_files.append(file_name)
    sampleURL = []
    for file in saved_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for i in range(15):
                randomURL = random.choice(lines)
                if check_url(randomURL):
                    sampleURL.append(randomURL)
    sampleURL = [x.strip() for x in sampleURL]
    myFile = open("URL_Results.txt", mode="a+")
    for url in tqdm(sampleURL, desc="Testing 15 samples from OpenPhish results saved to URL_Results.txt"):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                current_time = time.strftime("%X")
                resultUP = "Timestamp:" + str(current_time) + " URL:" + str(url) + " test SUCCESSFUL\n"
                myFile.write(resultUP)
            else:
                current_time = time.strftime("%X")
                resultDOWN = "Timestamp:" + str(current_time) + " URL:" + str(url) + " test FAILED\n"
                myFile.write(resultDOWN)
        except Exception as e:
            continue
    for file_name in saved_files:
        os.remove(file_name)
    aprint("random")
    clear_screen()

def known_TOR():
    urls = 'https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst'
    saved_files = []
    print("Downloading Samples")
    response = requests.get(urls)
    if response.status_code == 200:
        file_name = urls.split("/")[-1]
        with open(file_name, "w") as f:
            f.write(response.text)
            saved_files.append(file_name)
    sampleTOR = []
    for file in saved_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for i in range(15):
                randomIP = random.choice(lines)
                if check_ip(randomIP):
                    sampleTOR.append(randomIP)
    sampleTOR = [x.strip() for x in sampleTOR]
    ports = [80, 443]
    myFile = open("TOR_Results.txt", mode="a+")
    for ip in tqdm(sampleTOR, desc="Testing 15 TOR Exits Nodes, results saved to TOR_Results.txt"):
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    current_time = time.strftime("%X")
                    resultUP = "Timestamp:" + str(current_time) + " IP:" + str(ip) + " : Port:" + str(
                        port) + " test SUCCESSFUL\n"
                    myFile.write(resultUP)
                else:
                    current_time = time.strftime("%X")
                    resultDOWN = "Timestamp:" + str(current_time) + " IP:" + str(ip) + " : Port:" + str(
                        port) + " test FAILED\n"
                    myFile.write(resultDOWN)
                sock.close()
            except Exception as e:
                current_time = time.strftime("%X")
                resultDOWN = "Timestamp:" + str(current_time) + " IP:" + str(ip) + " : Port:" + str(
                    port) + " test FAILED\n"
                myFile.write(resultDOWN)
                continue
    for file_name in saved_files:
        os.remove(file_name)
    aprint("random")
    clear_screen()

def known_dist():
    print('Testing LIVE malware distribution URL, THANKS TO ABUSE.CH!!!')
    urlsIndex = []
    randomUrlsIndex = []
    baseURL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/"
    response = requests.get(baseURL)
    json_response = response.json()
    counter = 0
    for x in tqdm(json_response["urls"], desc="Getting samples list"):
        status = json_response["urls"][counter]["url_status"]
        if status == "online":
            liveURL = json_response["urls"][counter]["url"]
            urlsIndex.append(liveURL)
        counter = counter + 1
    for i in range(20):
        randomSample = random.choice(urlsIndex)
        randomUrlsIndex.append(randomSample)
    myFile = open("Malware_Results.txt", mode="a+")
    for x in tqdm(randomUrlsIndex, desc="Testing samples, Results saved at Malware_Results.txt"):
        try:
            downloader = requests.get(x, timeout=5)
            if downloader.status_code == 200:
                current_time = time.strftime("%X")
                result = "Timestamp:" + str(current_time) + " URL:" + str(x) + " test SUCCESFULL\n"
                myFile.write(result)
            else:
                current_time = time.strftime("%X")
                result = "Timestamp:" + str(current_time) + " URL:" + str(x) + " test FAILED\n"
                myFile.write(result)
        except Exception as e:
            current_time = time.strftime("%X")
            result = "Timestamp:" + str(current_time) + " URL:" + str(x) + " test FAILED\n"
            myFile.write(result)
            continue
    aprint("random")
    clear_screen()

def known_crypto():
    urls = 'https://gist.githubusercontent.com/asluppiter/88aa3cb285948e4f982dd94218e5baf3/raw/bffe8bb462eb8b3fb6cd647be65d67de059cb789/mining'
    saved_files = []
    print("Downloading Samples")
    response = requests.get(urls)
    if response.status_code == 200:
        file_name = urls.split("/")[-1]
        with open(file_name, "w") as f:
            f.write(response.text)
            saved_files.append(file_name)
    sampleMining = []
    for file in saved_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for i in range(15):
                randomIP = random.choice(lines)
                sampleMining.append(randomIP)
    sampleMining = [x.strip() for x in sampleMining]
    myFile = open("Mining_Results.txt", mode="a+")
    for x in tqdm(sampleMining, desc="Testing samples, Results saved at Mining_Results.txt"):
        try:
            downloader = requests.get(x, timeout=5)
            if downloader.status_code == 200:
                current_time = time.strftime("%X")
                result = "Timestamp:" + str(current_time) + " URL:" + str(x) + " test SUCCESFULL\n"
                myFile.write(result)
            else:
                current_time = time.strftime("%X")
                result = "Timestamp:" + str(current_time) + " URL:" + str(x) + " test FAILED\n"
                myFile.write(result)
        except Exception as e:
            current_time = time.strftime("%X")
            result = "Timestamp:" + str(current_time) + " URL:" + str(x) + " test FAILED\n"
            myFile.write(result)
            continue
    for file_name in saved_files:
        os.remove(file_name)
    aprint("random")
    clear_screen()

def generate_DGA():
    tld_list = ['xyz', 'top', 'zone', 'info', 'biz', 'gq', 'tk', 'club'] #https://trends.netcraft.com/cybercrime/tlds
    sampleDGA = []
    for i in range(1, 15):
        tld = random.choice(tld_list)
        domain_length = random.randint(5, 15)
        domain_name = ''.join(random.choices(string.ascii_lowercase, k=domain_length))
        dga = domain_name + '.' + tld
        sampleDGA.append(dga)
    myFile = open("DGA_Results.txt", mode="a+")
    ports = [80, 443]
    for ip in tqdm(sampleDGA, desc="Testing samples, Results saved at DGA_Results.txt"):
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    current_time = time.strftime("%X")
                    resultUP = "Timestamp:" + str(current_time) + " IP:" + str(ip) + " : Port:" + str(
                        port) + " tested (Actual DGA generated by script, so the domain even may not exist BUT look if your FW or IPS detected the request and tagged it)\n"
                    myFile.write(resultUP)
                else:
                    current_time = time.strftime("%X")
                    resultDOWN = "Timestamp:" + str(current_time) + " IP:" + str(ip) + " : Port:" + str(
                        port) + " tested (Actual DGA generated by script, so the domain even may not exist BUT look if your FW or IPS detected the request and tagged it)\n"
                    myFile.write(resultDOWN)
                sock.close()
            except Exception as e:
                current_time = time.strftime("%X")
                resultDOWN = "Timestamp:" + str(current_time) + " IP:" + str(ip) + " : Port:" + str(
                    port) + " tested (Actual DGA generated by script, so the domain even may not exist BUT look if your FW or IPS detected the request and tagged it)\n"
                myFile.write(resultDOWN)
                continue
    aprint("random")
    clear_screen()

def test_RAT():
    print('\nUnsanctioned Remote Desktop management tools are used by threat actors for persistance and exfil read more at: https://redcanary.com/blog/misbehaving-rats/')
    urls = [
        'teamviewer.com', #Functional URLs thanks to https://www.netify.ai/resources/applications
        'router1.teamviewer.com',
        'udp.ping.teamviewer.com'
        'boot.net.anydesk.com',
        'rpm.anydesk.com',
        'relay-a7a47b7c.net.anydesk.com',
        'splashtop.com',
        'sdrs.splashtop.com'
        'st2-v3-dc.splashtop.com',
        'update.logmein.com',
        'lmi-app22-01.logmein.com',
        'secure.logmeinrescue.com',
        'screenconnect.com',
        'server-nix4beff1f3-web.screenconnect.com',
        'instance-ra153n-relay.screenconnect.com',
        'gotoassist.com'
    ]
    if platform.system() == 'Windows':
        ping_args = '-n'
    else:
        ping_args = '-c'
    myFile = open("RAT_Results.txt", mode="a+")
    for url in tqdm(urls,desc="Testing URLs from known Remote Desktop tools, results saved to RAT_Results.txt"):
        try:
            subprocess.check_output(['ping', ping_args, '1', url])
            current_time = time.strftime("%X")
            result = "Timestamp:" + str(current_time) + " URL:" + str(url) + " test DONE\n"
            myFile.write(result)
        except subprocess.CalledProcessError:
            current_time = time.strftime("%X")
            result = "Timestamp:" + str(current_time) + " URL:" + str(url) + " test DONE\n"
            myFile.write(result)
    aprint("random")
    clear_screen()

def known_badAgents():
    print("Simulating traffic using known bad User-Agent(SPAM,botnet,etc)")
    urls = 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list'
    saved_files = []
    response = requests.get(urls)
    if response.status_code == 200:
        file_name = urls.split("/")[-1]
        with open(file_name, "w") as f:
            f.write(response.text)
            saved_files.append(file_name)
    sampleAgent = []
    for file in saved_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for i in tqdm(range(15),desc='Downloading Samples'):
                randomAgent = random.choice(lines)
                sampleAgent.append(randomAgent)
    sampleAgent = [x.strip() for x in sampleAgent]
    myFile = open("Agent_Results.txt", mode="a+")
    for agent in tqdm(sampleAgent,desc='Sending HTTPS request to Google with known bad User-Agent'):
        url = 'https://google.com'
        headers = {'User-Agent': agent}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            current_time = time.strftime("%X")
            result = "Timestamp:" + str(current_time) + " URL:" + str(agent) + " test DONE\n"
            myFile.write(result)
        else:
            current_time = time.strftime("%X")
            result = "Timestamp:" + str(current_time) + " URL:" + str(agent) + " test DONE\n"
            myFile.write(result)
    for file_name in saved_files:
        os.remove(file_name)
    aprint("random")
    clear_screen()
#Main
Art=text2art("Somnium: NetSec testing script","rand")
print(Art)
loopEnd = False
while(loopEnd == False):
  choice = input("#1 Test connection with known bad IPs.\n#2 Test connection with known Phishing URLs.\n#3 Test connection to TOR Exits Nodes.\n#4 Test connection to live Malware distribution Urls\n#5 Test connection to known Cryptomining domains.\n#6 Test connection to Domain-Generated-Algorithm Domains.\n#7 Test connection to Remote Desktop Management.(Anydesk,etc.)\n#8 Test connection using known bad user agents.\n#0 Exit.\nChoice:")
  if int(choice) == 1:
      known_IP()
  elif int(choice) == 2:
      known_phish()
  elif int(choice) == 3:
      known_TOR()
  elif int(choice) == 4:
      known_dist()
  elif int(choice) == 5:
      known_crypto()
  elif int(choice) == 6:
      generate_DGA()
  elif int(choice) == 7:
      test_RAT()
  elif int(choice) == 8:
      known_badAgents()
  else:
      print("-----")
      clear_screen()
      exit()


