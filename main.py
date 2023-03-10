#pip libs
from tqdm import tqdm
import requests
#standar libs
import random
import json
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
  choice = input("#1 Test connection with known bad IPs.\n#2 Test connection with known Phishing URLs.\n#3 Test connection to TOR Exits Nodes.\n#4 Test connection to live Malware distribution Urls\n#5 Test connection to known Cryptomining domains\n#0 Exit.\nChoice:")
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
            response = requests.get(url,timeout=5)
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
    clear_screen()
  elif int(choice) == 4:
      urlsIndex= []
      randomUrlsIndex = []
      baseURL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/"
      response = requests.get(baseURL)
      json_response = response.json()
      counter = 0
      for x in tqdm(json_response["urls"],desc="Getting samples list"):
          status = json_response["urls"][counter]["url_status"]
          if status == "online":
              liveURL = json_response["urls"][counter]["url"]
              urlsIndex.append(liveURL)
          counter=counter+1
      for i in range(20):
          randomSample = random.choice(urlsIndex)
          randomUrlsIndex.append(randomSample)
      myFile = open("Malware_Results.txt", mode="a+")
      for x in tqdm(randomUrlsIndex,desc="Testing samples, Results saved at Malware_Results.txt"):
          try:
              downloader = requests.get(x,timeout=5)
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
      clear_screen()
  elif int(choice) == 5:
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
              downloader = requests.get(x,timeout=5)
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
      clear_screen()
      for file_name in saved_files:
          os.remove(file_name)
      clear_screen()
  else:
      print("-----")
      clear_screen()
      exit()


