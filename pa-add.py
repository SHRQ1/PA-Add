from panos.firewall import Firewall
from panos.objects import AddressObject
import re
from urllib.parse import urlparse
import argparse
import getpass




# Change it
server_ip='192.168.1.1'
username='admin'
Tag='Test'

ipAddr = []
FDQN= []


def classify(file_path):
    with open(file_path) as f:
        lines = f.readlines()
    f.close()




    Ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    FDQN_pattern = re.compile(r"^([a-zA-Z0-9._-]+$)")



    for y in lines:
        if y.isspace(): # skip empty line
            continue
        k = Ip_pattern.search(y)  # find Ip match the accepted pattern
        if not k == None:
                ipAddr.append(k.group())
        else:
            k = FDQN_pattern.search(y)  # find url match the accepted pattern
            if not k==None:
                FDQN.append(k.group())
            else: # url not matching
               y=parseFQDN(y)
               if not y=='None':
                 FDQN.append(y)

                ########################################33

def parseFQDN(url):
    if urlparse(url).scheme:
       return urlparse(url).hostname
    elif '://' not in url:
        url=url.replace('//','://')
    else:
        url = 'http://'+url

    url = re.sub(r"[^A-Za-z0-9.-_]","",str(urlparse(url).hostname))
    return url



def add(input_desc,pswd):
    try:
        fw = Firewall(server_ip, username, pswd)
        fw.show_system_info()
    except:
        print("Invalid credential")
        exit(1)

    print("\nThe script found the following FDQN ("+len(FDQN)+" ):\n")
    for x in FDQN:
        print(x)

    print("The script found the following Ip addresses ("+len(ipAddr)+"):\n ")
    for x in ipAddr:
        print(x)

    ################## Adding start here
    for x in FDQN:
        try:
            obj = AddressObject(x, x, 'fqdn', input_desc, Tag)
            fw.add(obj)
            obj.create()
        except:
            print("Something went wrong with "+x)

    for x in ipAddr:
        try:
            obj = AddressObject(x, x, 'ip-netmask', input_desc, Tag)
            fw.add(obj)
            obj.create()
        except:
            print("Something went wrong with "+x)

    fw.commit()


def main(file_path, input_desc,pswd):
    classify(file_path)
    add(input_desc,pswd)
    print("the script done successfully ")


if __name__ == '__main__':
    pswd =getpass.getpass('Password:')
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, help=" file path")
    parser.add_argument("Description", type=str, help="description ")

    args = parser.parse_args()
    file_path = args.file
    input_desc = args.Description

    main(file_path, input_desc,pswd)


