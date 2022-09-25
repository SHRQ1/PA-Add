from panos.firewall import Firewall
from panos.objects import AddressObject
from panos.objects import AddressGroup
import re
from urllib.parse import urlparse
import argparse
import getpass
from xml.etree import ElementTree


# Change it
server_ip='192.168.1.1'
username='admin'
tag='Test'

ipAddr = []
FDQN= []
address_objects = []


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



def add(input_desc,fw):

    print("\n found the following FDQN ("+str(len(FDQN))+"):\n")
    for x in FDQN:
        print(x)

    print("\nfound the following Ip addresses ("+str(len(ipAddr))+"):\n ")
    for x in ipAddr:
        print(x)

    ################## Adding start here
    AddressObject.refreshall(fw,add=True)

    for x in FDQN:
        if not fw.find(x,AddressObject)== None:
            print(x+' Already has been added before')
            address_objects.append(fw.find(x,AddressObject))
            continue
        try:
            obj = AddressObject(x, x, 'fqdn', input_desc, tag)
            fw.add(obj)
            obj.create()
            address_objects.append(obj)
        except:
            print("Something went wrong with "+x)
    for x in ipAddr:

        if not fw.find(x, AddressObject)== None:
            print(x + ' Already has been added before')
            address_objects.append(fw.find(x,AddressObject))
            continue
        try:
           obj = AddressObject(x, x,'ip-netmask' ,input_desc, tag)
           fw.add(obj)
           obj.create()
           address_objects.append(obj)
        except:
            print("Something went wrong with " + x)



def addGroup(grp_name,fw):

    AddressGroup.refreshall(fw,add=True)
    grp=fw.find(grp_name)
    if grp==None:
         print("Create a group with name: "+grp_name)
         grp = AddressGroup(grp_name,address_objects)
         fw.add(grp)
         grp.create()
    else:
        print("Group already have been created")
        grp.extend(address_objects)

    print("\nAdded to "+grp_name)


def main(file_path, input_desc,grp_name):
    pswd =getpass.getpass('Password:')
    fw= Firewall(server_ip, username, pswd, is_virtual=True)
    try:
        fw.show_system_info()
    except:
        print("Invalid credential")
        exit(1)

    classify(file_path)
    add(input_desc,fw)
    if not grp_name == None:
         addGroup(grp_name,fw)




    print("Wait to commit")
    fw.commit()
    print("\nDone")

    quit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, help=" file path")
    parser.add_argument("Description", type=str, help="description ")
    parser.add_argument("-g","--group", required=False ,type=str, help="adding the list to a group ")

    args = parser.parse_args()
    file_path = args.file
    input_desc = args.Description
    grp_name=args.group

    main(file_path, input_desc,grp_name)



