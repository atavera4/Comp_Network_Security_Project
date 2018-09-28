import os
import sys
from os import path



def main(argv):

    # BONUS #1 PIPE in stdin if --online option is given
    if(argv == "--online"):
        file = sys.stdin
        AnalyzeFile(file)
    else:
        #AnalyzeFile(file)
        GetFilesList()


    return;

# Start the program.
def GetFilesList():
    # Create a list of all the files in the current directory.
    #print(all_files)

    for file in os.listdir(os.getcwd()):
        if file.endswith(".log"):
            f = OpenFile(file)
            print("\n\n" +file + "--> \n")
            AnalyzeFile(f)

    return;


def OpenFile(filename):
    file = open(filename, 'r')
    return file;


def AnalyzeFile(file):

    n = 10000
    ip_address_list = [""]
    ip_address_list_counters = [0] * n

    # make a list that adds the scanners victim ip only if a target port is detectd.
    # then use this list and the ip from the victim info to search if that ip appears 8 times in
    # this list. That would indicate the 1- the victim has had all target ports probed.
    # and 2- all of those probes came from the same ip address.

    ip_address_scanner_list = [""]
    ip_address_scanner_list_counters = [""]
    ip_list_location = 0
    ip_scanner_list_location = 0

    total_ports = 0
    victim_scanner_ip_list = ['']
    scanner_victim_ip_list = ['']


    ip_address_scanner_list_time = [""]
    ip_address_list_time = [""]

    Nmap_F_portList = ["smux","pop3","mysql","smtp", "ssh", "netbios-ssn", "domain", "loc-srv", "rmtcfg", "submission", "telnet", "auth"]
    Nmap_F_portList_size = 7;
    Nmap_F_portCounters = [0] * n
    Nmap_F_portList_scanner = ["smux","pop3","mysql","smtp", "ssh", "netbios-ssn", "domain", "loc-srv"]
    Nmap_F_portCounters_scanner = [0] * n

    Nmap_sS_portList = ["smux","pop3","mysql","smtp", "ssh", "netbios-ssn", "domain", "loc-srv", "rmtcfg", "submission", "telnet", "auth"]
    Nmap_sS_portCounters = [0] * n
    Nmap_sS_portList_size = 11
    Nmap_sS_portList_scanner = ["smux","pop3","mysql","smtp", "ssh", "netbios-ssn", "domain", "loc-srv", "rmtcfg", "submission", "telnet", "auth"]
    Nmap_sS_portCounters_scanner = [0] * n

    Nmap_v_portList = ["","","",""]
    Nmap_v_portCounters = [0] * n
    Nmap_v_portList_size = 7
    Nmap_v_portList_scanner = ["smtp","domain","rmtcfg", "submission", "telnet", "auth", "microsoft-ds", "smux"]
    Nmap_v_portCounters_scanner = [0] * n

    n_scan_victims = ['']
    n_scan_attackers = ['']

 # Ports attributed to any scan must occure within a specified amount of time to be valid.
    TimeThreshold_F = 0
    TimeThreshold_sS = 0
    TimeThreshold_v = 0

    for line in file:  # to pipe it in just set line = sys.read() cmd line for each line instead of for loop file......................
#########  Potential Scanner/ INTRUDER INFORMATION COLLECTION
        scanner_ip = GetScannerIPAddress(line)
        if("who-has" in line):
            n_scan_attackers.append(DetectFnScan(line))

        if( (scanner_ip not in ip_address_scanner_list) and (LineIsNotWebRequest(line)) ):
            ip_address_scanner_list.append(GetScannerIPAddress(line))
            #ip_address_list_time.append(GetTime());
        elif (LineIsNotWebRequest(line)): # the ip has been seen before!!!! make
                                            #sure that it is not a web request from that ip too.


            ip_scanner_list_location = FindScannerIpInList(scanner_ip, ip_address_scanner_list)
            ip_address_list_counters[ip_scanner_list_location] += 1
            # Collect information on a potential scanner/ intruder on network.
            for scanner_port in Nmap_F_portList_scanner:

                if GetLineScannerPort(line) == scanner_port:
                    # remove from port from list b/c we have already found it and no longer need to compare it.
                    # We want different ones now.
                    Nmap_F_portList_scanner.remove(scanner_port)
                    Nmap_F_portCounters_scanner[ip_scanner_list_location] += 1

                    scanner_victim_ip_list.append(scanner_ip);
                    #print(Nmap_F_portCounters_scanner[ip_scanner_list_location])
                    #print ("GOT HERE !!!!!!!!!!!!!!!!!!!????????????????")
                    break;
            for scanner_port in Nmap_sS_portList_scanner:
                if GetLineScannerPort(line) == scanner_port:
                    # remove from port from list b/c we have already found it and no longer need to compare it.
                    # We want different ones now.
                    Nmap_sS_portList_scanner.remove(scanner_port)
                    Nmap_sS_portCounters_scanner[ip_scanner_list_location] += 1
                    scanner_victim_ip_list.append(GetIPAddress(line))
                    break;
            for scanner_port in Nmap_v_portList_scanner:
                if GetLineScannerPort(line) == scanner_port:
                    # remove from port from list in this iteration of for loop only
                    #   b/c we have already found it and no longer need to compare it.
                    # We want to search for different ports now that have not been seen yet.
                    Nmap_v_portList_scanner.remove(scanner_port)
                    Nmap_v_portCounters_scanner[ip_scanner_list_location] += 1
                    scanner_victim_ip_list.append(GetIPAddress(line))
                    break;


# Checks to see if all of the ports for a certain scan type were seen from a single ip address.
        current_ip = str(GetIPAddress(line))
        time = GetTime(line)
        if( DetectNmapF( Nmap_F_portCounters, Nmap_F_portCounters_scanner, Nmap_F_portList_size)):
            Nmap_F_portList_scanner = ["smux","pop3","mysql","smtp", "ssh", "netbios-ssn", "domain", "loc-srv", "telnet", "auth"]
            Nmap_F_portCounters_scanner[ip_scanner_list_location] = 0 # reset this for both ip scanner and ip victim.
            Nmap_v_portCounters_scanner[ip_scanner_list_location] = 0
            Nmap_sS_portCounters_scanner[ip_scanner_list_location] = 0
            #time = GetTime()
            #if((time - ip_address_list_time(ip_list_location) < TimeThreshold):

            if(current_ip in n_scan_attackers):
                print("Potential F -n scan DETECTED \nfrom: " + current_ip + " to: " + ip_address_scanner_list[ip_scanner_list_location] + " at " + time)
            else:
                type_f_scan = 1
                print("Potential -F or -sS Scan DETECTED\n from: " + current_ip  + " to: " + ip_address_scanner_list[ip_scanner_list_location] + " at " + time)

        # elif(current_ip in n_scan_attackers):
        #     print("Potential -n type scan DETECTED\nfrom ip address: " + current_ip + "to ip address: " + str(ip_address_scanner_list[ip_scanner_list_location]) + " at " + time)
        #     type_n_scan = 1
        #     n_scan_attackers = ['']

        elif( DetectNmapV(Nmap_v_portCounters_scanner, Nmap_v_portList_size) ):
            #time = GetTime()
            #if((time - ip_address_list_time(ip_list_location) < TimeThreshold):
            Nmap_v_portList_scanner = ["smtp","domain","rmtcfg", "submission", "telnet", "auth", "microsoft-ds", "smux"]
            Nmap_v_portCounters_scanner[ip_scanner_list_location] = 0
            Nmap_sS_portCounters_scanner[ip_scanner_list_location] = 0
            Nmap_F_portCounters_scanner[ip_scanner_list_location] = 0

            print("Potential -v Scan DETECTED\nfrom: " + current_ip + "to: " + ip_address_scanner_list[ip_scanner_list_location] + " at " + time)
            type_v_scan = 1

        elif( DetectNmapsS(Nmap_sS_portCounters, Nmap_sS_portCounters_scanner, Nmap_sS_portList_size) ):
            #time = GetTime()
            #if((time - ip_address_list_time(ip_list_location) < TimeThreshold):
            Nmap_sS_portList_scanner = ["smux","pop3","mysql","smtp", "ssh", "netbios-ssn", "domain", "loc-srv", "rmtcfg", "submission", "telnet", "auth"]
            Nmap_sS_portCounters_scanner[ip_scanner_list_location] = 0
            Nmap_F_portCounters_scanner[ip_scanner_list_location] = 0
            Nmap_v_portCounters_scanner[ip_scanner_list_location] = 0

            print("Potential -sS scan Scan DETECTED\nfrom: " + current_ip + "to: " + ip_address_scanner_list[ip_scanner_list_location] + " at " + time)
            type_sS_scan = 1


    return;

def GetTime(line):
    position = 0
    time = ''
    for character in line:
        if(position >= 12):
            return time;
        else:
            position += 1
            time = time + character

    return ".";

def GetIPAddress(line):
    ip_start = 19
    ip_end = 33
    position = 0
    address = ""
    for character in line:
        if(position >= ip_end):
            break
        elif(position >= ip_start):
            address = address + character
        position += 1

    return address;

# This is the ip of the computer that is probing the network.
def GetScannerIPAddress(line):
    ip_start = 4
    ip_end = 4
    position = 0
    periods = 0
    address = ''
    for character in line:
        if(character == ' '):
            position += 1
        elif(position >= ip_start):
            address = address + character
            if(character == '.'):
                periods += 1
                if(periods >= ip_end):
                    return address;

    return address;


# count 5 '.' then go until a space is seen.
def GetLinePort(line):
    port_start = 0
    port_end = ' '
    position = 0
    position2 = 0
    port = ""
    for character in line:
        if(character == '.'):
            port_start += 1
        elif(port_start == 5):
            if(character == port_end):

                return port;
            else:
                port = port + character

    return;

def GetLineScannerPort(line):
    port_start = 9
    port_end = ' '
    position = 0
    port = ""

    for character in line:
        if(character == '.'):
            position += 1
        elif(position >= port_start):
            if(character == ':'):
                break;
            else:
                port = port + character

    return port;

def LineIsNotWebRequest(line):

    if ("AAAA" in line): return 0;
    if ("AAA" in line): return 0;
    if ("A?" in line): return 0;
    if(".com" in line): return 0;
    if("www." in line): return 0;
    if("who-has" in line): return 0;
    if("is-at" in line): return 0;

    return 1;


def FindIpInList(ip, ip_address_list):
    location = 0

    for address in ip_address_list:
        if(address == ip):
            return location;
        location += 1
    return;

def FindScannerIpInList(scanner_ip, ip_address_scanner_list):
    location = 0

    for address in ip_address_scanner_list:
        if(address == scanner_ip):
            return location;
        location += 1

    return;



# This function checks to see if the current line with the ip address specified has a port that corresponds to
# a -F scan from nmap.
def DetectNmapF(Nmap_F_portCounters, Nmap_F_portCounters_scanner, Nmap_F_portList_size):
    potential_attacker = 0
    potential_attacker_ip_match = 0

    potential_victim = 0
    potential_victim_ip_match = 0

    position1 = 0
    position2 = 0

    location = 0
    location2 = 0

    for num_of_ports in Nmap_F_portCounters:
        if(num_of_ports == Nmap_F_portList_size):
            potential_victim = 1;
            #print("GOT HERE")

    for num_of_scanner_ports in Nmap_F_portCounters_scanner:
        if(num_of_scanner_ports == Nmap_F_portList_size):
            potential_attacker = 1;
            #print("GOT HERE")

        if((potential_victim + potential_attacker) > 0):
            return 1;

    return 0; # if this then do not add to list.

def DetectFnScan(line):
    num_spaces = 0
    address = ''
    for character in line:
        if(character == ' '):
            num_spaces += 1
        elif(num_spaces == 7):
            address = address + character
            if(character == ','):
                #print(address.strip(','))
                return address.strip(',');

    return;

def DetectNmapsS(Nmap_sS_portCounters,Nmap_sS_portCounters_scanner, Nmap_sS_portList_size):
    potential_attacker = 0
    potential_attacker_ip_match = 0

    potential_victim = 0
    potential_victim_ip_match = 0


    for num_of_scanner_ports in Nmap_sS_portCounters_scanner:
        if(num_of_scanner_ports == Nmap_sS_portList_size):
            potential_attacker = 1;
            #print("GOT HERE")

        if(potential_attacker == 1):
            return 1;

    return 0;

def DetectNmapV(Nmap_v_portCounters_scanner, Nmap_v_portList_size):
    potential_attacker = 0
    for num_of_scanner_ports in Nmap_v_portCounters_scanner:
        if(num_of_scanner_ports == Nmap_v_portList_size):
            potential_attacker = 1;
            #print("GOT HERE")

        if(potential_attacker == 1):
            return 1;
    return 0;



if len(sys.argv) == 1:
    s = ''
else:
    s = sys.argv[1]
main(s)
#       1
#for the first bonus taks just pipe the log files
#       2
# for the second bonus differentiate between different types of scans.
# do this by checking for a string in the line of the log files.
#       3
# for the last bonus task try to detect both a smiley face and an ftp connection.
