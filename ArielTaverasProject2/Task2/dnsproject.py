import re
import string
import sys
import codecs
import csv
import datetime
from collections import Counter
from itertools import islice
#import string.ascii_letters

# #
# 1st detect first time the website name is seen and then use everything after that as requests made by
# the site until the new site in gone to.

def main():
    StartScript()


for line in sys.stdin:
    num = int(line);
    print(num**2, end="")

    
    return;

def StartScript():
    Stored_list = []
    List_Index = [0] * 5000
    UniqueRequests = 0
    InitialRequest = ""
    #FileOut = OpenFile("out.txt")
    #f = open('mydns.txt', 'r')
    #f = open('P.txt', 'r')
    f = open('dnslog.txt', 'r')
    ReportFile = open ("dnsReport.txt", 'a')
    Append_Flag = 1
    prev_time_minute = list("00")
    prev_time_seconds = list("00")
    time_minute = list("00")
    time_seconds = list("00")
    init_time = list("00")
    previous_lines = list("")
    for line in f:
        time_minute = list("00")
        time_seconds = list("00")
        time = list("00") # time in milliseconds!!!!

        ReadInTime(line,time, time_minute, time_seconds)

        if(CheckForPatterns(line) and CheckNumberOfPeriods(line)):
            previous_lines.append(line)


        # Check/Perform Analysis for different conditions to detect a new web request from a user.
        if(CompareWithPreviousLines(previous_lines, line) and CheckForPatterns(line) and CheckNumberOfPeriods2(line) and (ConvertToSeconds(time_minute, time_seconds, time) - ConvertToSeconds(prev_time_minute, prev_time_seconds, init_time))  >= int(50000) ):
            ReportFile.write(PrintNewRequest(InitialRequest, UniqueRequests))
            previous_lines[:] = [""]
            t = 0
            for y in Stored_list:
                ReportFile.write(PrintLine(y, 0))
                #print(str(y)) #+ "  appears " + str(List_Index[t]+1) + "  times!!!")
                t = t+1
            Stored_list[:] = [""]

            # index = 0
            print("\n\n")
            ReportFile.write("\n\n")
            #print("Time threshold exceeded for Total MilliSeconds. at time --> " + "Minute: " + "".join(time_minute) + " Seconds: " + "".join(time_seconds) + "  Milliseconds:" +"".join(time)+ "  NEW WEB REQUEST" + '\n' + "Time Difference since previous user request:")
            #ReportFile.write("Time threshold exceeded for Total MilliSeconds. at time --> " + "Minute: " + "".join(time_minute) + " Seconds: " + "".join(time_seconds) + "  Milliseconds:" +"".join(time)+ "  NEW WEB REQUEST" + '\n' + "Time Difference since previous user request:")
            #print(ConvertToSeconds(time_minute, time_seconds, time) - ConvertToSeconds(prev_time_minute, prev_time_seconds, init_time))
            #ReportFile.write(str(ConvertToSeconds(time_minute, time_seconds, time) - ConvertToSeconds(prev_time_minute, prev_time_seconds, init_time)))
            init_time = time
            prev_time_minute = time_minute # keeps track of the previous lines minute time
            prev_time_seconds = time_seconds
            InitialRequest = line
            UniqueRequests = 0
        # else:
        #     print("THRESHOLD NOT REACHED!")
        #     #break

        Append_Flag = CheckIfDuplicate(Stored_list, line, List_Index)

        #print(Append_Flag)
        if(Append_Flag == 1):
            Stored_list.append(line.strip('\n').replace('A', ''))
            #print(Stored_list)
            UniqueRequests = UniqueRequests + 1
            #Append_Flag = 0


    PrintNewRequest(InitialRequest, UniqueRequests)
    t = 0
    for y in Stored_list:
        ReportFile.write(PrintLine(y, 0))
        #print(str(y)) #+ "  appears " + str(List_Index[t]+1) + "  times!!!")
        t = t+1
    Stored_list[:] = [""]

    print("END OF FILE/Program Finished ")
    ReportFile.write("END OF FILE/Program Finished ")
    #print(UniqueRequests)
    f.close()

    return;

def CompareWithPreviousLines(prev_lines, line):
    for p_line in prev_lines:
        if((ParseLine(p_line) in ParseLine(line)) and ("www." in line)):
            return 1
    return 0

def ParseLine(line):
    parsed_line = list("")
    position = 0
    for i in line:
        if(position > 60):
            parsed_line.append(i)
        position += 1
    parsed_line = "".join(parsed_line)
    parsed_line = parsed_line.strip('\n')
    parsed_line = parsed_line.replace("IN", '')
    parsed_line = parsed_line.replace("AAAA", '')
    parsed_line = parsed_line.replace("A", '')
    parsed_line = parsed_line.strip(' ')
    #print(parsed_line)
    return parsed_line


def CheckNumberOfPeriods(line1):
    total_periods = 0
    for i in line1:
        if(i == '.'):
            total_periods += 1
    if((total_periods == 6)):
        return 1
    else:
        return 0

def CheckNumberOfPeriods2(line1):
    total_periods = 0
    for i in line1:
        if(i == '.'):
            total_periods += 1
    if((total_periods == 7)):
        return 1
    else:
        return 0

def CheckForPatterns(line1):
    var = 0
    if("www." in line1):
        var = 1
    if(".com." in line1):
        var = 1
    else:
        return 0
    if("AAAA" in line1):
        return 0
    return 1

def ConvertToSeconds(t1_minutes, t2_seconds, t3_millisec):
    total_seconds = int("".join(t1_minutes)) * int(60) * int(1000)
    total_seconds += int("".join(t2_seconds)) * int(1000)
    total_seconds += int("".join(t3_millisec)) *10
    return total_seconds


def CheckTimeThresholdMilliseconds(t1, t2, mode):
    time_treshold = int("".join(t1))-int("".join(t2))

    if(time_treshold >= int(10)):
        return 1
    else:
        return 0
#Prints and returns the name of site in a line. As well as the time.
def PrintNewRequest(line2, num):
    position_in_line_name = 0;
    position_in_line_time = 0
    temp_name = [""]
    temp_time = [""]
    for i in line2:
        if(position_in_line_name > 60):
            temp_name.append(i)
        position_in_line_name += 1

    for y in line2:
        if(position_in_line_time < 25):
            temp_time.append(y)
        position_in_line_time += 1

    print("".join(temp_name).strip('\n').replace('IN A', '') + ":" + str(num) + "  Time: " + "".join(temp_time))

    return "".join(temp_name).strip('\n').replace('IN A', '') + ":" + str(num) + "  Time: " + "".join(temp_time)
#Prints and returns the name of site in a line
def PrintLine(line2, mode):
    position_in_line = 0
    temp_string = [""]
    for i in line2:
        if(position_in_line > 60):
            #print(i)
            temp_string.append(i)
        position_in_line = position_in_line + 1

    print("".join(temp_string).replace("IN", ''))
    return "".join(temp_string).replace("IN", '') + '\n';


def ReadInTime(line,time_ms,time_minute, time_seconds):
    position = 0
    for u in line:
        position += 1
        if(position == 15):
            time_minute[0] = u
        elif(position == 16):
            time_minute[1] = u
        elif(position == 18):
            time_seconds[0] = u
        elif(position == 19):
            time_seconds[1] = u
        elif(position == 21):
            time_ms[0] = u
        elif(position == 22):
            time_ms[1] = u

    return;

# Checks to see if the line is an unecesesary ipv6 request.
def CheckIfDuplicate(Stored_list, line, List_Index):
    index = 0
    Append_Flag = 0
    Request_Counter = 0
    #print(line)
    for i in Stored_list:
        #print(i)
        #index = 0
        if ("AAA" in line):
            Append_Flag = 0
        elif("AAAA" in line):
            Append_Flag = 0
        elif("AA" in line):
            Append_Flag = 0

        elif line.strip('\n').replace('A', '') == i:
            #print("FOUND !!!!")
            Append_Flag = 0
            #print(Append_Flag)
            #print(line)
            List_Index[index] = List_Index[index] + 1
            #print(List_Index[index])
            #print(index)
            break
            #print(i)
        else:
            Append_Flag = 1
            #print(Append_Flag)
            index = index + 1
    return Append_Flag;

def OpenFile(name):
    file = open(name, 'w')
    return file;

#################################################
main()

# notes:
# to edit the dns2proxy file ....
