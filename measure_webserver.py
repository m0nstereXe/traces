from scapy.all import *
import sys
import time
import math 

def grab_http_response_times(pcap_filename,ip,port):
    last_send = 0
    ans = [] 
    processed_file = rdpcap(pcap_filename)  
    sessions = processed_file.sessions()   
    for ses in sessions:
        for p in sessions[ses]:
            if p.haslayer(TCP):
                if p.haslayer(HTTP):
                    if p[IP].dst == ip and p[TCP].dport == port:
                        if HTTPRequest in p:
                            last_send = p.time
                    elif p[IP].src == ip and p[TCP].sport == port:
                        if HTTPResponse in p:
                            time_sent = p.time - last_send
                            ans.append(time_sent)

    return ans


def grab_average(times):
    return sum(times)/len(times)

def grab_percentile(times,percentile):
    return times[int(math.floor(len(times)*percentile))]

percents = [0.25,0.5,0.75,0.95,0.99]

def main():
    load_layer("http")
    input_file = sys.argv[1]
    ip,port = sys.argv[2],int(sys.argv[3])
    times = grab_http_response_times(input_file,ip,port)
    times.sort()


    print("AVERAGE LATENCY: %f" % grab_average(times))
    lat = [grab_percentile(times,p) for p in percents]
    print("PERCENTILE LATENCIES: %f, %f, %f, %f, %f" % (lat[0],lat[1],lat[2],lat[3],lat[4]))



if __name__ == '__main__':
    main()