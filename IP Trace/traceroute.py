import struct
import argparse
from basic_structures import *
from trace import *
import statistics

def main():
    packet_headers = {} 
    packet_data = {}
    ether_headers = {}
    ipv4_headers = {}
    tcp_headers = {}
    
    udp_info = {}
    icmp_info = {}
    icmp_res = {}
    src = []
    dst = []
    nodes = []
 
    parser = argparse.ArgumentParser()
    parser.add_argument("CAP", help="Enter the name of cap file as an input")
    args = parser.parse_args()

    cap_file = args.CAP

    try:
        file = open(cap_file, "rb")
    except:
        print("Error: The file may not exist.")
        exit()

    split_packet(packet_headers,packet_data,file)


    if (check_os(packet_data) == 0):
        get_data(packet_data, packet_headers, udp_info, icmp_info, src, dst)
        nodes = sort_nodes(icmp_info,udp_info,src,dst)
        calc_rtt(udp_info,icmp_info)
        calc_adv_rtt(icmp_info)
        result(udp_info, icmp_info, src, dst, nodes)

    elif (check_os(packet_data) == 1):
        get_win_data(packet_data, packet_headers, icmp_res, icmp_info, src, dst)
        nodes = sort_nodes(icmp_info,icmp_res,src,dst)
        calc_rtt(icmp_res,icmp_info)
        calc_adv_rtt(icmp_info)
        result(icmp_res, icmp_info, src, dst, nodes)

    
    # print(icmp_info)
    # print(udp_info)
    # print(icmp_res)

## This function checks if pcap is captures in Linux or Windows
## besed on existance of a valid UDP header.
## If there's valid UDP header, file is captured in Linux.
## Otherwise, the file is captured in Windows
def check_os(packet_data):
    udp = False
    icmp = False
    
    for key in packet_data:
        IHL = struct.unpack("<B", packet_data[key][14:15])[0]                          # Get IP Version Number and IHL
        IHL = IHL & 0x0f                                                            # But we need only IHL, so use mask to get IHL only
        IHL = 4*IHL

        protocol = struct.unpack("B",packet_data[key][23:24])[0]

        if protocol == 1:
            icmp = True

        elif protocol == 17:
            buffer = packet_data[key][14+IHL+2:14+IHL+4]
            num1 = ((buffer[0]&240)>>4)*16*16*16
            num2 = (buffer[0]&15)*16*16
            num3 = ((buffer[1]&240)>>4)*16
            num4 = (buffer[1]&15)
            dst_port = num1+num2+num3+num4
            
            if (dst_port >= 33434 and dst_port <= 33529):
                udp = True

    if udp == True and icmp == True:
        return 0
    elif udp == False and icmp == True:
        return 1

## This function extracts needed data from pcap file captured in Linux
def get_data(packet_data, packet_headers, udp_info, icmp_info, src, dst):

    frag_num = 0

    orig_seconds = struct.unpack('I',packet_headers["packet_header1"][:4])[0]
    orig_microseconds = struct.unpack('<I',packet_headers["packet_header1"][4:8])[0]
    orig_time = orig_seconds + orig_microseconds  *0.000000001

    num = 1

    prev_ID = 0
    while True:
        try:
            key = "packet_data" + str(num)
            key1 = "packet_header" + str(num)

            p = packet()

            ts_sec = packet_headers[key1][:4]
            ts_usec = packet_headers[key1][4:8]
            p.timestamp_set(ts_sec,ts_usec,orig_time)

            time = p.timestamp # in second

            IHL = struct.unpack("<B", packet_data[key][14:15])[0]       # Get IP Version Number and IHL
            IHL = IHL & 0x0f                                            # But we need only IHL, so use mask to get IHL only
            IHL = 4*IHL

            ip = IP_Header()
            total_length = packet_data[key][16:18]
        
            ip.get_total_len(total_length)
            total_length = ip.total_len

            ID = packet_data[key][18:20]
            num1 = ((ID[0]&240)>>4)*16*16*16
            num2 = (ID[0]&15)*16*16
            num3 = ((ID[1]&240)>>4)*16
            num4 = (ID[1]&15)
            ID = num1+num2+num3+num4
            
            flags = packet_data[key][20:22][0]&224
        
            frag_offset = packet_data[key][20:22][1]&31

            ttl = struct.unpack("B",packet_data[key][22:23])[0]

            protocol = struct.unpack("B",packet_data[key][23:24])[0]

            if protocol == 17:
                buffer = packet_data[key][14+IHL:14+IHL+2]
                num1 = ((buffer[0]&240)>>4)*16*16*16
                num2 = (buffer[0]&15)*16*16
                num3 = ((buffer[1]&240)>>4)*16
                num4 = (buffer[1]&15)
                src_port = num1+num2+num3+num4

                buffer = packet_data[key][14+IHL+2:14+IHL+4]
                num1 = ((buffer[0]&240)>>4)*16*16*16
                num2 = (buffer[0]&15)*16*16
                num3 = ((buffer[1]&240)>>4)*16
                num4 = (buffer[1]&15)
                dst_port = num1+num2+num3+num4

                

            elif protocol == 1:
                icmp_type = struct.unpack("B",packet_data[key][14+20:14+20+1])[0]

                if icmp_type in [0,3,8,11]:
                    buffer = packet_data[key][14+IHL+8+20:14+IHL+8+20+2]
                    num1 = ((buffer[0]&240)>>4)*16*16*16
                    num2 = (buffer[0]&15)*16*16
                    num3 = ((buffer[1]&240)>>4)*16
                    num4 = (buffer[1]&15)
                    src_port = num1+num2+num3+num4

                    buffer = packet_data[key][14+IHL+8+20+2:14+IHL+8+20+4]
                    num1 = ((buffer[0]&240)>>4)*16*16*16
                    num2 = (buffer[0]&15)*16*16
                    num3 = ((buffer[1]&240)>>4)*16
                    num4 = (buffer[1]&15)
                    dst_port = num1+num2+num3+num4
                else:
                    src_port = 0
                    dst_port = 0

            else:
                src_port = 0
                dst_port = 0


            ip = IP_Header()
            source_address = packet_data[key][26:30]
            dest_address = packet_data[key][30:34]
            ip.get_IP(source_address, dest_address)

            if frag_offset != 0:
                frag_offset = frag_offset*80 - total_length


        ### Creating dictionary regarding UDP information captured from pcap file ###
            if (dst_port >= 33434 and dst_port <= 33529):
                if protocol == 17:
                    udp_info[dst_port] = [frag_num, frag_offset, ttl, ip.src_ip, ip.dst_ip, ID, time]
                    if ttl == 1 and ip.src_ip not in src and ip.dst_ip not in dst:
                        src.append(ip.src_ip)
                        dst.append(ip.dst_ip)

            else:    
                if ID == prev_ID and protocol == 17:        
                    udp_info[prev_port][0] += 1
                    udp_info[prev_port][1] += frag_offset
                    

            ### Creating dictionary regarding ICMP information captured from pcap file ###
            if protocol == 1:
                pair = []
                rtts = []
                avg_rtt = 0
                sd_rtt = 0
                if dst_port in udp_info:
                    ttl = udp_info[dst_port][2] 

                if ip.src_ip not in icmp_info:
                    if ip.dst_ip in src:
                        
                        timestamp = (dst_port,time)
                        icmp_info[ip.src_ip] = [ttl,pair,rtts,avg_rtt,sd_rtt]
                        icmp_info[ip.src_ip][1].append(timestamp)

                else:
                    timestamp = (dst_port,time)
                    icmp_info[ip.src_ip][1].append(timestamp) 


            prev_ID = ID
            prev_port = dst_port
            num = num + 1
        except:
            break

## This function extracts needed data from pcap file captured in Windows
def get_win_data(packet_data, packet_headers, icmp_res, icmp_info, src, dst):
    frag_num = 0

    orig_seconds = struct.unpack('I',packet_headers["packet_header1"][:4])[0]
    orig_microseconds = struct.unpack('<I',packet_headers["packet_header1"][4:8])[0]
    orig_time = orig_seconds + orig_microseconds  *0.000000001

    num = 1

    while True:
        try:
            key = "packet_data" + str(num)
            key1 = "packet_header" + str(num)

            p = packet()

            ts_sec = packet_headers[key1][:4]
            ts_usec = packet_headers[key1][4:8]
            p.timestamp_set(ts_sec,ts_usec,orig_time)

            time = p.timestamp # in second

            IHL = struct.unpack("<B", packet_data[key][14:15])[0]                          # Get IP Version Number and IHL
            IHL = IHL & 0x0f                                                            # But we need only IHL, so use mask to get IHL only
            IHL = 4*IHL

            ip = IP_Header()
            total_length = packet_data[key][16:18]
        
            ip.get_total_len(total_length)
            total_length = ip.total_len

            ID = packet_data[key][18:20]
            num1 = ((ID[0]&240)>>4)*16*16*16
            num2 = (ID[0]&15)*16*16
            num3 = ((ID[1]&240)>>4)*16
            num4 = (ID[1]&15)
            ID = num1+num2+num3+num4
            
            flags = packet_data[key][20:22][0]&224
        
            frag_offset = packet_data[key][20:22][1]&31

            ttl = struct.unpack("B",packet_data[key][22:23])[0]
            protocol = struct.unpack("B",packet_data[key][23:24])[0]

            if protocol == 1:
                ip = IP_Header()
                source_address = packet_data[key][26:30]
                dest_address = packet_data[key][30:34]
                ip.get_IP(source_address, dest_address)

                pair = []
                rtts = []
                avg_rtt = 0
                sd_rtt = 0

                if not src and not dst:
                    src.append(ip.src_ip)
                    dst.append(ip.dst_ip)
                
                icmp_type = struct.unpack("BB", packet_data[key][14+IHL+0:14+IHL+2])[0]
                # cs = struct.unpack("BB", packet_data[key][14+IHL+2:14+IHL+4])
                ID = packet_data[key][18:20]
                num1 = ((ID[0]&240)>>4)*16*16*16
                num2 = (ID[0]&15)*16*16
                num3 = ((ID[1]&240)>>4)*16
                num4 = (ID[1]&15)
                ID = num1+num2+num3+num4

                seq = packet_data[key][14+IHL+6:14+IHL+8]
                num1 = ((seq[0]&240)>>4)*16*16*16
                num2 = (seq[0]&15)*16*16
                num3 = ((seq[1]&240)>>4)*16
                num4 = (seq[1]&15)
                seq = num1+num2+num3+num4

                if ip.dst_ip in src:
                    if icmp_type == 11:
                        seq = packet_data[key][14+IHL+8+IHL+6:14+IHL+8+IHL+8]
                        num1 = ((seq[0]&240)>>4)*16*16*16
                        num2 = (seq[0]&15)*16*16
                        num3 = ((seq[1]&240)>>4)*16
                        num4 = (seq[1]&15)
                        seq = num1+num2+num3+num4

                        timestamp = (seq, time)
                    
                    if ip.src_ip not in icmp_info:
                        pair.append(timestamp)
                        icmp_info[ip.src_ip] = [ttl,pair,rtts,avg_rtt,sd_rtt]
                    else:
                        icmp_info[ip.src_ip][1].append(timestamp)

                    if seq in icmp_res:
                        icmp_info[ip.src_ip][0] = icmp_res[seq][2]

                if ip.src_ip in src:
                    if seq not in icmp_res:
                        icmp_res[seq] = [frag_num, frag_offset, ttl, ip.src_ip, ip.dst_ip, ID, time]
                    else:
                        icmp_res[seq][0] += 1
                        icmp_res[seq][1] += frag_offset

            num += 1

        except:
            break

## This function sorts intermediate nodes based on hop counts in increasing order
## and return sorted list of intermediate nodes
def sort_nodes(icmp_info,udp_info,src,dst):
    intermediate_nodes = []
    for key in icmp_info:
        if key in src or key in dst:
            continue
    
        port = icmp_info[key][1][0][0]

        if port not in udp_info:
            continue

        if not intermediate_nodes:
            intermediate_nodes.append(key)
            continue

        for node in intermediate_nodes:
            index = intermediate_nodes.index(node)
           
            if icmp_info[key][0] >= icmp_info[node][0]:
                continue

            else:
                intermediate_nodes.insert(index,key)
                break

        if index == len(intermediate_nodes) - 1:
            intermediate_nodes.append(key)

    return intermediate_nodes

## This function calculates rtt 
def calc_rtt(udp_info,icmp_info):
    for key in icmp_info:
        for pair in icmp_info[key][1]:
            if pair[0] in udp_info:
                rtt = round(pair[1] - udp_info[pair[0]][6],6)
                icmp_info[key][2].append(rtt)
        
## This function calculates avg and standard deviation using rtts calculated in calc_rtt()
def calc_adv_rtt(icmp_info):
    total_rtt = 0
    for key in icmp_info:
        
        avg_rtt = round(statistics.mean(icmp_info[key][2]),6)
        avg_rtt = avg_rtt*1000
        icmp_info[key][3] = avg_rtt

        sd_rtt = round(statistics.pstdev(icmp_info[key][2]),6)
        sd_rtt = sd_rtt*1000
        icmp_info[key][4] = sd_rtt
        
## This function prints out the result
def result(udp_info, icmp_info, src, dst, nodes):
    i = 1
    print("The IP of the source node: %s" %src[0])
    print("The IP of ultimate destination node: %s" %dst[0])
    print("The IP addresses of the intermediate destination nodes:")
    for node in nodes:
        print("\trouter %d: %s" %(i,node))
        i += 1

    print("\n")
    print("The value in the protocol field of IP headers:")
    
    if icmp_info:
        print("\t1: ICMP")
    if udp_info:
        print("\t17: UDP")

    for key in udp_info:
        if udp_info[key][0] != 0:
            print("\n\nThe number of fragments created from the original datagram %s is: %d" %(key,udp_info[key][0]))
            print("\nThe offset of the last fragment is: %d" %udp_info[key][1])
    
    print("\n")
    for node in nodes:
        print("The avg RTT between %s and %s is: %f ms, the s.d. is: %f" %(src[0], node, icmp_info[node][3], icmp_info[node][4]))
    

if __name__ == "__main__":
    main()   