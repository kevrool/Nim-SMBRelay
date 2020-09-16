import strutils, tables
import HelpUtil

var 
    sessionsTable* = initTable[string, string]()
    ntlmv2UsernameList: seq[string]

proc GetSMBNTLMChallenge*(payloadHex: string): string =
    var
        index = payloadHex.find("4E544C4D53535000")
    if index > 0 and payloadHex.substr(index + 16, index + 16 + 7) == "02000000":
        result = payloadHex.substr(index + 48, index + 48 + 15)

proc GetNTLMResponse*(payload: seq[char], payloadHex: string, sourceIP: string, sourcePort: int) =
    var 
        index = payloadHex.find("4E544C4D53535000")
        lmResponse: string
        ntlmResponse: string
        ntlmLength: int
        challenge: string
        domain: string
        user: string
        host: string
    
    if index > 0 and payloadHex.substr(index + 16, index + 16 + 7) == "03000000":
        # echo index
        var 
            ntlmsspOffset = int(index / 2)
            lmLength = UInt16DataLength(ntlmsspOffset + 12, payload)
            lmOffset = Uint32DataLength(ntlmsspOffset + 16, payload)
            ntlmOffset = Uint32DataLength(ntlmsspOffset + 24, payload)
            domainLength = UInt16DataLength(ntlmsspOffset + 28, payload)
            domainOffset = Uint32DataLength(ntlmsspOffset + 32, payload)
            userLength = UInt16DataLength(ntlmsspOffset + 36, payload)
            userOffset = UInt32DataLength(ntlmsspOffset + 40, payload)
            hostLength = UInt16DataLength(ntlmsspOffset + 44, payload)
            hostOffset = UInt32DataLength(ntlmsspOffset + 48, payload)

        lmResponse = payload[ntlmsspOffset + lmOffset .. ntlmsspOffset + lmOffset + (lmLength - 1)].join().toHex()
        ntlmLength = UInt16DataLength(ntlmsspOffset + 20, payload)
        ntlmResponse = payload[ntlmsspOffset + ntlmOffset .. ntlmsspOffset + ntlmOffset + (ntlmLength - 1)].join().toHex()
        domain = payload[ntlmsspOffset + domainOffset .. ntlmsspOffset + domainOffset + (domainLength - 1)].payloadToString()  
        user = payload[ntlmsspOffset + userOffset .. ntlmsspOffset + userOffset + (userLength - 1)].payloadToString()
        host = payload[ntlmsspOffset + hostOffset .. ntlmsspOffset + hostOffset + (hostLength - 1)].payloadToString()

        try:
            challenge = sessionsTable[sourceIP & ":" & $sourcePort]
        except Exception as e:
            challenge = ""
            echo e.msg

        var
            tempResponse = ntlmResponse
            ntlmv2Username = sourceIP&","&host&","&domain&"\\"&user
        tempResponse.insert(":", 32)
        
        if ntlmLength > 24:
            if challenge != "" and not ntlmv2UsernameList.contains(ntlmv2Username):
                ntlmv2UsernameList.add(ntlmv2Username)
                var ntlmV2Hash = user & "::" & domain & ":" & challenge & ":" & tempResponse
                echo ntlmV2Hash
        elif ntlmLength == 24:
            var ntlmV1Hash = user & "::" & domain & ":" & lmResponse & ":" & tempResponse & ":" & challenge 