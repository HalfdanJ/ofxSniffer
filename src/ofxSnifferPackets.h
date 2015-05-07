#pragma once

#include "tins.h"
#include "ofUtils.h"

using namespace Tins;

template <class T>
HWAddress<6> get_src_addr(const T& data) {
    if(!data.from_ds() && !data.to_ds())
        return data.addr2();
    if(!data.from_ds() && data.to_ds())
        return data.addr2();
    return data.addr3();
}

template <class T>
HWAddress<6> get_dst_addr(const T& data) {
    if(!data.from_ds() && !data.to_ds())
        return data.addr1();
    if(!data.from_ds() && data.to_ds())
        return data.addr3();
    return data.addr1();
}

class ofxSnifferProbeRequestFrame {
public:
    bool isValid = false;
    
    string ssid;
    HWAddress<6> addr;
    
    ofxSnifferProbeRequestFrame() {}
    
    ofxSnifferProbeRequestFrame(Packet packet) {
        try {
            packet.pdu()->rfind_pdu<Tins::Dot11ProbeRequest>();
            const Tins::Dot11ManagementFrame &data = packet.pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();
            ssid = data.ssid();
            addr = get_src_addr(data);
            isValid = true;
        } catch (...) {
        }
    }
};

class ofxSnifferBeaconFrame {
public:
    bool isValid = false;
    
    string ssid;
    HWAddress<6> addr;
    
    ofxSnifferBeaconFrame() {}
    
    ofxSnifferBeaconFrame(Packet packet) {
        try {
            packet.pdu()->rfind_pdu<Tins::Dot11Beacon>();
            const Tins::Dot11ManagementFrame &data = packet.pdu()->rfind_pdu<Tins::Dot11ManagementFrame>();
            ssid = data.ssid();
            addr = get_src_addr(data);
            isValid = true;
        } catch (...) {
        }
    }
};

class ofxSnifferHttpPacket {
public:
    bool isValid = false;
    
    string srcIp;  /**< Source IP address. */
    string dstIp; /**< Destination IP address. */
    
    string host;  /**< Hostname in the HTTP request. */
    string requestType; /**< Request type in the HTTP request (GET/POST...). */
    string request; /**< The request in the HTTP request. */
    
    int srcPort = 0; /**< Source port. */
    int dstPort = 0; /**< Destination port. */
    
    ofxSnifferHttpPacket() {}
    
    ofxSnifferHttpPacket(Packet packet) {
        try {
            // Find the IP layer
            const Tins::IP &ip = packet.pdu()->rfind_pdu<Tins::IP>();

            // Find the TCP layer
            const Tins::TCP &tcp = packet.pdu()->rfind_pdu<Tins::TCP>();

            srcIp = ip.src_addr().to_string();
            srcPort = tcp.sport();
            dstIp = ip.dst_addr().to_string();
            dstPort = tcp.dport();
            
            // Get the raw PDU
            const Tins::RawPDU &raw = packet.pdu()->rfind_pdu<Tins::RawPDU>();

            std::string str = "";
            char ch;
            int s = raw.payload().size();
            int printable = 0;
            for(int i=0;i<s;i++){
                ch = raw.payload()[i];
                if(isprint(ch)) {
                    printable++;
                }
//                else {
//                    ch = '.';
//                }
                str += ch;
            }
            
//            if(printable > s / 2) {
//                cout << "data (" << (100*printable / s) << "): " << str << endl;
//            }
            
            int getIndex = str.find("GET ",0);
            int hostIndex = str.find("Host: ",0);
            
            if(getIndex != -1 && hostIndex != -1){
                
                int end = str.find(" ", getIndex+4);
                
                string get = str.substr(getIndex+4,end-(getIndex+4));
                
                end = str.find("\r", hostIndex+6);
                
                string _host = str.substr(hostIndex+6,end-(hostIndex+6));
                
                requestType = "GET";
                request = get;
                host = _host;
                
                isValid = true;
            }
        } catch(...){
        }
    }
};
