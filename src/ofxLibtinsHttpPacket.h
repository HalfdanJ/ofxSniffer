#pragma once

#include "tins.h"
#include "ofxLibtinsPacketWrapper.h"

using namespace Tins;


class ofxLibtinsHttpPacket : public ofxLibtinsPacketWrapper {
public:
    
    string srcIp;  /**< Source IP address. */
    string dstIp; /**< Destination IP address. */
    
    string host;  /**< Hostname in the HTTP request. */
    string requestType; /**< Request type in the HTTP request (GET/POST...). */
    string request; /**< The request in the HTTP request. */
    
    int srcPort; /**< Source port. */
    int dstPort; /**< Destination port. */
    
    
    ofxLibtinsHttpPacket(){};
    
    ofxLibtinsHttpPacket(Packet packet){
        isValid = false;

        try {
            // Find the IP layer
            const Tins::IP &ip = packet.pdu()->rfind_pdu<Tins::IP>();

            // Find the TCP layer
            const Tins::TCP &tcp = packet.pdu()->rfind_pdu<Tins::TCP>();
            
            // Get the raw PDU
            const Tins::RawPDU &raw = packet.pdu()->rfind_pdu<Tins::RawPDU>();
            
            srcIp = ip.src_addr().to_string();
            srcPort = tcp.sport();
            dstIp = ip.dst_addr().to_string();
            dstPort = tcp.dport();
            
            std::string str = "";
            char ch;
            int s = raw.payload().size();
            for(int i=0;i<s;i++){
                ch = raw.payload()[i];
                str += ch;
            }
            
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
