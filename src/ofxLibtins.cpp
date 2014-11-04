//
//  ofxLibtins.cpp
//  NetworkStream
//
//  Created by Jonas Jongejan on 29/10/14.
//
//

#include "ofxLibtins.h"

ofxLibtinsSimpleSniffer::ofxLibtinsSimpleSniffer(){
    ofAddListener(ofEvents().update, this, &ofxLibtinsSimpleSniffer::update);
}

ofxLibtinsSimpleSniffer::~ofxLibtinsSimpleSniffer(){
    sniffer->stop_sniff();
    lock();
    delete sniffer;
    unlock();
}


void ofxLibtinsSimpleSniffer::startSniffing(string _interface){
    interface = _interface;

    // Sniffer configuration
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    
    // Create the sniffer instance
    sniffer =  new Sniffer(interface, config);
    
    startThread(true);
}

void ofxLibtinsSimpleSniffer::update(ofEventArgs & args){
    ofxLibtinsHttpPacket packet;

    while(incomming_http_packets.tryReceive(packet)){
        ofNotifyEvent(newHttpPacketEvent, packet, this);
    }
}


void ofxLibtinsSimpleSniffer::threadedFunction()
{
    while(isThreadRunning())
    {
        lock();
        
        try {
            Packet packet = sniffer->next_packet();
            
            if(packet)
            {
                newRawPacketEvent.notifyAsync(this, packet);
                
                ofxLibtinsHttpPacket http = ofxLibtinsHttpPacket(packet);
                if(http.isValid){
                    incomming_http_packets.send(http);
                }
            }
        } catch(...){
         
        }
        unlock();
    }
}


            