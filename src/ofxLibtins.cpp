#include "ofxLibtins.h"

#include "ofUtils.h"

ofxSniff::ofxSniff(){
    ofAddListener(ofEvents().update, this, &ofxSniff::update);
}

ofxSniff::~ofxSniff(){
    sniffer->stop_sniff();
    lock();
    delete sniffer;
    unlock();
}

void ofxSniff::startSniffing(string _interface, bool monitorMode){
    interface = _interface;

    // Sniffer configuration
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_rfmon(monitorMode);
    
    // Create the sniffer instance
    sniffer = new Sniffer(interface, config);
    
    startThread(true);
}

void ofxSniff::update(ofEventArgs & args){
    ofxLibtinsHttpPacket packet;

    while(incomming_http_packets.tryReceive(packet)){
        ofNotifyEvent(httpPacketEvent, packet, this);
    }
}

void ofxSniff::threadedFunction() {
    while(isThreadRunning()) {
        lock();
        try {
            Packet packet = sniffer->next_packet();
            if(packet) {
                newRawPacketEvent.notifyAsync(this, packet);
                ofxLibtinsHttpPacket http = ofxLibtinsHttpPacket(packet);
                if(http.isValid){
                    incomming_http_packets.send(http);
                }
            }
        } catch(...) {
        }
        unlock();
    }
}


            