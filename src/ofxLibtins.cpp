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
    
    startThread(true);

}

void ofxLibtinsSimpleSniffer::update(ofEventArgs & args){
    ofxLibtinsHttpPacket packet;

    while(incomming_http_packets.tryReceive(packet)){
        ofNotifyEvent(newHttpPacketEvent, packet, this);
    }
}


/*
bool ofxLibtinsSimpleSniffer::lock(){
    return ofThread::lock();
}
void ofxLibtinsSimpleSniffer::unlock(){
    ofThread::unlock();
}*/




void ofxLibtinsSimpleSniffer::threadedFunction()
{
    SnifferConfiguration config;
    //config.set_filter("port 80");
    config.set_promisc_mode(true);
    //  config.set_snap_len(400);
    
    sniffer =  new Sniffer(interface, config);
    
    while(isThreadRunning())
    {
        lock();

        Packet packet = sniffer->next_packet();

        // Attempt to lock the mutex.  If blocking is turned on,
        if(packet)
        {
            newRawPacketEvent.notifyAsync(this, packet);
            
            ofxLibtinsHttpPacket http = ofxLibtinsHttpPacket(packet);
            if(http.isValid){
            //    newHttpPacketEvent.notifyAsync(this, http);
                incomming_http_packets.send(http);
            }
            /*
            if(http.isValid && lock()){
                cout<<"lock"<<endl;
                _incommingHttpPackets.push_back(http);
                cout<<"unlock"<<endl;
                unlock();

            }*/
        }
        unlock();
    }
}


            