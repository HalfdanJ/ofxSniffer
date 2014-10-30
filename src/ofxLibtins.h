#pragma once
#include "ofConstants.h"

#include "ofThread.h"
#include "ofEvents.h"

#include "ofxLibtinsPacketWrapper.h"
#include "ofxLibtinsHttpPacket.h"
#include "ofThreadChannel.h"

#include "tins.h"

using namespace Tins;

class ofxLibtinsSimpleSniffer : public ofThread {
public:
    ofxLibtinsSimpleSniffer();
    ~ofxLibtinsSimpleSniffer();
    void startSniffing(string interface);

    Sniffer * sniffer;
    
    
    /*!
     Note these events are running on the background thread!
     */
    ofEvent<Packet> newRawPacketEvent;
    ofEvent<ofxLibtinsHttpPacket> newHttpPacketEvent;
    
    void update(ofEventArgs &);

private:
    void threadedFunction();
    
    string interface;


    ofThreadChannel<ofxLibtinsHttpPacket> incomming_http_packets;

};