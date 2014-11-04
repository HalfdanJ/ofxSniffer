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

    /*!
     The libtins sniffer object
     */
    Tins::Sniffer * sniffer;

    
    /*!
     Start sniffing on a background thread
     @param interface The name of the the network interface to sniff on
     */
    void startSniffing(string interface="en0");

    
    
    /*!
     Event emitted every time a packet is being sniffed. 
     
     Note: This event is being emitted on a background thread!
     */
    ofEvent<Packet> newRawPacketEvent;
    
    
    /*!
     Event emitted every time a http packet is detected. 
     This event is emitted on the main thread.
     */
    ofEvent<ofxLibtinsHttpPacket> newHttpPacketEvent;
    

private:
    void threadedFunction();

    void update(ofEventArgs &);
    
    string interface;


    ofThreadChannel<ofxLibtinsHttpPacket> incomming_http_packets;

};