#pragma once
#include "ofConstants.h"

#include "ofThread.h"
#include "ofEvents.h"

#include "ofxSnifferPackets.h"
#include "ofThreadChannel.h"

#include "tins.h"

using namespace Tins;

class ofxSniff : public ofThread {
public:
    ofxSniff();
    ~ofxSniff();

    /*!
     The libtins sniffer object
     */
    Tins::Sniffer * sniffer;
    
    /*!
     Start sniffing on a background thread
     @param interface The name of the the network interface to sniff on
     */
    void startSniffing(string interface="en0", bool monitorMode = false);

    /*!
     Iterate through packet types and return a string containing all of them.
     @param packet The packet to print.
     */
    string toString(const Packet& packet);
    
    /*!
     Event emitted every time a packet is being sniffed. 
     
     Note: This event is being emitted on a background thread!
     */
    ofEvent<Packet> newRawPacketEvent;
    
    /*!
     Event emitted every time a http packet is detected. 
     This event is emitted on the main thread.
     */
    ofEvent<ofxSnifferHttpPacket> httpPacketEvent;
    
    /*!
     Event emitted every time a beacon frame is detected.
     This event is emitted on the main thread.
     */
    ofEvent<ofxSnifferBeaconFrame> beaconFrameEvent;
    
    /*!
     Event emitted every time a probe request frame is detected.
     This event is emitted on the main thread.
     */
    ofEvent<ofxSnifferProbeRequestFrame> probeRequestFrameEvent;
    
private:
    void threadedFunction();
    void update(ofEventArgs &);
    
    string interface;
    ofThreadChannel<ofxSnifferHttpPacket> httpPackets;
    ofThreadChannel<ofxSnifferBeaconFrame> beaconFrames;
    ofThreadChannel<ofxSnifferProbeRequestFrame> probeRequestFrames;
};