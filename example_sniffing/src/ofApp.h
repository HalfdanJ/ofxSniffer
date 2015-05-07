#pragma once

#include "ofMain.h"
#include "ofxSniffer.h"

class ofApp : public ofBaseApp{
    
public:
    void setup();
    void exit();
    void draw();
        
    ofxSniff sniff;
    
    void httpPacket(ofxSnifferHttpPacket &packet);
    void beaconFrame(ofxSnifferBeaconFrame &beacon);
    void probeRequestFrame(ofxSnifferProbeRequestFrame &probeRequest);
    
    // a deque is like a vector that can be
    // pushed/popped from back or front
    deque<string> incomingPackets;
    
    set<string> beaconSsids, probeRequestSsids;
};
