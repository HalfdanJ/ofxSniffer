#pragma once

#include "ofMain.h"
#include "ofxLibtins.h"

class ofApp : public ofBaseApp{
    
public:
    void setup();
    void exit();
    void draw();
        
    ofxSniff sniff;
    
    void httpPacket(ofxLibtinsHttpPacket &packet);
    
    // a deque is like a vector that can be
    // pushed/popped from back or front
    deque<string> incomingPackets;
};
