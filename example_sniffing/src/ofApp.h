#pragma once

#include "ofMain.h"
#include "ofxLibtins.h"

class ofApp : public ofBaseApp{
    
public:
    void setup();
    void exit();
    void update();
    void draw();
        
    ofxSniff sniff;
    
    void httpPacket(ofxLibtinsHttpPacket &packet);
    
    //Almost just like vectors, just better for this example
    deque<string> incomingPackets;
};
