#pragma once

#include "ofMain.h"
#include "ofxLibtins.h"

class ofApp : public ofBaseApp{
    
public:
    void setup();
    void update();
    void draw();
        
    ofxLibtinsSimpleSniffer sniffer;
    
    void newHttpPacket(ofxLibtinsHttpPacket &packet);
    
    //Almost just like vectors, just better for this example
    deque<string> incommingPacktes;
};
