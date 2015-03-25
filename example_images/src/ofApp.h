#pragma once

#include "ofMain.h"
#include "ofxSniffer.h"

class ofApp : public ofBaseApp{
    
public:
    void setup();
    void exit();
    void update();
    void draw();
        
    ofxSniff sniffer;
    ofImage image;
    deque<string> files;
    
    void newHttpPacket(ofxSnifferHttpPacket &packet);
};
