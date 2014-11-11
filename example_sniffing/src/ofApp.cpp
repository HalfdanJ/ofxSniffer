#include "ofApp.h"

//--------------------------------------------------------------
void ofApp::setup(){
    // Add event listener for new http packets
    ofAddListener(sniff.httpPacketEvent, this, &ofApp::httpPacket);

    // Start the sniffing
    sniff.startSniffing("en0", true);
    
    ofBackground(0);
}

//--------------------------------------------------------------
void ofApp::exit() {
    sniff.stopThread();
}

//--------------------------------------------------------------
void ofApp::draw() {
    ofSetColor(255);
    for(int i = 0; i < incomingPackets.size(); i++){
        ofDrawBitmapString(incomingPackets[i], ofPoint(10, 20 * i + 20));
    }
}

//--------------------------------------------------------------
void ofApp::httpPacket(ofxSnifferHttpPacket &packet){
    incomingPackets.push_back(packet.host+packet.request);

    while(incomingPackets.size() > 50){
        incomingPackets.pop_front();
    }
}