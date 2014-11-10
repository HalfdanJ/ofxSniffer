#include "ofApp.h"

//--------------------------------------------------------------
void ofApp::setup(){
    // Add event listener for new http packets
    ofAddListener(sniffer.newHttpPacketEvent, this, &ofApp::newHttpPacket);

    // Start the sniffing
    sniffer.startSniffing("en0", true);
    
    ofBackground(0, 0, 0);
}

//--------------------------------------------------------------
void ofApp::exit(){
    sniffer.stopThread();
}

//--------------------------------------------------------------
void ofApp::update(){

}

//--------------------------------------------------------------
void ofApp::draw(){
    ofSetColor(255);
    for(int i=0;i<incomingPackets.size();i++){
        ofDrawBitmapString(incomingPackets[i], ofPoint(10,20*i+20));
    }
}

//--------------------------------------------------------------
void ofApp::newHttpPacket(ofxLibtinsHttpPacket &packet){
    incomingPackets.push_back(packet.host+packet.request);

    while(incomingPackets.size() > 50){
        incomingPackets.pop_front();
    }
}