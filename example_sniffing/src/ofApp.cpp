#include "ofApp.h"

//--------------------------------------------------------------
void ofApp::setup(){
    // Add event listener for new http packets
    ofAddListener(sniffer.newHttpPacketEvent, this, &ofApp::newHttpPacket);

    // Start the sniffing
    sniffer.startSniffing("en0");
    
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
    for(int i=0;i<incomingPacktes.size();i++){
        ofDrawBitmapString(incomingPacktes[i], ofPoint(10,20*i+20));
    }
}

//--------------------------------------------------------------
void ofApp::newHttpPacket(ofxLibtinsHttpPacket &packet){
    incomingPacktes.push_back(packet.host+packet.request);

    if(incomingPacktes.size() > 50){
        incomingPacktes.pop_front();
    }
}