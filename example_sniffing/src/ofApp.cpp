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
void ofApp::update(){

}

//--------------------------------------------------------------
void ofApp::draw(){
    ofSetColor(255);
    for(int i=0;i<incommingPacktes.size();i++){
        ofDrawBitmapString(incommingPacktes[i], ofPoint(10,20*i+20));
    }
}

//--------------------------------------------------------------
void ofApp::newHttpPacket(ofxLibtinsHttpPacket &packet){
    incommingPacktes.push_back(packet.host+packet.request);

    if(incommingPacktes.size() > 50){
        incommingPacktes.pop_front();
    }
}