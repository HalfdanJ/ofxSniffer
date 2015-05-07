#include "ofApp.h"

//--------------------------------------------------------------
void ofApp::setup(){
    // Add event listener for new http packets
    ofAddListener(sniff.httpPacketEvent, this, &ofApp::httpPacket);
    
    // Add event listener for new beacon frame packets
    ofAddListener(sniff.beaconFrameEvent, this, &ofApp::beaconFrame);
    
    // Add event listener for new probe request frame packets
    ofAddListener(sniff.probeRequestFrameEvent, this, &ofApp::probeRequestFrame);

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
    int i;
    set<string>::iterator itr;
    
    i = 0;
    for(itr = beaconSsids.begin(); itr != beaconSsids.end(); itr++){
        ofDrawBitmapString(*itr, ofPoint(10, 20 * i + 20));
        i++;
    }
    
    ofTranslate(ofGetWidth() / 3, 0);
    i = 0;
    for(itr = probeRequestSsids.begin(); itr != probeRequestSsids.end(); itr++){
        ofDrawBitmapString(*itr, ofPoint(10, 20 * i + 20));
        i++;
    }
    
    ofTranslate(ofGetWidth() / 3, 0);
    while(incomingPackets.size() > 50){
        incomingPackets.pop_front();
    }
    
    for(i = 0; i < incomingPackets.size(); i++){
        ofDrawBitmapString(incomingPackets[i], ofPoint(10, 20 * i + 20));
    }
}

//--------------------------------------------------------------
void ofApp::httpPacket(ofxSnifferHttpPacket &packet){
    incomingPackets.push_back(packet.host+packet.request);
}

//--------------------------------------------------------------
void ofApp::beaconFrame(ofxSnifferBeaconFrame &beacon){
    beaconSsids.insert(beacon.ssid);
}

//--------------------------------------------------------------
void ofApp::probeRequestFrame(ofxSnifferProbeRequestFrame &probeRequest){
    probeRequestSsids.insert(probeRequest.ssid);
}