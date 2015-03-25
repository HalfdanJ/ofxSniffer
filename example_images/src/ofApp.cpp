// need to know my ip
// need to have async and sync options

#include "ofApp.h"

#include "Poco/RegularExpression.h"
#include "Poco/Hash.h"
using Poco::RegularExpression;
using Poco::Hash;

//--------------------------------------------------------------
void ofApp::setup(){
    // Add event listener for new http packets
    ofAddListener(sniffer.httpPacketEvent, this, &ofApp::newHttpPacket);

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
    if(files.size()) {
        string url = files.front();
        files.pop_front();
        ofLog() << "grabbing file";
        ofPixels pix;
        try {
            bool success = ofLoadImage(pix, ofLoadURL(url).data);
            size_t hash = Hash<string>()(url);
            string filename = ofToString(hash)+".jpg";
            if(!success) {
                pix.allocate(1, 1, OF_IMAGE_COLOR);
            }
            ofLog() << "saving to " << filename;
            ofSaveImage(pix, filename);
            if(pix.getWidth() > 10 && pix.getHeight() > 10) {
                image.setFromPixels(pix);
                image.update();
            } else {
                ofLog() << "too small";
            }
        } catch (...) {
            ofLog() << "error";
        }
    }
}

//--------------------------------------------------------------
void ofApp::draw(){
    ofBackground(0);
    ofTranslate(ofGetWidth() / 2, ofGetHeight() / 2);
    if(image.getTexture().isAllocated()) {
        image.setAnchorPercent(.5, .5);
        float s = ofGetHeight() / image.getHeight();
        ofScale(s, s);
        image.draw(0, 0);
    }
}

//--------------------------------------------------------------
void ofApp::newHttpPacket(ofxSnifferHttpPacket &packet){
    if(packet.srcIp == "172.29.5.185") {
        ofLog() << "skipping self";
        return;
    }
    string url = "http://" + packet.host + packet.request;
    cout << ".";
    
    if(RegularExpression(".*vidible.*").match(url)) {
        ofLog() << "ignoring ad";
        return;
    }
    
    RegularExpression regex(".*\\.(png|gif|jpe?g).*");
    if(regex.match(url)) {
        ofLog() << "match: " << url;
        size_t hash = Hash<string>()(url);
        string filename = ofToString(hash)+".jpg";
        if(ofFile(filename).exists()) {
            ofLog() << "file exists";
            return;
        }
        files.push_back(url);
    }
}