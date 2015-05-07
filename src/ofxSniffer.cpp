#include "ofxSniffer.h"

#include "ofUtils.h"

ofxSniff::ofxSniff(){
    ofAddListener(ofEvents().update, this, &ofxSniff::update);
}

ofxSniff::~ofxSniff(){
    sniffer->stop_sniff();
    lock();
    delete sniffer;
    unlock();
    httpPackets.close();
    beaconFrames.close();
    probeRequestFrames.close();
}

void ofxSniff::startSniffing(string _interface, bool monitorMode){
    interface = _interface;

    // Sniffer configuration
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_rfmon(monitorMode);
    
    // Create the sniffer instance
    try {
        sniffer = new Sniffer(interface, config);
    } catch(...) {
        ofLogError() << "Couldn't create Sniffer, you might need to run `sudo chmod o+r /dev/bpf*`";
        return;
    }
    
    startThread(true);
}

void ofxSniff::update(ofEventArgs & args){
    ofxSnifferHttpPacket packet;
    while(httpPackets.tryReceive(packet)){
        ofNotifyEvent(httpPacketEvent, packet, this);
    }
    
    ofxSnifferBeaconFrame beacon;
    while(beaconFrames.tryReceive(beacon)){
        ofNotifyEvent(beaconFrameEvent, beacon, this);
    }
    
    ofxSnifferProbeRequestFrame probeRequest;
    while(probeRequestFrames.tryReceive(probeRequest)){
        ofNotifyEvent(probeRequestFrameEvent, probeRequest, this);
    }
}

string ofxSniff::toString(const Packet& packet) {
    vector<string> types;
    const PDU *cur = packet.pdu();
    while(cur) {
        types.push_back(Utils::to_string(cur->pdu_type()));
        cur = cur->inner_pdu();
    }
    types.push_back(ofToString((int) packet.pdu()->size()) + " bytes");
    return ofJoinString(types, " ");
}

bool print(PDU &pdu) {
    
    cout << "PDU: " << (int) pdu.size() << " bytes" << endl;
    
    // RADIOTAP
    try {
        const RadioTap &radioTap = pdu.rfind_pdu<RadioTap>();
        cout << "RadioTap: " <<
        "dbms[" << (int) (radioTap.dbm_signal()) << "] " <<
        "dbmn[" << (int) (radioTap.dbm_noise()) << "] " <<
        "sq[" << (int) (radioTap.signal_quality()) << "] " <<
        "dbs[" << (int) (radioTap.db_signal()) << "] " <<
        "rate[" << (int) (radioTap.rate()) << "] " <<
        "freq[" << (int) (radioTap.channel_freq()) << "] " <<
        "ch[" << Utils::mhz_to_channel(radioTap.channel_freq()) << "]" << endl;
    } catch (...) {}
    
    // Dot11
    try {
        const Dot11 &data = pdu.rfind_pdu<Dot11>();
        cout << "Dot11" << endl;
        cout << "\taddr1 " << data.addr1() << endl;
        cout << "\tfrom " << ofToHex(data.from_ds()) << endl;
        cout << "\tto " << ofToHex(data.to_ds()) << endl;
    } catch(...) {}
    
    // IP
    try {
        const IP &data = pdu.rfind_pdu<IP>();
        cout << "IP" << endl;
        cout << "\ttot_len " << (int) data.tot_len() << endl;
        cout << "\ttos " << (int) data.tos() << endl;
        cout << "\tid " << (int) data.id() << endl;
        cout << "\tttl " << (int) data.ttl() << endl;
        cout << "\tfrag_off " << (int) data.frag_off() << endl;
        cout << "\thead_len " << (int) data.head_len() << endl;
        cout << "\tsrc_addr " << data.src_addr() << endl;
        cout << "\tdst_addr " << data.dst_addr() << endl;
    } catch (...) {}
    
    // IPv6
    try {
        const IPv6 &data = pdu.rfind_pdu<IPv6>();
        cout << "IPv6" << endl;
        cout << "\tpayload_length " << (int) data.payload_length() << endl;
        cout << "\tsrc_addr " << data.src_addr() << endl;
        cout << "\tdst_addr " << data.dst_addr() << endl;
    } catch (...) {}
    
    // TCP
    try {
        const TCP &data = pdu.rfind_pdu<TCP>();
        cout << "TCP" << endl;
        cout << "\tdport " << (int) data.dport() << endl;
        cout << "\tsport " << (int) data.sport() << endl;
        cout << "\twindow " << (int) data.window() << endl;
        cout << "\tseq " << data.seq() << endl;
    } catch (...) {}
    
    // UDP
    try {
        const UDP &data = pdu.rfind_pdu<UDP>();
        cout << "UDP" << endl;
        cout << "\tdport " << (int) data.dport() << endl;
        cout << "\tsport " << (int) data.sport() << endl;
        cout << "\tlength " << (int) data.length() << endl;
    } catch (...) {}

    // RAW
    try {
        const RawPDU &data = pdu.rfind_pdu<RawPDU>();
        cout << "Raw" << endl;
        cout << "\theader_size " << (int) data.header_size() << endl;
        cout << "\tpayload_size " << (int) data.payload_size() << endl;
    } catch (...) {}
    
    // Dot11ControlTA
    try {
        const Dot11ControlTA &data = pdu.rfind_pdu<Dot11ControlTA>();
        cout << "Dot11ControlTA" << endl;
        cout << "\ttarget_addr " << data.target_addr() << endl;
    } catch(...) {}
    
    // Dot11Management
    try {
        const Dot11ManagementFrame &data = pdu.rfind_pdu<Dot11ManagementFrame>();
        cout << "Management" << endl;
        cout << "\taddr2 " << data.addr2() << endl;
        cout << "\taddr3 " << data.addr3() << endl;
        cout << "\tsrc  " << get_src_addr(data) << endl;
        cout << "\tdst  " << get_dst_addr(data) << endl;
        cout << "\tssid " << data.ssid() << endl;
    } catch (...) {}
    
    // Dot11Beacon
    try {
        const Dot11Beacon &data = pdu.rfind_pdu<Dot11Beacon>();
        cout << "Beacon" << endl;
    } catch (...) {}
    
    // Dot11ProbeRequest
    try {
        const Dot11ProbeRequest &data = pdu.rfind_pdu<Dot11ProbeRequest>();
        cout << "Dot11ProbeRequest" << endl;
    } catch (...) {}
    
    // Dot11ProbeResponse
    try {
        const Dot11ProbeResponse &data = pdu.rfind_pdu<Dot11ProbeResponse>();
        cout << "Dot11ProbeResponse" << endl;
    } catch (...) {}
    
    // Dot11Data
    try {
        const Dot11Data &data = pdu.rfind_pdu<Dot11Data>();
        cout << "Data" << endl;
        cout << "\tsrc  " << get_src_addr(data) << endl;
        cout << "\tdst  " << get_dst_addr(data) << endl;
        cout << "\tfrag_num " << (int) data.frag_num() << endl;
        cout << "\tseq_num " << (int) data.seq_num() << endl;
        cout << "\tbssid_addr " << data.bssid_addr() << endl;
    } catch (...) {}
    
    cout << endl;
    
    return true;
}

void ofxSniff::threadedFunction() {
    while(isThreadRunning()) {
        lock();
        try {
            Packet packet = sniffer->next_packet();
            if(packet) {
                newRawPacketEvent.notifyAsync(this, packet);
                
//                cout << packet.pdu()->size() << endl;
//                cout << "packet: " << toString(packet) << endl;
//                print(*packet.pdu());
                
                ofxSnifferHttpPacket http = ofxSnifferHttpPacket(packet);
                if(http.isValid){
                    httpPackets.send(http);
                }
                
                ofxSnifferBeaconFrame beacon = ofxSnifferBeaconFrame(packet);
                if(beacon.isValid) {
                    beaconFrames.send(beacon);
                }
                
                ofxSnifferProbeRequestFrame probeRequest = ofxSnifferProbeRequestFrame(packet);
                if(probeRequest.isValid) {
                    probeRequestFrames.send(probeRequest);
                }
            }
        } catch(...) {
        }
        unlock();
    }
}
            