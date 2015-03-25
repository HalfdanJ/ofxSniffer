## ofxLibtins
Wrapper for the [libtins library](http://libtins.github.io). Libtins can be used to sniff network packages, or to generate network pacakages yourself. See the [tutorial section](http://libtins.github.io/tutorial/) of libtins to see how more advanced uses

The addon currently implements a simple packet sniffer `ofxLibtinsSimpleSniffer` running in a background thread, and a http interpreter. This makes it super easy to sniff http traffic. But the addon can also be used just as a way to include the libtins library that has many many other uses. 

### Common problems

If you get an error on OS X like `(cannot open BPF device) /dev/bpf0: Permission denied` then go into Terminal and run `sudo chmod 644 /dev/bpf*`.

### Build libraries
***Note:*** *If you dont want to build the libraries yourself, then download the [release](https://github.com/HalfdanJ/ofxLibtins/releases) instead*

The static libraries are build with [apothecary](https://github.com/openframeworks/apothecary). 
After you have cloned the addon to your addons folder, run 
```
cd scripts/apothecary
./apothecary update ofxLibtins
```
This will build libtins and libpcap. Currently only tested on mac os, but should work under linux and windows (with some modifications to the formula).