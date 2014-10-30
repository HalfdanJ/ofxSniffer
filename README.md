## ofxLibtins
Wrapper for the [libtins library](http://libtins.github.io). Libtins can be used to sniff network packages, or to generate network pacakages yourself. See the [tutorial section](http://libtins.github.io/tutorial/) of libtins to see how more advanced uses

### Build libraries
The static libraries are build with [apothecary](https://github.com/openframeworks/apothecary). 
After you have cloned the addon to your addons folder, run 
```
cd scripts/apothecary
./apothecary update ofxLibtins
```
This will build libtins and libpcap. Currently only tested on mac os, but should work under linux and windows (with some modifications to the formula). 


