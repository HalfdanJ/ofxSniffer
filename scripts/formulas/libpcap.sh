#! /bin/bash
#
# Libpcap
#

# define the version
VER=1.6.2

# tools for git use
GIT_URL=
#GIT_TAG="v$VER"
GIT_TAG=
USE_GIT=1

FORMULA_TYPES=( "osx" "linux")



# download the source code and unpack it into LIB_NAME
function download() {
    curl -LO http://www.tcpdump.org/release/libpcap-$VER.tar.gz
	tar -xf libpcap-$VER.tar.gz
	mv libpcap-$VER libpcap
	rm libpcap-$VER.tar.gz
}

# prepare the build environment, executed inside the lib src dir
function prepare() {
    : # noop
}

# executed inside the lib src dir
function build() {
	./configure
	make



}
# executed inside the lib src dir, first arg $1 is the dest libs dir root
function copy() {
 	# prepare libs directory if needed
 	mkdir -p $1/lib/$TYPE

 	if [ "$TYPE" == "vs" ] ; then
 		echo "VS not implemented"
 	else
 		# Standard *nix style copy.
 		# copy lib
 		cp -Rv libpcap.a $1/lib/$TYPE/
 	fi

}

# executed inside the lib src dir
function clean() {
    if [ "$TYPE" == "vs" ] ; then
		rm -f *.lib
	else
		make clean;
	fi
}
