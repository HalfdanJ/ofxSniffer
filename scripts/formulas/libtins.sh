#! /bin/bash
#
# Libtins network packet library
# cross platform packet sniffing
# https://github.com/halfdanj/ofxLibtins
#
# uses CMake

# define the version
VER=3.1

# tools for git use
GIT_URL="https://github.com/mfontanini/libtins"
#GIT_TAG="v$VER"
GIT_TAG=
USE_GIT=1

FORMULA_TYPES=( "osx" "linux")


# download the source code and unpack it into LIB_NAME
function download() {
    : # noop, done with git
}

# prepare the build environment, executed inside the lib src dir
function prepare() {
    : # noop
}

# executed inside the lib src dir
function build() {
	rm -f CMakeCache.txt
    rm -rf build
    rm -rf build_output

    if [ "$TYPE" == "vs" ] ; then
        echo "VS not implemented"
    else
    	mkdir build 
    	mkdir build_output 
    	cd build
        # *nix build system

		# 64 bit
		cmake ../ -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_BUILD_SHARED=0
		make
		mv lib/libtins.a ../build_output/libtins-x86_64.a
		make clean

		cd ..
		rm -rf build
		rm -f CMakeCache.txt
		mkdir build 
    	cd build

		# 32 bit
		cmake ../ -DLIBTINS_ENABLE_CXX11=0 -DLIBTINS_BUILD_SHARED=0 "-DCMAKE_OSX_ARCHITECTURES=i386" -DCMAKE_CXX_FLAGS="-std=gnu++98 -stdlib=libstdc++"
		make
		mv lib/libtins.a ../build_output/libtins-i386.a
		make clean

		# link into universal lib
		lipo -c ../build_output/libtins-i386.a ../build_output/libtins-x86_64.a -o ../build_output/libtins.a



	fi

}
# executed inside the lib src dir, first arg $1 is the dest libs dir root
function copy() {
    echo "Copying"

    # prepare headers directory if needed
	mkdir -p $1/include/libtins

	# prepare libs directory if needed
	mkdir -p $1/lib/$TYPE

	if [ "$TYPE" == "vs" ] ; then
		echo "VS not implemented"
	else
		# Standard *nix style copy.
		# copy headers
		cp -Rv include/tins/* $1/include/
		# copy lib
		cp -Rv build_output/libtins.a $1/lib/$TYPE/
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
