cmake_minimum_required(VERSION 2.8)
project(nfproc)

include_directories(/usr/pgsql-9.4/include ./src ) # libs/jsoncpp-master/include libs/boost)
link_directories(/usr/pgsql-9.4/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        ./src/nfdump.c
        ./src/nfstat.c
        ./src/nfexport.c
        ./src/util.c
        ./src/flist.c
        ./src/nffile.c
        ./src/nfxstat.c
        ./src/nflowcache.c
        ./src/exporter.c
        ./src/nfx.c
        ./src/ipconv.c
        ./src/nf_common.c
        ./src/scanner.c
        ./src/nftree.c
        ./src/nfprof.c
        ./src/grammar.c
        ./src/minilzo.c
        ./src/ini.c
        ./src/ini.h

        ./cpp/main.cpp
        ./cpp/netflow.cpp
        ./cpp/IniReader.cpp
        ./cpp/IniReader.h
        )
add_executable(nf2postgres ${SOURCE_FILES})
target_link_libraries(nf2postgres pq bz2)