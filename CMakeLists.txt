cmake_minimum_required(VERSION 3.6)
project(nfproc)

include_directories(/usr/pgsql-9.4/include) # libs/jsoncpp-master/include libs/boost)
link_directories(/usr/pgsql-9.4/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        ./src/main.cpp
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
        src/netflow.cpp
        src/IniReader.cpp
        src/IniReader.h
        src/ini.c
        src/ini.h)
add_executable(nf2postgres ${SOURCE_FILES})
target_link_libraries(nf2postgres pq)