#include <iostream>
#include <getopt.h>
#include <libpq-fe.h>
#include "netflow.h"
#include "IniReader.h"
FILE *logStream;

void usage () {

//    printf("nfproc -r nfcapd_file_path -C \"host=<address> dbname=<database_name> user=<user_id> password=<password>\"\n");
    printf("nf2postgres -r nfcapd_file_path -c config_file_path\n");
    exit(1);
}

int main(int argc, char **argv) {

    int c;
    std::string pg_conn_string;
    char *rfile = nullptr,
            *configfile = nullptr;

    while ((c = getopt(argc, argv, "h:r:c:")) != EOF) {

        switch (c) {

//            case 'C':
//                pg_conn_string = optarg;
//                break;
            case 'r':
                rfile = optarg;
                break;
            case 'c':
                configfile = optarg;
                break;
            case 'h':
                usage();
                break;
            default:
                printf ("Invalid optionn: '%c\n", c);
                usage();
        }
    }
    if (configfile=="" || rfile== nullptr)
        usage();

    INIReader iniReader(configfile);
    if (iniReader.ParseError() < 0) {

        LogError((char*)"Can't load '%s'\n",configfile);
        exit(1);
    }
    std::string host = iniReader.Get("db","host","127.0.0.1");
    std::string dbname = iniReader.Get("db","dbname","");
    std::string user = iniReader.Get("db","user","");
    std::string password = iniReader.Get("db","password","");
    std::string logPath = iniReader.Get("log","path","");
    logStream = freopen (logPath.c_str(), "a", stderr);
    if (logStream==NULL) {

        LogError((char*)"Unable to open log path \"%s\"", logPath.c_str());
        exit(1);
    }
    pg_conn_string = "host="+host+" dbname="+dbname+" user="+user+" password="+password;
    PGconn *pgConn = PQconnectdb(pg_conn_string.c_str());
    if (PQstatus(pgConn) != CONNECTION_OK) {

        LogError((char*)"Error connecting to database\n");
//        freopen("CON", "w", stderr);
        exit(255);
    }
    NetStat nf(pgConn);
    if (!nf.error) {

        LogInfo((char*)"Processing \"%s\" file...", rfile);
        nf.CopyNetFlow(rfile);
        LogInfo((char*)"%u data records processed", nf.RecordsProcessed());
    }

    PQfinish(pgConn);
    //fclose (logStream);
    //freopen("CON", "w", stderr);

    exit(0);
}