#include <iostream>
#include <getopt.h>
#include <libpq-fe.h>
#include "netflow.h"

void usage () {

    printf("nfproc -r nfcapd_file_path -C \"host=<address> dbname=<database_name> user=<user_id> password=<password>\"\n");
    exit(1);
}

int main(int argc, char **argv) {

    int c;
    char *pg_conn_string = nullptr;
    char *rfile = nullptr;
    while ((c = getopt(argc, argv, "h:r:C:")) != EOF) {

        switch (c) {

            case 'C':
                pg_conn_string = optarg;
                break;
            case 'r':
                rfile = optarg;
                break;
            case 'h':
                usage();
        }
    }
    if (pg_conn_string==nullptr || rfile== nullptr)
        usage();

    PGconn *pgConn = PQconnectdb(pg_conn_string);
    if (PQstatus(pgConn) != CONNECTION_OK) {

        LogError((char*)"Error connecting to database\n");
        exit(255);
    }
    NetStat nf(pgConn);
    nf.CopyNetFlow(rfile);
    PQfinish(pgConn);

    exit(0);
}