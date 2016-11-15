#include <iostream>
#include <getopt.h>
#include <libpq-fe.h>
#include <cstring>
#include "netflow.h"
#include "IniReader.h"
FILE *logStream;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void usage () {

//    printf("nfproc -r nfcapd_file_path -C \"host=<address> dbname=<database_name> user=<user_id> password=<password>\"\n");
    printf("nf2postgres -c config_file_path -initdb -r nfcapd_file_path -f\n");
    exit(1);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void PrintCreateTable (std::string parentname, bool insert) {

    if (!insert) {

        std::cout << "CREATE TABLE "+parentname+"\n"
                "(\n"
                "  datetime timestamp without time zone,\n"
                "  router_ip inet,\n"
                "  ip_addr inet,\n"
                "  in_bytes bigint,\n"
                "  out_bytes bigint,\n"
                "  type integer\n"
                ");\n"
                "ALTER TABLE "+parentname+" OWNER TO postgres;\n";
        return;
    }
    std::cout << "CREATE TABLE "+parentname+"\n"
            "(\n"
            "  datetime timestamp without time zone,\n"
            "  router_ip inet,\n"
            "  ip_addr inet,\n"
            "  in_bytes bigint,\n"
            "  out_bytes bigint,\n"
            "  type integer\n"
            ");\n"
            "ALTER TABLE "+parentname+" OWNER TO postgres;\n"
            "CREATE OR REPLACE FUNCTION "+parentname+"_partitioning() RETURNS trigger AS\n"
              "$BODY$\n"
              "declare\n"
              "        relname varchar;\n"
              "        schema varchar;\n"
              "        rel_exists text;\n"
              "        suffix varchar;\n"
              "        this_mon timestamp;\n"
              "        next_mon timestamp;\n"
              "        rec_exists boolean;\n"
              "begin\n"
              "        suffix := to_char(new.datetime, 'YYYYMM');\n"
              "        schema := 'public';\n"
              "        relname := '"+parentname+"_1h_' || suffix;\n"
              "        EXECUTE 'SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_schema = ' || quote_literal(schema) || ' AND table_name = ' || quote_literal(relname) || ')' INTO rel_exists;\n"
              "        IF rel_exists = 'f'\n"
              "        THEN\n"
              "                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' );' INTO this_mon;\n"
              "                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' + INTERVAL ''1 MON'');' INTO next_mon;\n"
              "                EXECUTE 'CREATE TABLE ' || schema || '.' || relname || \n"
              "                        ' (CONSTRAINT ' || relname || '_datetime_check CHECK (' || \n"
              "                        'datetime >= ' || quote_literal(this_mon) || '::timestamp without time zone AND ' || \n"
              "                        'datetime < ' || quote_literal(next_mon) || '::timestamp without time zone)' || \n"
              "                        ') INHERITS (public."+parentname+") WITH (OIDS=FALSE)';\n"
              "                EXECUTE 'CREATE UNIQUE INDEX ' || relname || '_idx ON ' || schema || '.' || relname || ' USING btree (datetime, ip_addr, type)';\n"
              "                EXECUTE 'ALTER TABLE ' || relname || ' OWNER TO postgres';\n"
              "                EXECUTE 'GRANT ALL ON TABLE ' || relname || ' TO postgres';\n"
              "        END IF;\n"
              "\n"
              "        EXECUTE 'SELECT EXISTS (SELECT * FROM ' || relname || ' WHERE datetime=' || quote_literal(new.datetime) || ' AND ip_addr=' || quote_literal(new.ip_addr) || ' AND type=' || new.type || ')' INTO rec_exists;\n"
              "        IF NOT rec_exists\n"
              "        THEN\n"
              "\n"
              "                EXECUTE format('insert into ' || relname || '(datetime,router_ip,ip_addr,in_bytes,out_bytes,type) VALUES($1,$2,$3,$4,$5,$6)')\n"
              "                        USING new.datetime,new.router_ip,new.ip_addr,new.in_bytes,new.out_bytes,new.type;\n"
              "        ELSE\n"
              "                EXECUTE format('update ' || relname || ' set in_bytes=in_bytes+$1, out_bytes=out_bytes+$2 where datetime=$3 and ip_addr=$4 and type=$5') USING new.in_bytes,new.out_bytes, new.datetime,new.ip_addr,new.type;\n"
              "        END IF;\n"
              "\n"
              "        relname := '"+parentname+"_1d_' || suffix;\n"
              "        EXECUTE 'SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_schema = ' || quote_literal(schema) || ' AND table_name = ' || quote_literal(relname) || ')' INTO rel_exists;\n"
              "        IF rel_exists = 'f'\n"
              "        THEN\n"
              "                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' );' INTO this_mon;\n"
              "                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' + INTERVAL ''1 MON'');' INTO next_mon;\n"
              "\n"
              "                EXECUTE 'CREATE TABLE ' || schema || '.' || relname || \n"
              "                        ' (CONSTRAINT ' || relname || '_datetime_check CHECK (' || \n"
              "                        'datetime >= ' || quote_literal(this_mon) || '::timestamp without time zone AND ' || \n"
              "                        'datetime < ' || quote_literal(next_mon) || '::timestamp without time zone)' || \n"
              "                        ') INHERITS (public."+parentname+") WITH (OIDS=FALSE)';\n"
              "\n"
              "                EXECUTE 'CREATE UNIQUE INDEX ' || relname || '_idx ON ' || schema || '.' || relname || ' USING btree (datetime, ip_addr, type)';\n"
              "                EXECUTE 'ALTER TABLE ' || relname || ' OWNER TO postgres';\n"
              "                EXECUTE 'GRANT ALL ON TABLE ' || relname || ' TO postgres';\n"
              "        END IF;\n"
              "\n"
              "        return null;\n"
              "end;\n"
              "$BODY$\n"
              "  LANGUAGE plpgsql VOLATILE\n"
              "  COST 100;\n"
              "ALTER FUNCTION "+parentname+"_partitioning() OWNER TO postgres;\n"
            "CREATE TRIGGER partitioning\n"
            "  BEFORE INSERT\n"
            "  ON "+parentname+"\n"
            "  FOR EACH ROW\n"
            "  EXECUTE PROCEDURE "+parentname+"_partitioning();\n";
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv) {

    int c;
    std::string pg_conn_string;
    char *rfile = nullptr,
            *configfile = nullptr;
    std::string algorithm;
    bool force = false, initdb = false;

    while ((c = getopt(argc, argv, "h:i:r:c:a:f::")) != EOF) {

        switch (c) {

//            case 'C':
//                pg_conn_string = optarg;
//                break;
            case 'i':
                if (strcmp(optarg, "nitdb"))
                    usage();

                initdb = true;
                break;
            case 'r':
                rfile = optarg;
                break;
            case 'c':
                configfile = optarg;
                break;
            case 'f':
                force = true;
                break;
            case 'a':
                if (strcmp (optarg, "copy")==0) {

                    algorithm = optarg;
                    break;
                }
                if (strcmp (optarg, "insert")==0) {

                    algorithm = optarg;
                    break;
                }
            case 'h':
                usage();
                break;
            default:
                printf ("Invalid optionn: '%c\n", c);
                usage();
        }
    }
    if (configfile=="")
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
    std::string parentname = iniReader.Get("db","parent","traf_flow");
    if (algorithm.size()==0)
        algorithm = iniReader.Get("db","algorithm","insert");

    if (initdb) {

        PrintCreateTable (parentname, algorithm=="insert");
        exit(0);
    }
    if (rfile== nullptr)
        usage();

//    std::string src = iniReader.Get("debug","src","");
//    std::string dst = iniReader.Get("debug","dst","");
    std::string logPath = iniReader.Get("log","path","");
    logStream = logPath.size()>0? freopen (logPath.c_str(), "a", stderr):stdout;
    if (logStream==NULL) {

        LogError((char*)"Unable to open log path \"%s\"", logPath.c_str());
        exit(1);
    }
    pg_conn_string = "host="+host+" dbname="+dbname+" user="+user+" password="+password;
    PGconn *pgConn = PQconnectdb(pg_conn_string.c_str());
    if (PQstatus(pgConn) != CONNECTION_OK) {

        LogError((char*)"Error connecting to database\n");
        exit(255);
    }
    NetStat nf(pgConn);
    if (!nf.error) {

        if (!nf.isProcessed(rfile,parentname) || force) {

            LogInfo((char*)"Processing \"%s\" file...", rfile);
            nf.StoreNetFlow(parentname, rfile, (algorithm=="insert"));
            nf.saveProcessed(rfile, parentname);
            LogInfo((char*)"%u data records processed, %u records skipped, %u records marked as ignored", nf.RecordsProcessed(), nf.RecordsSkipped(), nf.RecordsIgnored());
        }
        else
            LogInfo((char*)"\"%s\" file is already done", rfile);
    }
    PQfinish(pgConn);
    exit(0);
}