#pragma once
#include <map>
#include <vector>
#include <iostream>
#include <memory>
#include <libpq-fe.h>
#include <arpa/inet.h>
extern "C" {

#include "nffile.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "nf_common.h"
#include "exporter.h"
#include "nfx.h"
#include "util.h"
#include "rbtree.h"
#include "nftree.h"
}

typedef enum {

    FLOW_INET,
    FLOW_LOCAL

} NetFlowType;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class AddressRec {

public:
//    int id;
//    struct in_addr addr;
    std::string host_ip;
    unsigned int host_mask;
    NetFlowType type;
    bool ignored;
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class AddressBook {

    std::vector<AddressRec> addr_rec;
public:
    bool error= false;

    AddressBook(PGconn *conn) {

//        if (!createTable (conn))
//            return ;

        std::string sql = "select ip_addr::cidr, type, ignored from traf_settings";
        PGresult *res = PQexec(conn, sql.c_str());
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {

            error = true;
            LogError((char*)"Error retrieving address book records: %s\n", PQresultErrorMessage(res));
            return;
        }
        AddressRec rec;
        for (int i=0; i<PQntuples(res); i++) {

            std::string cidr = PQgetvalue(res, i, 0);
            rec.type = (NetFlowType)atoi(PQgetvalue(res, i, 1));
            rec.ignored = ('t' == *PQgetvalue(res, i, 2));

            std::size_t pos = cidr.find('/');
            if (pos>0) {

                rec.host_ip = cidr.substr(0, pos);
                rec.host_mask = stoi(cidr.substr(pos+1));
            }
            else {

                rec.host_ip = cidr;
                rec.host_mask = 0;
            }
//            long long_address = inet_addr (inaddr.c_str()) ;
//            rec.addr.s_addr = long_address;
            addr_rec.push_back(rec);
        }
    };
    bool createTable (PGconn *conn) {

        PGresult *res = PQexec(conn, "CREATE TABLE IF NOT EXISTS traf_settings(ip_addr inet,type integer,ignored boolean);ALTER TABLE traf_settings OWNER TO postgres;");
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {

            LogError((char*)"Error creating data table traf_settings: %s\n", PQresultErrorMessage(res));
            return false;
        }
    };
    AddressRec *get(std::string inet) {

        uint32_t ip_addr =  inet_addr(inet.c_str());
        for (auto &item : addr_rec) {

            uint32_t range = inet_addr(item.host_ip.c_str());
            unsigned mask = (1 << item.host_mask) -1;
            if ((ip_addr & mask) == (range & mask))
                return &item;
        }
        return nullptr;
    };
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class NetFlow {

public:
    time_t timestamp;
    std::string router_ip;
    std::string source_addr;
    unsigned long in_bytes,
            out_bytes;
    NetFlowType type;

};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class NetStat : public AddressBook {

    PGconn * pgConn=NULL;
    extension_map_list_t *extension_map_list;
    master_record_t		*master_record;
    stat_record_t 		stat_record;
    std::map<std::string, NetFlow> net_flow_map;
    time_t tm_min, tm_max;
    unsigned reccount;

public:
    NetStat (PGconn *conn) : AddressBook(conn) { this->pgConn=conn; reccount=0; };
    unsigned RecordsProcessed() { return reccount;};
    bool tableExists(std::string relname);
    bool createTable(std::string relname);
    bool CopyNetFlow(char *filename);
    bool ReadNetFlow(char *rfile);
    bool SaveNetFlow (std::string csvfilepath);
    bool CopyNetFlow (time_t timestamp);
    //bool ProcessNetFlow();
    bool CopyNetFlow (char *rel_name, char *filename);
    unsigned ProcessDataBlock (nffile_t *nffile_r);
    void addNetPeer (std::string source_addr, time_t datetime, NetFlowType type, unsigned long in_bytes, unsigned long out_bytes);
    std::string rel_name(time_t);
    bool sameMonth(time_t time1, time_t time2);
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static inline void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, exporter_info_record_t *exporter_info, master_record_t *output_record );
static inline void UpdateStat(stat_record_t	*stat_record, master_record_t *master_record);
static inline void CopyV6IP(uint32_t *dst, uint32_t *src);
extern generic_exporter_t **exporter_list;
