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

    FLOW_LOCAL,
    FLOW_INET

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
    bool ipv6family;
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class AddressBook {

    std::vector<AddressRec> addr_rec;
public:
    bool error= false;

    AddressBook(PGconn *conn, std::string schema) {

//        if (!createTable (conn))
//            return ;

        std::string sql = "select ip_addr::cidr, type, ignored, family(ip_addr) from "+schema+".traf_settings";
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
            rec.ipv6family = ('6' == *PQgetvalue(res, i, 3));

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
    bool validIpv4Address(const std::string &ipAddress) {

        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr));
        return result != 0;
    }
    bool subnetContains (unsigned char ipv6_subnet[], unsigned char ipv6_addr[], int prefixLength) {

        int i = 0;
        int bits = prefixLength;
        for (; bits >= 8; bits -= 8) {

            if (ipv6_subnet[i] != ipv6_addr[i])
                return false;

            ++i;
        }
        if (bits > 0)
        {
            int mask = (unsigned char)~(255 >> bits);
            if ((ipv6_subnet[i] & mask) != (ipv6_addr[i] & mask))
                return false;
        }
        return true;
    }
    AddressRec *get(std::string inet) {

        if (validIpv4Address(inet)) {

            // ipv4 :
            uint32_t ip_addr =  inet_addr(inet.c_str());
            ip_addr = ntohl(ip_addr);
            AddressRec *arec = nullptr;
            for (auto &item : addr_rec) {

                if (item.ipv6family)
                    continue;

                uint32_t range = inet_addr(item.host_ip.c_str());
                range = ntohl(range);
//                uint32_t mask = (1 << item.host_mask) -1;
//                if ((ip_addr & mask) == (range & mask))
//                    return &item;

                uint32_t mask = 0;
                int i;
                for( i = 1; i <= item.host_mask; i++ )
                    mask = (mask << 1) | 1;

                for(; i <= 32; i++ )
                    mask = mask << 1;

                if ((ip_addr & mask) == (range & mask)) {

                    if (arec==nullptr || arec->host_mask<item.host_mask)
                        arec = &item;
                    //return &item;
                }
            }
            return arec;
        }
        // ipv6 :
        unsigned char ipv6_addr[sizeof(struct in6_addr)];
        if (inet_pton(AF_INET6, inet.c_str(), ipv6_addr)<=0)
            return nullptr;

        for (auto &item : addr_rec) {

            if (!item.ipv6family)
                continue;

            unsigned char ipv6_subnet[sizeof(struct in6_addr)];
            if (inet_pton(AF_INET6, item.host_ip.c_str(), ipv6_subnet)<=0)
                continue;

            if (subnetContains (ipv6_subnet, ipv6_addr, item.host_mask))
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
    unsigned long long in_bytes,
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
    unsigned reccount,
            //localrec,
            ignoredrec,
            skipped;
    std::string src;
    std::string dst;
    FILE *processLog;

public:
    NetStat (PGconn *conn, std::string schema, FILE *log) : AddressBook(conn, schema) { this->pgConn=conn; this->processLog=log; reccount=ignoredrec=skipped=0; };
    unsigned RecordsProcessed() { return reccount;};
    //unsigned RecordsLocal() { return localrec; };
    unsigned RecordsIgnored() { return  ignoredrec; };
    unsigned RecordsSkipped() { return skipped; };
    bool tableExists(std::string schema, std::string relname);
    bool createPartition(std::string schema, std::string relname, std::string parentname, bool unique_index);
    bool createTable(std::string parentname, std::string schema, std::string suffix, time_t timestamp, std::string &relname);
    bool checkParent(std::string schema, std::string parentname, bool insert);
    bool createParent(std::string schema, std::string parentname);
    bool StoreNetFlow (std::string parentname, std::string schema, char *filename, bool insert);
    bool CopyNetFlow(std::string parentname, char *filename, std::string src, std::string dst);
    bool WriteNetFlow (std::string schema, std::string rel_name, time_t timestamp);
    bool CopyNetFlow (char *rel_name, char *filename);
    bool ReadNetFlow(char *rfile);
    bool ReadNetFlow(std::string parentname);
    bool SaveNetFlow (std::string csvfilepath);
    //bool ProcessNetFlow();
    bool InsertNetFlow (std::string relname,  std::string schema);
    bool InsertNetFlow2 (std::string relname, std::string schema);
    unsigned ProcessDataBlock (nffile_t *nffile_r);
    void addNetPeer (std::string router_ip, std::string source_addr, time_t datetime, NetFlowType type, unsigned long in_bytes, unsigned long out_bytes);
    std::string relName(std::string name, std::string suffix, time_t);
    bool sameMonth(time_t time1, time_t time2);
    std::string GetRouterIp ();
    std::string GetSourceAddr ();
    std::string GetDestAddr ();
    bool isProcessed(const std::string path, std::string schema, std::string parent);
    bool saveProcessed(const std::string path, std::string schema, std::string parent);
    time_t str2time (std::string datetime);
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static inline void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, exporter_info_record_t *exporter_info, master_record_t *output_record );
static inline void UpdateStat(stat_record_t	*stat_record, master_record_t *master_record);
static inline void CopyV6IP(uint32_t *dst, uint32_t *src);
extern generic_exporter_t **exporter_list;
