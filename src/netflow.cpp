#include <iostream>
#include <netinet/in.h>
#include <cstring>
#include <memory>
#include <libpq-fe.h>
#include <vector>
#include <limits>
#include <regex>

#include "netflow.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::CopyNetFlow(char *filename, std::string src, std::string dst) {

    this->src = src;
    this->dst = dst;
    if (!ReadNetFlow(filename))
        return false;

    if (net_flow_map.size()==0) {

        LogError((char*)"Net flow array is empty");
        return true;
    }
//    std::string schema ="public";
//    std::string relname;
//    if (!createTable(schema, "1h", tm_min, relname)) {
//
//        LogError((char*)"Unable to create %s", relname.c_str());
//        return false;
//    }
//    if (!CopyNetFlow (relaname, tm_min))
//        return false;
//
//    if (sameMonth(tm_min, tm_max))
//        return true;
//
//    if (!createTable(schema, "1h", tm_max, relname)) {
//
//        LogError((char*)"Unable to create %s", relname.c_str());
//        return false;
//    }
    return InsertNetFlow("traf_flow");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::isProcessed(const std::string path) {

    std::string filname = getFileName(path);
    if (filname.empty())
        return false;

    std::string check = "SELECT EXISTS(SELECT * FROM public.files_processed WHERE filename = '"+filname+"')";
    PGresult *res = PQexec(pgConn, check.c_str());
    if ((PQresultStatus(res)==PGRES_TUPLES_OK) && (PQntuples(res)>0)) {

        std::string s = PQgetvalue(res, 0, 0);
        return s=="t";
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::saveProcessed(const std::string path) {

    std::string filname = getFileName(path);
    if (filname.empty())
        return false;

    std::string sql;
    if (!isProcessed(path))
        sql="INSERT INTO public.files_processed (datetime,filename) values(now(),'"+filname+"')";
    else
        sql = "UPDATE public.files_processed SET datetime=now() WHERE filename='"+filname+"'";

    PGresult *res = PQexec(pgConn, sql.c_str());
    return  PQresultStatus(res)==PGRES_COMMAND_OK;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string NetStat::getFileName(const std::string& path) {

    char sep = '/';
    size_t i = path.rfind(sep, path.length());
    if (i != std::string::npos)
        return(path.substr(i+1, path.length() - i));

    return(path);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::createTable(std::string schema, std::string suffix, time_t timestamp, std::string &relname) {

    relname = rel_name(suffix, timestamp);
    if (!tableExists(schema, relname) && !createTable(schema, relname))
        return false;

    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::sameMonth(time_t time1, time_t time2) {

    struct tm *tm1 = localtime(&time1);
    struct tm *tm2 = localtime(&time2);
    return tm1->tm_mon==tm2->tm_mon;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string NetStat::rel_name(std::string suffix, time_t datetime) {

    struct tm *temp = localtime(&datetime);
    char relname[128];
    std::string format = "traf_flow_"+suffix+"_%4d%02d";
    snprintf (relname, sizeof(relname), format.c_str(), temp->tm_year+1900, temp->tm_mon+1);
    return std::string(relname);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::tableExists(std::string schema, std::string relname) {

    std::string check = "SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_schema = '"+schema+"' AND table_name = '"+relname+"')";
//            "SELECT to_regclass('" + relname + "')";
    PGresult *res = PQexec(pgConn, check.c_str());
    if ((PQresultStatus(res)==PGRES_TUPLES_OK) && (PQntuples(res)>0)) {

        std::string s = PQgetvalue(res, 0, 0);
        return s=="t";
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::createTable(std::string schema, std::string relname) {

    std::string sql = "SET client_min_messages = error;"
                      "CREATE TABLE IF NOT EXISTS "+schema+"."+relname+"() INHERITS ("+schema+".traf_flow);"
                      "ALTER TABLE "+relname+" OWNER TO postgres;"
                      "CREATE UNIQUE INDEX "+relname+"_idx ON "+schema+"."+relname+" USING btree (datetime, ip_addr);";
    PGresult *res = PQexec(pgConn, sql.c_str());
//            PQexec(pgConn, "CREATE TABLE IF NOT EXISTS net_flow(datetime timestamp without time zone,router_ip inet,ip_addr inet,in_bytes bigint,out_bytes bigint,type integer);"
//            "ALTER TABLE net_flow OWNER TO postgres;");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {

        LogError((char*)"Error creating data table %s: %s\n", relname.c_str(), PQresultErrorMessage(res));
        return false;
    }
    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::CopyNetFlow (char *rel_name, char *filename) {

    char sql[4096];
    snprintf(sql, sizeof(sql), "COPY %s FROM '%s' DELIMITER ',' CSV header", rel_name, filename);
    PGresult *res = PQexec(pgConn, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {

        LogError((char*)"Error inserting data record: %s\n", PQresultErrorMessage(res));
        return false;
    }
    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::InsertNetFlow (std::string relname) {

    PGresult *res = PQexec(pgConn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        LogError((char*)"BEGIN command failed: %s", PQerrorMessage(pgConn));
        PQclear(res);
        return false;
    }
    unsigned recordscopied = 0;
    for (auto it=net_flow_map.begin(); it!=net_flow_map.end(); ++it) {

        NetFlow &nf = it->second;
//        if (!sameMonth(nf.timestamp, timestamp))
//            continue;

        char datetime[64];
        struct tm *ts = localtime(&nf.timestamp);
        strftime(datetime, sizeof(datetime)-1, "%Y-%m-%d %H:%M:%S", ts);
        char sql[2048];
        snprintf(sql, sizeof(sql), "INSERT INTO %s (datetime,router_ip,ip_addr,in_bytes,out_bytes,type) VALUES('%s','%s','%s',%llu,%llu,%u)",
                 relname.c_str(), datetime, nf.router_ip.c_str(), nf.source_addr.c_str(), nf.in_bytes, nf.out_bytes,nf.type);

        res = PQexec(pgConn, sql);
        ExecStatusType stat = PQresultStatus(res);
        if (stat != PGRES_COMMAND_OK) {

            LogError((char*)"Error inserting data record: %s\n", PQresultErrorMessage(res));
            PQclear(res);
            return false;
        }
        recordscopied++;
    }
    res = PQexec(pgConn, "END");
    PQclear(res);
    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::CopyNetFlow (std::string relname, time_t timestamp) {

    std::string sql = "COPY " + relname + " FROM STDIN DELIMITER ',' CSV header";
    PGresult *res = PQexec(pgConn, sql.c_str());
    ExecStatusType stat = PQresultStatus(res);
    if (stat != PGRES_COPY_IN) {

        LogError((char*)"Error inserting data record: %s\n", PQresultErrorMessage(res));
        return false;
    }
    char csvline[1024];
    strcpy(csvline, "datetime,router_ip,ip_addr,in_bytes,out_bytes,type\n");
    int ret = PQputCopyData (pgConn, csvline, strlen(csvline));
    unsigned recordscopied = 0;
    for (auto it=net_flow_map.begin(); it!=net_flow_map.end() && ret>=0; ++it) {

        NetFlow &nf = it->second;
        if (!sameMonth(nf.timestamp, timestamp))
            continue;

        char datetime[64];
        struct tm *ts = localtime(&nf.timestamp);
        strftime(datetime, sizeof(datetime)-1, "%Y-%m-%d %H:%M:%S", ts);
        snprintf(csvline, sizeof(csvline), "%s,%s,%s,%llu,%llu,%u\n", datetime, nf.router_ip.c_str(), nf.source_addr.c_str(), nf.in_bytes, nf.out_bytes,nf.type);
        ret = PQputCopyData(pgConn, csvline, strlen(csvline));
        recordscopied++;
    }
    if (ret>=0)
        ret = PQputCopyData(pgConn,"\\.\n", 3);

    if (ret<0)
        LogError((char*)"Error copying data records: %s\n", PQerrorMessage (pgConn));
    else
        LogInfo((char*)"%u records copied to %s", recordscopied, relname.c_str());

    PQputCopyEnd(pgConn, NULL);
    stat = PQresultStatus(PQgetResult(pgConn));
    return stat==PGRES_COMMAND_OK;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::ReadNetFlow(char *rfile) {

    nffile_t *nffile_r = OpenFile(rfile, NULL);
    if (!nffile_r)
        return false;

    tm_min = std::numeric_limits<time_t>::max();
    tm_max = 0;
    try {

        extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
        if ( !InitExporterList() )
            throw false;

        while (true) {

            // get next data block from file
            int ret = ReadBlock(nffile_r);
            if (ret==NF_CORRUPT) {

                LogError((char*)"Data file '%s' is corrupt\n", rfile);
                throw false;
            }
            if (ret==NF_ERROR) {

                LogError((char*)"Read error in file '%s'\n", rfile);
                throw false;
            }
            if (ret==NF_EOF)
                throw true;

            if ( nffile_r->block_header->id == Large_BLOCK_Type ) {
                // skip
                LogError((char*)"Xstat block skipped ...\n");
                throw false;
            }
            if ( nffile_r->block_header->id != DATA_BLOCK_TYPE_2 ) {

                if ( nffile_r->block_header->id == DATA_BLOCK_TYPE_1 )
                    LogError((char*)"Can't process nfdump 1.5.x block type 1. Add --enable-compat15 to compile compatibility code. Skip block.\n");
                else
                    LogError((char*)"Can't process block type %u. Skip block.\n", nffile_r->block_header->id);

                continue;
            }
            reccount+=ProcessDataBlock (nffile_r);

        }
    }
    catch (bool ret) {

        CloseFile(nffile_r);
        FreeExtensionMaps(extension_map_list);
        return ret;
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
unsigned NetStat::ProcessDataBlock (nffile_t *nffile_r) {

    unsigned rec_count = 0;
    common_record_t *flow_record = (common_record_t *) nffile_r->buff_ptr;
    for ( int i=0; i < nffile_r->block_header->NumRecords; i++ ) {

        switch ( flow_record->type ) {

            case CommonRecordV0Type:
            case CommonRecordType:  {
                uint32_t map_id = flow_record->ext_map;
                generic_exporter_t *exp_info = exporter_list[flow_record->exporter_sysid];
                if ( map_id >= MAX_EXTENSION_MAPS ) {
                    LogError((char*)"Corrupt data file. Extension map id %u too big.\n", flow_record->ext_map);
                    exit(255);
                }
                if ( extension_map_list->slot[map_id] == NULL ) {
                    LogError((char*)"Corrupt data file. Missing extension map %u. Skip record.\n", flow_record->ext_map);
                    break;
                }

                master_record = &(extension_map_list->slot[map_id]->master_record);
                ExpandRecord_v2( flow_record, extension_map_list->slot[map_id], exp_info ? &(exp_info->info) : NULL, master_record);

                // Update statistics
                UpdateStat(&stat_record, master_record);

                // update number of flows matching a given map
                extension_map_list->slot[map_id]->ref_count++;

                // source
                std::string source_ip = GetSourceAddr();

                // destination
                std::string dest_ip = GetDestAddr ();

                if (!this->src.empty() && this->src!=source_ip)
                    break;

                if (!this->dst.empty() && this->dst!=dest_ip)
                    break;

                rec_count++;

                AddressRec *source_rec = get(source_ip);
                AddressRec *dest_rec = get(dest_ip);
                NetFlowType type = (source_rec!= nullptr) && (dest_rec!= nullptr)? NetFlowType::FLOW_LOCAL:NetFlowType::FLOW_INET;

                if (source_rec!= nullptr) {

                    if (source_rec->ignored) {

                        ignoredrec++;
                        break; // skip source marked as IGNORED
                    }
                    addNetPeer (source_ip, master_record->first, type, master_record->out_bytes, master_record->dOctets);
                }
                if (dest_rec!= nullptr) {

                    if (dest_rec->ignored) {

                        ignoredrec++;
                        break; // skip destination marked as IGNORED
                    }
                    addNetPeer (dest_ip, master_record->first, type, master_record->dOctets, master_record->out_bytes);
                }
                if (source_rec==nullptr && dest_rec==nullptr) {

                    time_t timestamp = master_record->first;
                    struct tm *ts = localtime(&timestamp);
                    char datetime[64];
                    strftime(datetime, sizeof(datetime)-1, "%Y-%m-%d %H:%M:%S", ts);
                    LogError((char*)"%s\t%s\t%s\t%lld\t%lld", datetime, source_ip.c_str(), dest_ip.c_str(),
                             (long long)master_record->dOctets, (long long)master_record->out_bytes);
                    skipped++;
                }
            } break;

            case ExtensionMapType: {
                extension_map_t *map = (extension_map_t *)flow_record;
                Insert_Extension_Map(extension_map_list, map);
            } break;

            case ExporterRecordType:
            case SamplerRecordype:
                // Silently skip exporter records
                break;

            case ExporterInfoRecordType: {
                int ret = AddExporterInfo((exporter_info_record_t *)flow_record);
                if ( ret == 0 ) {
                    LogError((char*)"Failed to add Exporter Record\n");
                }
            } break;

            case ExporterStatRecordType:
                AddExporterStat((exporter_stats_record_t *)flow_record);
                break;

            case SamplerInfoRecordype: {
                int ret = AddSamplerInfo((sampler_info_record_t *)flow_record);
                if (ret == 0 ) {
                    LogError((char*)"Failed to add Sampler Record\n");
                }
            } break;

            default: {
                LogError((char*)"Skip unknown record type %i\n", flow_record->type);
            }
        }
        // Advance pointer by number of bytes for netflow record
        flow_record = (common_record_t *)((char*)flow_record + flow_record->size);

    } // for all records

    return rec_count;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void NetStat::addNetPeer (std::string source_addr, time_t datetime, NetFlowType type, unsigned long in_bytes, unsigned long out_bytes) {

    time_t start_of_hour = datetime - (datetime % 3600);
    std::string key = source_addr+std::to_string(start_of_hour)+std::to_string(type);
    auto it = net_flow_map.find(key);
    if (it == net_flow_map.end()) {

        auto &net_flow = net_flow_map[key];
        net_flow.timestamp = start_of_hour;
        net_flow.router_ip = GetRouterIp ();
        net_flow.source_addr = source_addr;
        net_flow.out_bytes = out_bytes;
        net_flow.in_bytes = in_bytes;
        net_flow.type = type;

        if (tm_max < start_of_hour)
            tm_max = start_of_hour;

        if (tm_min > start_of_hour)
            tm_min = start_of_hour;
    }
    else {

        net_flow_map[key].out_bytes += out_bytes;
        net_flow_map[key].in_bytes += in_bytes;
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool NetStat::SaveNetFlow (std::string csvfilepath) {

    FILE *csvfile = fopen(csvfilepath.c_str(),"w+t");
    if (csvfile==NULL) {

        LogError((char*)"Unable to open temporary csv file\n");
        return false;
    }
    fprintf(csvfile, "datetime,router_ip,source_addr,in_bytes,out_bytes,type\n");
    for (auto it=net_flow_map.begin(); it!=net_flow_map.end(); ++it) {

        NetFlow &nf = it->second;
        char datetime[64];
        struct tm *ts = localtime(&nf.timestamp);
        strftime(datetime, sizeof(datetime)-1, "%Y-%m-%d %H:%M:%S", ts);
        if (fprintf(csvfile, "%s,%s,%s,%u,%u,%u\n", datetime, nf.router_ip.c_str(), nf.source_addr.c_str(), nf.in_bytes, nf.out_bytes,nf.type)<0) {

            LogError ((char*)"Error %d writing to %s: %s\n", errno, csvfilepath.c_str(), strerror (errno));
            break;
        }
    }
    fclose(csvfile);

    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string NetStat::GetRouterIp () {

    char router_ip[INET6_ADDRSTRLEN];
    get_ra (master_record, router_ip);
    std::string value = router_ip;
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), std::bind1st(std::not_equal_to<char>(), ' ')));
    return value;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string NetStat::GetSourceAddr () {

    char source_ip[INET6_ADDRSTRLEN];
    get_sa(master_record,source_ip,sizeof(source_ip));
    std::string value = source_ip;
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), std::bind1st(std::not_equal_to<char>(), ' ')));
    return value;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string NetStat::GetDestAddr () {

    char dest_ip[INET6_ADDRSTRLEN];
    get_da(master_record,dest_ip,sizeof(dest_ip));
    std::string value = dest_ip;
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), std::bind1st(std::not_equal_to<char>(), ' ')));
    return value;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static inline void UpdateStat(stat_record_t	*stat_record, master_record_t *master_record) {

    switch (master_record->prot) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            stat_record->numflows_icmp   += master_record->aggr_flows ? master_record->aggr_flows : 1;
            stat_record->numpackets_icmp += master_record->dPkts;
            stat_record->numpackets_icmp += master_record->out_pkts;
            stat_record->numbytes_icmp   += master_record->dOctets;
            stat_record->numbytes_icmp   += master_record->out_bytes;
            break;
        case IPPROTO_TCP:
            stat_record->numflows_tcp   += master_record->aggr_flows ? master_record->aggr_flows : 1;
            stat_record->numpackets_tcp += master_record->dPkts;
            stat_record->numpackets_tcp += master_record->out_pkts;
            stat_record->numbytes_tcp   += master_record->dOctets;
            stat_record->numbytes_tcp   += master_record->out_bytes;
            break;
        case IPPROTO_UDP:
            stat_record->numflows_udp   += master_record->aggr_flows ? master_record->aggr_flows : 1;
            stat_record->numpackets_udp += master_record->dPkts;
            stat_record->numpackets_udp += master_record->out_pkts;
            stat_record->numbytes_udp   += master_record->dOctets;
            stat_record->numbytes_udp   += master_record->out_bytes;
            break;
        default:
            stat_record->numflows_other   += master_record->aggr_flows ? master_record->aggr_flows : 1;
            stat_record->numpackets_other += master_record->dPkts;
            stat_record->numpackets_other += master_record->out_pkts;
            stat_record->numbytes_other   += master_record->dOctets;
            stat_record->numbytes_other   += master_record->out_bytes;
    }
    stat_record->numflows   += master_record->aggr_flows ? master_record->aggr_flows : 1;
    stat_record->numpackets	+= master_record->dPkts;
    stat_record->numpackets	+= master_record->out_pkts;
    stat_record->numbytes 	+= master_record->dOctets;
    stat_record->numbytes 	+= master_record->out_bytes;

    if ( master_record->first < stat_record->first_seen ) {
        stat_record->first_seen = master_record->first;
        stat_record->msec_first = master_record->msec_first;
    }
    if ( master_record->first == stat_record->first_seen &&
         master_record->msec_first < stat_record->msec_first )
        stat_record->msec_first = master_record->msec_first;

    if ( master_record->last > stat_record->last_seen ) {
        stat_record->last_seen = master_record->last;
        stat_record->msec_last = master_record->msec_last;
    }
    if ( master_record->last == stat_record->last_seen &&
         master_record->msec_last > stat_record->msec_last )
        stat_record->msec_last = master_record->msec_last;

} // End of UpdateStat

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Use 4 uint32_t copy cycles, as SPARC CPUs brak
static inline void CopyV6IP(uint32_t *dst, uint32_t *src) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
} // End of CopyV6IP

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Expand file record into master record for further processing
 * LP64 CPUs need special 32bit operations as it is not guarateed, that 64bit
 * values are aligned
 */
static inline void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, exporter_info_record_t *exporter_info, master_record_t *output_record ) {
    extension_map_t *extension_map = extension_info->map;
    uint32_t	i, *u;
    void		*p = (void *)input_record;
#ifdef NSEL
    // nasty bug work around - compat issues 1.6.10 - 1.6.12 onwards
		union {
			uint16_t port[2];
			uint32_t vrf;
		} compat_nel_bug;
		compat_nel_bug.vrf = 0;
		int compat_nel = 0;
#endif

    // set map ref
    output_record->map_ref = extension_map;

    if ( input_record->type == CommonRecordType ) {
        // Copy common data block
        memcpy((void *)output_record, (void *)input_record, COMMON_RECORD_DATA_SIZE);
        p = (void *)input_record->data;
    } else {
        // Compat v0 record - convert to new Common Record
        common_record_v0_t *common_record_v0 = (common_record_v0_t *)input_record;
        uint16_t flags			= common_record_v0->flags;
        uint16_t exporter_sysid = common_record_v0->exporter_sysid;
        memcpy((void *)output_record, (void *)input_record, COMMON_RECORDV0_DATA_SIZE);
        output_record->flags 		  = flags;
        output_record->exporter_sysid = exporter_sysid;
        p = (void *)common_record_v0->data;
    }

    if ( exporter_info ) {
        uint32_t sysid = exporter_info->sysid;
        output_record->exporter_sysid = sysid;
        input_record->exporter_sysid  = sysid;
        output_record->exp_ref 		  = exporter_info;
    } else {
        output_record->exp_ref 		  = NULL;
    }

    // map icmp type/code in it's own vars
    output_record->icmp = output_record->dstport;

    // Required extension 1 - IP addresses
    if ( (input_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
        // IPv6
        // keep compiler happy
        // memcpy((void *)output_record->v6.srcaddr, p, 4 * sizeof(uint64_t));
        memcpy((void *)output_record->ip_union._ip_64.addr, p, 4 * sizeof(uint64_t));
        p = (void *)((char*)p + 4 * sizeof(uint64_t));
    } else {
        // IPv4
        u = (uint32_t *)p;
        output_record->v6.srcaddr[0] = 0;
        output_record->v6.srcaddr[1] = 0;
        output_record->v4.srcaddr 	 = u[0];

        output_record->v6.dstaddr[0] = 0;
        output_record->v6.dstaddr[1] = 0;
        output_record->v4.dstaddr 	 = u[1];
        p = (void *)((char*)p + 2 * sizeof(uint32_t));
    }

    // Required extension 2 - packet counter
    if ( (input_record->flags & FLAG_PKG_64 ) != 0 ) {
        // 64bit packet counter
        value64_t	l, *v = (value64_t *)p;
        l.val.val32[0] = v->val.val32[0];
        l.val.val32[1] = v->val.val32[1];
        output_record->dPkts = l.val.val64;
        p = (void *)((char*)p + sizeof(uint64_t));
    } else {
        // 32bit packet counter
        output_record->dPkts = *((uint32_t *)p);
        p = (void *)((char*)p + sizeof(uint32_t));
    }

    // Required extension 3 - byte counter
    if ( (input_record->flags & FLAG_BYTES_64 ) != 0 ) {
        // 64bit byte counter
        value64_t	l, *v = (value64_t *)p;
        l.val.val32[0] = v->val.val32[0];
        l.val.val32[1] = v->val.val32[1];
        output_record->dOctets = l.val.val64;
        p = (void *)((char*)p + sizeof(uint64_t));
    } else {
        // 32bit bytes counter
        output_record->dOctets = *((uint32_t *)p);
        p = (void *)((char*)p + sizeof(uint32_t));
    }

    // preset one single flow
    output_record->aggr_flows = 1;

    // Process optional extensions
    i=0;
    while ( extension_map->ex_id[i] ) {
        switch (extension_map->ex_id[i++]) {
            // 0 - 3 should never be in an extension table so - ignore it
            case 0:
            case 1:
            case 2:
            case 3:
                break;
            case EX_IO_SNMP_2: {
                tpl_ext_4_t *tpl = (tpl_ext_4_t *)p;
                output_record->input  = tpl->input;
                output_record->output = tpl->output;
                p = (void *)tpl->data;
            } break;
            case EX_IO_SNMP_4: {
                tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
                output_record->input  = tpl->input;
                output_record->output = tpl->output;
                p = (void *)tpl->data;
            } break;
            case EX_AS_2: {
                tpl_ext_6_t *tpl = (tpl_ext_6_t *)p;
                output_record->srcas = tpl->src_as;
                output_record->dstas = tpl->dst_as;
                p = (void *)tpl->data;
            } break;
            case EX_AS_4: {
                tpl_ext_7_t *tpl = (tpl_ext_7_t *)p;
                output_record->srcas = tpl->src_as;
                output_record->dstas = tpl->dst_as;
                p = (void *)tpl->data;
            } break;
            case EX_MULIPLE: {
                tpl_ext_8_t *tpl = (tpl_ext_8_t *)p;
                // use a 32 bit int to copy all 4 fields
                output_record->any = tpl->any;
                p = (void *)tpl->data;
            } break;
            case EX_NEXT_HOP_v4: {
                tpl_ext_9_t *tpl = (tpl_ext_9_t *)p;
                output_record->ip_nexthop.v6[0] = 0;
                output_record->ip_nexthop.v6[1] = 0;
                output_record->ip_nexthop.v4	= tpl->nexthop;
                p = (void *)tpl->data;
                ClearFlag(output_record->flags, FLAG_IPV6_NH);
            } break;
            case EX_NEXT_HOP_v6: {
                tpl_ext_10_t *tpl = (tpl_ext_10_t *)p;
                CopyV6IP((uint32_t *)output_record->ip_nexthop.v6, (uint32_t *)tpl->nexthop);
                p = (void *)tpl->data;
                SetFlag(output_record->flags, FLAG_IPV6_NH);
            } break;
            case EX_NEXT_HOP_BGP_v4: {
                tpl_ext_11_t *tpl = (tpl_ext_11_t *)p;
                output_record->bgp_nexthop.v6[0] = 0;
                output_record->bgp_nexthop.v6[1] = 0;
                output_record->bgp_nexthop.v4	= tpl->bgp_nexthop;
                ClearFlag(output_record->flags, FLAG_IPV6_NHB);
                p = (void *)tpl->data;
            } break;
            case EX_NEXT_HOP_BGP_v6: {
                tpl_ext_12_t *tpl = (tpl_ext_12_t *)p;
                CopyV6IP((uint32_t *)output_record->bgp_nexthop.v6, (uint32_t *)tpl->bgp_nexthop);
                p = (void *)tpl->data;
                SetFlag(output_record->flags, FLAG_IPV6_NHB);
            } break;
            case EX_VLAN: {
                tpl_ext_13_t *tpl = (tpl_ext_13_t *)p;
                output_record->src_vlan = tpl->src_vlan;
                output_record->dst_vlan = tpl->dst_vlan;
                p = (void *)tpl->data;
            } break;
            case EX_OUT_PKG_4: {
                tpl_ext_14_t *tpl = (tpl_ext_14_t *)p;
                output_record->out_pkts = tpl->out_pkts;
                p = (void *)tpl->data;
            } break;
            case EX_OUT_PKG_8: {
                tpl_ext_15_t v, *tpl = (tpl_ext_15_t *)p;
                v.v[0] = tpl->v[0];
                v.v[1] = tpl->v[1];
                output_record->out_pkts = v.out_pkts;
                p = (void *)tpl->data;
            } break;
            case EX_OUT_BYTES_4: {
                tpl_ext_16_t *tpl = (tpl_ext_16_t *)p;
                output_record->out_bytes = tpl->out_bytes;
                p = (void *)tpl->data;
            } break;
            case EX_OUT_BYTES_8: {
                tpl_ext_17_t v,*tpl = (tpl_ext_17_t *)p;
                v.v[0] = tpl->v[0];
                v.v[1] = tpl->v[1];
                output_record->out_bytes = v.out_bytes;
                p = (void *)tpl->data;
            } break;
            case EX_AGGR_FLOWS_4: {
                tpl_ext_18_t *tpl = (tpl_ext_18_t *)p;
                output_record->aggr_flows = tpl->aggr_flows;
                p = (void *)tpl->data;
            } break;
            case EX_AGGR_FLOWS_8: {
                tpl_ext_19_t v, *tpl = (tpl_ext_19_t *)p;
                v.v[0] = tpl->v[0];
                v.v[1] = tpl->v[1];
                output_record->aggr_flows = v.aggr_flows;
                p = (void *)tpl->data;
            } break;
            case EX_MAC_1: {
                tpl_ext_20_t v, *tpl = (tpl_ext_20_t *)p;
                v.v1[0] = tpl->v1[0];
                v.v1[1] = tpl->v1[1];
                output_record->in_src_mac = v.in_src_mac;

                v.v2[0] = tpl->v2[0];
                v.v2[1] = tpl->v2[1];
                output_record->out_dst_mac = v.out_dst_mac;
                p = (void *)tpl->data;
            } break;
            case EX_MAC_2: {
                tpl_ext_21_t v, *tpl = (tpl_ext_21_t *)p;
                v.v1[0] = tpl->v1[0];
                v.v1[1] = tpl->v1[1];
                output_record->in_dst_mac = v.in_dst_mac;
                v.v2[0] = tpl->v2[0];
                v.v2[1] = tpl->v2[1];
                output_record->out_src_mac = v.out_src_mac;
                p = (void *)tpl->data;
            } break;
            case EX_MPLS: {
                tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
                int j;
                for (j=0; j<10; j++ ) {
                    output_record->mpls_label[j] = tpl->mpls_label[j];
                }
                p = (void *)tpl->data;
            } break;
            case EX_ROUTER_IP_v4: {
                tpl_ext_23_t *tpl = (tpl_ext_23_t *)p;
                output_record->ip_router.v6[0] = 0;
                output_record->ip_router.v6[1] = 0;
                output_record->ip_router.v4	= tpl->router_ip;
                p = (void *)tpl->data;
                ClearFlag(output_record->flags, FLAG_IPV6_EXP);
            } break;
            case EX_ROUTER_IP_v6: {
                tpl_ext_24_t *tpl = (tpl_ext_24_t *)p;
                CopyV6IP((uint32_t *)output_record->ip_router.v6, (uint32_t *)tpl->router_ip);
                p = (void *)tpl->data;
                SetFlag(output_record->flags, FLAG_IPV6_EXP);
            } break;
            case EX_ROUTER_ID: {
                tpl_ext_25_t *tpl = (tpl_ext_25_t *)p;
                output_record->engine_type = tpl->engine_type;
                output_record->engine_id   = tpl->engine_id;
                p = (void *)tpl->data;
            } break;
            case EX_BGPADJ: {
                tpl_ext_26_t *tpl = (tpl_ext_26_t *)p;
                output_record->bgpNextAdjacentAS = tpl->bgpNextAdjacentAS;
                output_record->bgpPrevAdjacentAS = tpl->bgpPrevAdjacentAS;
                p = (void *)tpl->data;
            } break;
            case EX_LATENCY: {
                tpl_ext_latency_t *tpl = (tpl_ext_latency_t *)p;
                output_record->client_nw_delay_usec = tpl->client_nw_delay_usec;
                output_record->server_nw_delay_usec = tpl->server_nw_delay_usec;
                output_record->appl_latency_usec = tpl->appl_latency_usec;
                p = (void *)tpl->data;
            } break;
            case EX_RECEIVED: {
                tpl_ext_27_t *tpl = (tpl_ext_27_t *)p;
                value64_t v;
                v.val.val32[0] = tpl->v[0];
                v.val.val32[1] = tpl->v[1];
                output_record->received = v.val.val64;
                p = (void *)tpl->data;
            } break;
#ifdef NSEL
            case EX_NSEL_COMMON: {
				tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
				value64_t v;
				v.val.val32[0] = tpl->v[0];
				v.val.val32[1] = tpl->v[1];
				output_record->event_time = v.val.val64;
				output_record->conn_id 	  = tpl->conn_id;
				output_record->event   	  = tpl->fw_event;
				output_record->event_flag = FW_EVENT;
				output_record->fw_xevent  = tpl->fw_xevent;
				output_record->icmp = tpl->nsel_icmp;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_XLATE_PORTS: {
				tpl_ext_38_t *tpl = (tpl_ext_38_t *)p;
				output_record->xlate_src_port = tpl->xlate_src_port;
				output_record->xlate_dst_port = tpl->xlate_dst_port;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_XLATE_IP_v4: {
				tpl_ext_39_t *tpl = (tpl_ext_39_t *)p;
				output_record->xlate_src_ip.v6[0] = 0;
				output_record->xlate_src_ip.v6[1] = 0;
				output_record->xlate_src_ip.v4	= tpl->xlate_src_ip;
				output_record->xlate_dst_ip.v6[0] = 0;
				output_record->xlate_dst_ip.v6[1] = 0;
				output_record->xlate_dst_ip.v4	= tpl->xlate_dst_ip;
				p = (void *)tpl->data;
				output_record->xlate_flags = 0;
				} break;
			case EX_NSEL_XLATE_IP_v6: {
				tpl_ext_40_t *tpl = (tpl_ext_40_t *)p;
				output_record->xlate_src_ip.v6[0] = tpl->xlate_src_ip[0];
				output_record->xlate_src_ip.v6[1] = tpl->xlate_src_ip[1];
				output_record->xlate_dst_ip.v6[0] = tpl->xlate_dst_ip[0];
				output_record->xlate_dst_ip.v6[1] = tpl->xlate_dst_ip[1];
				p = (void *)tpl->data;
				output_record->xlate_flags = 1;
				} break;
			case EX_NSEL_ACL: {
				tpl_ext_41_t *tpl = (tpl_ext_41_t *)p;
				int j;
				for (j=0; j<3; j++) {
					output_record->ingress_acl_id[j] = tpl->ingress_acl_id[j];
					output_record->egress_acl_id[j] = tpl->egress_acl_id[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER: {
				tpl_ext_42_t *tpl = (tpl_ext_42_t *)p;
				strncpy((void *)output_record->username, (void *)tpl->username, sizeof(output_record->username));
				output_record->username[sizeof(output_record->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER_MAX: {
				tpl_ext_43_t *tpl = (tpl_ext_43_t *)p;
				strncpy((void *)output_record->username, (void *)tpl->username, sizeof(output_record->username));
				output_record->username[sizeof(output_record->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NEL_COMMON: {
				tpl_ext_46_t *tpl = (tpl_ext_46_t *)p;
				output_record->event 	  = tpl->nat_event;
				output_record->event_flag = FW_EVENT;
				// XXX	- 3 bytes unused
				output_record->egress_vrfid  = tpl->egress_vrfid;
				output_record->ingress_vrfid = tpl->ingress_vrfid;
				p = (void *)tpl->data;

				// remember this value, if we read old 1.6.10 files
				compat_nel_bug.vrf = tpl->egress_vrfid;
				if ( compat_nel ) {
					output_record->xlate_src_port = compat_nel_bug.port[0];
					output_record->xlate_dst_port = compat_nel_bug.port[1];
					output_record->egress_vrfid   = 0;
				}
			} break;
			// compat record v1.6.10
			case EX_NEL_GLOBAL_IP_v4: {
				tpl_ext_47_t *tpl = (tpl_ext_47_t *)p;
				output_record->xlate_src_ip.v6[0] = 0;
				output_record->xlate_src_ip.v6[1] = 0;
				output_record->xlate_src_ip.v4	= tpl->nat_inside;
				output_record->xlate_dst_ip.v6[0] = 0;
				output_record->xlate_dst_ip.v6[1] = 0;
				output_record->xlate_dst_ip.v4	= tpl->nat_outside;
				p = (void *)tpl->data;

				output_record->xlate_src_port = compat_nel_bug.port[0];
				output_record->xlate_dst_port = compat_nel_bug.port[1];
				output_record->egress_vrfid   = 0;
				compat_nel = 1;
			} break;
			case EX_PORT_BLOCK_ALLOC: {
				tpl_ext_48_t *tpl = (tpl_ext_48_t *)p;
				output_record->block_start = tpl->block_start;
				output_record->block_end = tpl->block_end;
				output_record->block_step = tpl->block_step;
				output_record->block_size = tpl->block_size;
				if ( output_record->block_end == 0 && output_record->block_size != 0 )
					output_record->block_end = output_record->block_start + output_record->block_size - 1;
				p = (void *)tpl->data;
			} break;

#endif
        }
    }

} // End of ExpandRecord_v2
