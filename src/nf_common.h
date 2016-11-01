/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nf_common.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 *
 */

#ifndef _NF_COMMON_H
#define _NF_COMMON_H 1


typedef void (*printer_t)(void *, char **, int);

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t	pointer_addr_t;
#else
typedef uint32_t	pointer_addr_t;
#endif

typedef struct msec_time_s {
	time_t		sec;
	uint16_t	msec;
} msec_time_tt;

/* common minimum netflow header for all versions */
typedef struct common_flow_header {
  uint16_t  version;
  uint16_t  count;
} common_flow_header_t;

typedef struct printmap_s {
	char		*printmode;		// name of the output format
	printer_t	func;			// name of the function, which prints the record
	char		*Format;		// output format definition
} printmap_t;

#define NSEL_EVENT_IGNORE 0LL
#define NSEL_EVENT_CREATE 1LL
#define NSEL_EVENT_DELETE 2LL
#define NSEL_EVENT_DENIED 3LL
#define NSEL_EVENT_ALERT  4LL
#define NSEL_EVENT_UPDATE 5LL

#define NEL_EVENT_INVALID 0LL
#define NEL_EVENT_ADD	  1LL
#define NEL_EVENT_DELETE  2LL

typedef struct flowrec_s {

	time_t ts; 		// Date first seen
	time_t te; 		// Date last seen
	double td; 		// Duration
	char sa[128]; 	// Source Address
	char da[128]; 	// Destination Address
	int sp; 		// Source Port
	int dp; 		// Destination Port
	char pr[8]; 	// Protocol
	char flg[8]; 	// TCP Flags
	int fwd, 		// Forwarding Status
		stos; 		// Tos - Src tos
	unsigned long ipkt, 		// In Packets
		ibyt, 		// In Bytes
		opkt, 		// Out Packets
		obyt; 		// Out Bytes
 	long in; 		// Input Interface num
	long out; 		// Output Interface num
	int sas, 		// Source AS
		das, 		// Destination AS
		smk, 		// Src mask
		dmk, 		// Dst mask
		dtos,		// Tos - Dst tos
		dir; 		// Direction: ingress, egress
	char nh[128], 	// Next-hop IP Address
		nhb[128]; 	// BGP Next-hop IP Address
	int svln, 		// Src Vlan
		dvln; 		// Dst Vlan
//	uint8_t ismc[6], 	// Input Src Mac Addr
//		odmc [6], 	// Output Dst Mac Addr
//		idmc [6], 	// Input Dst Mac Addr
//		osmc [6]; 	// Output Src Mac Addr
//	char mpls1 [16], // MPLS Label 1
//		mpls2 [16], // MPLS Label 2
//		mpls3 [16], // MPLS Label 3
//		mpls4 [16], // MPLS Label 4
//		mpls5 [16], // MPLS Label 5
//		mpls6 [16], // MPLS Label 6
//		mpls7 [16], // MPLS Label 7
//		mpls8 [16], // MPLS Label 8
//		mpls9 [16], // MPLS Label 9
//		mpls10 [16]; // MPLS Label 10
	double cl, 		// client latency
			sl, 	// server latency
			al; 	// app latency
	char ra [128]; 	// Router IP Address
	int engine_type, engine_id; 	// Engine Type/ID
	long exid;		// Exporter SysID
	uint64_t tr; 		// Received Time

} flowrec_t;

/* prototypes */

int InitSymbols(void);

void Setv6Mode(int mode);

int Getv6Mode(void);

int Proto_num(char *protostr);

void format_file_block_header(void *header, char **s, int tag);

char *format_csv_header(void);

char *get_record_header(void);

char *get_sql_header(void);

char *get_sa (void *r, char *sa, int len);

char *get_da (void *rec, char *sa, int len);

char *get_ra (void *r, char *ra, int len);

void set_record_header(void);

void format_file_block_record(void *record, char **s, int tag);

void flow_record_to_pipe(void *record, char ** s, int tag);

void flow_record_to_csv(void *record, char ** s, int tag);

void flow_record_to_struct (void *record, flowrec_t *flowrec);

void flow_record_to_null(void *record, char ** s, int tag);

void flow_record_to_pgsql(void *record, char ** s, int tag);

int ParseOutputFormat(char *format, int plain_numbers, printmap_t *printmap);

void format_special(void *record, char ** s, int tag);

uint32_t Get_fwd_status_id(char *status);

char *Get_fwd_status_name(uint32_t id);

void Proto_string(uint8_t protonum, char *protostr);

void condense_v6(char *s);

#define TAG_CHAR ''

#endif //_NF_COMMON_H

