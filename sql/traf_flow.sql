-- Function: traf_flow_partitioning()

-- DROP FUNCTION traf_flow_partitioning();

CREATE OR REPLACE FUNCTION traf_flow_partitioning()
  RETURNS trigger AS
$BODY$
declare
        relname varchar;
        schema varchar;
        rel_exists text;
        suffix varchar;
        this_mon timestamp;
        next_mon timestamp;
        rec_exists boolean;
begin
	suffix := to_char(new.datetime, 'YYYYMM');
        --raise notice '%', suffix;
        schema := 'public';
        relname := 'traf_flow_1h_' || suffix;
        --raise notice '%', relname;
        --EXECUTE 'SELECT to_regclass('|| quote_literal(relname) ||');' INTO rel_exists;
	EXECUTE 'SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_schema = ' || quote_literal(schema) || 
		' AND table_name = ' || quote_literal(relname) || ')' INTO rel_exists;
	
        IF rel_exists = 'f'
        THEN
                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' );' INTO this_mon;
                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' + INTERVAL ''1 MON'');' INTO next_mon;

                EXECUTE 'CREATE TABLE ' || schema || '.' || relname || 
                        ' (CONSTRAINT ' || relname || '_datetime_check CHECK (' || 
                        'datetime >= ' || quote_literal(this_mon) || '::timestamp without time zone AND ' || 
                        'datetime < ' || quote_literal(next_mon) || '::timestamp without time zone)' || 
                        ') INHERITS (public.traf_flow) WITH (OIDS=FALSE)';

                EXECUTE 'CREATE UNIQUE INDEX ' || relname || '_idx ON ' || schema || '.' || relname || ' USING btree (datetime, ip_addr, type)';
                EXECUTE 'ALTER TABLE ' || relname || ' OWNER TO postgres';
                EXECUTE 'GRANT ALL ON TABLE ' || relname || ' TO postgres';
        END IF;

        EXECUTE 'SELECT EXISTS (SELECT * FROM ' || relname || ' WHERE datetime=' || quote_literal(new.datetime) || ' AND ip_addr=' || quote_literal(new.ip_addr) || 
		' AND type=' || new.type || ')' INTO rec_exists;
        IF NOT rec_exists
        THEN

                EXECUTE format('insert into ' || relname || '(datetime,router_ip,ip_addr,in_bytes,out_bytes,type) VALUES($1,$2,$3,$4,$5,$6)')
                        USING new.datetime,new.router_ip,new.ip_addr,new.in_bytes,new.out_bytes,new.type;
        ELSE
                EXECUTE format('update ' || relname || ' set in_bytes=in_bytes+$1, out_bytes=out_bytes+$2 where datetime=$3 and ip_addr=$4 and type=$5') 
			USING new.in_bytes,new.out_bytes, new.datetime,new.ip_addr,new.type;
        END IF;

	relname := 'traf_flow_1d_' || suffix;
	EXECUTE 'SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_schema = ' || quote_literal(schema) || 
		' AND table_name = ' || quote_literal(relname) || ')' INTO rel_exists;
	
        IF rel_exists = 'f'
        THEN
                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' );' INTO this_mon;
                EXECUTE 'select date_trunc(''month'', TIMESTAMP ' || quote_literal(new.datetime) || ' + INTERVAL ''1 MON'');' INTO next_mon;

                EXECUTE 'CREATE TABLE ' || schema || '.' || relname || 
                        ' (CONSTRAINT ' || relname || '_datetime_check CHECK (' || 
                        'datetime >= ' || quote_literal(this_mon) || '::timestamp without time zone AND ' || 
                        'datetime < ' || quote_literal(next_mon) || '::timestamp without time zone)' || 
                        ') INHERITS (public.traf_flow) WITH (OIDS=FALSE)';

                EXECUTE 'CREATE UNIQUE INDEX ' || relname || '_idx ON ' || schema || '.' || relname || ' USING btree (datetime, ip_addr, type)';
                EXECUTE 'ALTER TABLE ' || relname || ' OWNER TO postgres';
                EXECUTE 'GRANT ALL ON TABLE ' || relname || ' TO postgres';
        END IF;

        return null;  
end;
$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;
ALTER FUNCTION traf_flow_partitioning()
  OWNER TO postgres;

-- Table: traf_flow

-- DROP TABLE traf_flow;

CREATE TABLE traf_flow
(
  datetime timestamp without time zone,
  router_ip inet,
  ip_addr inet,
  in_bytes bigint,
  out_bytes bigint,
  type integer
)
WITH (
  OIDS=FALSE
);
ALTER TABLE traf_flow
  OWNER TO postgres;

-- Trigger: partitioning on traf_flow

-- DROP TRIGGER partitioning ON traf_flow;

CREATE TRIGGER partitioning
  BEFORE INSERT
  ON traf_flow
  FOR EACH ROW
  EXECUTE PROCEDURE traf_flow_partitioning();

