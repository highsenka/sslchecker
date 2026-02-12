-- CREATE ROLE sslchecker WITH
--   LOGIN
--   SUPERUSER
--   INHERIT
--   CREATEDB
--   CREATEROLE
--   NOREPLICATION
--   BYPASSRLS
--   PASSWORD 'sslchecker';

-- CREATE DATABASE sslchecker
--     WITH
--     OWNER = sslchecker
--     ENCODING = 'UTF8'
--     LC_COLLATE = 'en_US.utf8'
--     LC_CTYPE = 'en_US.utf8'
--     TABLESPACE = pg_default
--     CONNECTION LIMIT = -1
--     IS_TEMPLATE = False;

CREATE SCHEMA IF NOT EXISTS public
    AUTHORIZATION sslchecker;

-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp" ;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

\c sslchecker;

CREATE SCHEMA IF NOT EXISTS sslchecker AUTHORIZATION sslchecker;

--
-- Name: certificate; Type: TABLE; Schema: sslchecker; Owner: sslchecker
--

CREATE TABLE sslchecker.certificate (
    id character varying DEFAULT public.uuid_generate_v1() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    modulus_sha256 character varying NOT NULL,
    digest_sha256 character varying NOT NULL,
    common_name character varying,
    serial_number character varying NOT NULL,
    version integer,
    subject character varying,
    subject_kwargs jsonb,
    subject_alt_name character varying[],
    subject_alt_name_sha256 character varying,
    subject_key_identifier character varying,
    authority_key_identifier character varying,
    signature_algorithm character varying,
    public_key character varying,
    key_type character varying(50),
    public_key_size integer,
    certificate character varying,
    certificate_kwargs jsonb,
    issuer character varying,
    issuer_kwargs jsonb,
    extentions jsonb,
    not_after timestamp with time zone,
    not_before timestamp with time zone,
    state character varying(50),
    CONSTRAINT certificate_pkey PRIMARY KEY (id)
);


ALTER TABLE sslchecker.certificate OWNER TO sslchecker;

--
-- Name: endpoint; Type: TABLE; Schema: sslchecker; Owner: sslchecker
--

CREATE TABLE sslchecker.endpoint 
(
    id character varying DEFAULT public.uuid_generate_v1() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    host character varying NOT NULL,
    last_check timestamp with time zone,
    error_count integer DEFAULT 0,
    port integer DEFAULT 443,
    CONSTRAINT endpoint_pkey PRIMARY KEY (id),
    CONSTRAINT uq__host__port UNIQUE (host, port)
);

ALTER TABLE sslchecker.endpoint OWNER TO sslchecker;

--
-- Name: certificate_endpoint_ref; Type: TABLE; Schema: sslchecker; Owner: sslchecker
--

CREATE TABLE sslchecker.certificate_endpoint_ref 
(
    id character varying DEFAULT public.uuid_generate_v1() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    certificate_id character varying NOT NULL,
    endpoint_id character varying NOT NULL,
    endpoint_port integer DEFAULT 443,
    CONSTRAINT certificate_endpoint_ref_pkey PRIMARY KEY (id),
    CONSTRAINT uq__certificate_endpoint_ref UNIQUE (endpoint_id)
);

ALTER TABLE sslchecker.certificate_endpoint_ref OWNER TO sslchecker;

CREATE TABLE IF NOT EXISTS sslchecker.token
(
    id character varying COLLATE pg_catalog."default" NOT NULL DEFAULT uuid_generate_v1(),
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    last_used_at timestamp with time zone DEFAULT now(),
    token character varying COLLATE pg_catalog."default" NOT NULL,
    email character varying COLLATE pg_catalog."default",
    telegram character varying COLLATE pg_catalog."default",
    time_channel character varying COLLATE pg_catalog."default",
    CONSTRAINT token_pkey PRIMARY KEY (id)
);

ALTER TABLE IF EXISTS sslchecker.token OWNER to sslchecker;


--
-- Table: sslchecker.tokenendpoint_ref
--

CREATE TABLE IF NOT EXISTS sslchecker.token_endpoint_ref
(
    id character varying COLLATE pg_catalog."default" NOT NULL DEFAULT uuid_generate_v1(),
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    token_id character varying COLLATE pg_catalog."default" NOT NULL,
    endpoint_id character varying COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT token_endpoint_ref_pkey PRIMARY KEY (id),
    CONSTRAINT uq__token_endpoint_ref UNIQUE (token_id, endpoint_id)
);

ALTER TABLE IF EXISTS sslchecker.token_endpoint_ref OWNER to sslchecker;
