# smart_pcap_trigger.zeek
# Implements Smart PCAP triggers for selective packet capture
# Based on Corelight best practices: capture metadata everywhere, 
# full packets only when needed

@load base/frameworks/notice

module SmartPCAP;

export {
    redef enum Notice::Type += {
        ## Unusual HTTP method detected
        Suspicious_HTTP_Method,
        ## Potential data exfiltration detected
        Large_Upload_Detected,
        ## Non-standard port usage
        Suspicious_Port_Usage,
        ## Failed authentication attempts
        Auth_Failure_Pattern,
        ## Suspicious DNS query
        Suspicious_DNS_Query,
    };
    
    ## Threshold for flagging large uploads (bytes)
    const upload_threshold = 100000 &redef;
    
    ## Track suspicious domain patterns
    const suspicious_domains = /.*\.(xyz|top|tk|ml|ga)$/ &redef;
}

# Trigger on unusual HTTP methods
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    # Flag non-standard HTTP methods for Smart PCAP capture
    if ( method !in set("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH") )
        {
        NOTICE([$note=Suspicious_HTTP_Method,
                $conn=c,
                $msg=fmt("Smart PCAP Trigger: Unusual HTTP method '%s' to %s", 
                        method, original_URI),
                $identifier=cat(c$id$orig_h, c$id$resp_h, method)]);
        }
    }

# Trigger on large uploads (potential data exfiltration)
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( is_orig && stat?$body_length && stat$body_length > upload_threshold )
        {
        NOTICE([$note=Large_Upload_Detected,
                $conn=c,
                $msg=fmt("Smart PCAP Trigger: Large upload detected: %d bytes", 
                        stat$body_length),
                $identifier=cat(c$id$orig_h, c$id$resp_h, stat$body_length)]);
        }
    }

# Trigger on suspicious DNS queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( suspicious_domains in query )
        {
        NOTICE([$note=Suspicious_DNS_Query,
                $conn=c,
                $msg=fmt("Smart PCAP Trigger: Suspicious domain query: %s", query),
                $identifier=cat(c$id$orig_h, query)]);
        }
    
    # Flag domains with random-looking patterns (potential DGA)
    if ( /[a-z0-9]{20,}/ in query )
        {
        NOTICE([$note=Suspicious_DNS_Query,
                $conn=c,
                $msg=fmt("Smart PCAP Trigger: Potential DGA domain: %s", query),
                $identifier=cat(c$id$orig_h, query)]);
        }
    }

# Trigger on connections to unusual ports
event connection_established(c: connection)
    {
    local standard_ports: set[port] = set(80/tcp, 443/tcp, 22/tcp, 21/tcp, 25/tcp, 
                                           53/tcp, 110/tcp, 143/tcp, 993/tcp, 995/tcp);
    
    # Flag connections to non-standard ports above 1024
    if ( c$id$resp_p !in standard_ports && port_to_count(c$id$resp_p) > 1024 )
        {
        NOTICE([$note=Suspicious_Port_Usage,
                $conn=c,
                $msg=fmt("Smart PCAP Trigger: Connection to unusual port %s", 
                        c$id$resp_p),
                $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)]);
        }
    }
