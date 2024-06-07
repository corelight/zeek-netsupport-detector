signature netsupport-cmd-encd {
    ip-proto == tcp
    payload /.*\x0aCMD=ENCD\x0a.*/
    eval NetSupport::netsupport_cmd_encd_match    
}

signature netsupport-cmd-poll {
    ip-proto == tcp
    payload /.*\x0aCMD=POLL\x0a.*/
    eval NetSupport::netsupport_cmd_poll_match    
}