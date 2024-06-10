signature netsupport-cmd-encd {
    ip-proto == tcp
    payload /.*(\x0a|\x0d)CMD=ENCD(\x0a|\x0d).*/
    eval NetSupport::netsupport_cmd_encd_match    
}

signature netsupport-cmd-poll {
    ip-proto == tcp
    payload /.*(\x0a|\x0d)CMD=POLL(\x0a|\x0d).*/
    eval NetSupport::netsupport_cmd_poll_match    
}