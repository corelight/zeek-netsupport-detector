module NetSupport;

export {
	## The notice when NetSupport C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed_HTTP_Headers,
	    C2_Traffic_Observed_CMD_ENCD, C2_Traffic_Observed_CMD_POLL };
}

event http_header(c: connection, is_orig: bool, original_name: string,
    name: string, value: string)
	{
	if ( name != "USER-AGENT" && name != "SERVER" )
		return;

	if ( "NetSupport" !in value )
		return;

	local msg = "NetSupport C2 detected via HTTP headers.  NetSupport is often used in malware attacks, so be sure to check the endpoints.";

	NOTICE([ $note=NetSupport::C2_Traffic_Observed_HTTP_Headers, $msg=msg, $conn=c,
	    $identifier=c$uid ]);
	}

# Signature match function for CMD=ENCD
function netsupport_cmd_encd_match(state: signature_state, data: string): bool
    &is_used
	{
	local id = state$conn$id;
	local msg = "NetSupport C2 detected by CMD=ENCD in connection.  CMD=ENCD is often seen in malware attacks.  Be sure to check the endpoints.  Payload is in sub field.";

	NOTICE([ $note=NetSupport::C2_Traffic_Observed_CMD_ENCD, $msg=msg, $sub=data,
	    $conn=state$conn, $identifier=state$conn$uid ]);

	return T;
	}

# Signature match function for CMD=POLL
function netsupport_cmd_poll_match(state: signature_state, data: string): bool
    &is_used
	{
	local id = state$conn$id;
	local msg = "NetSupport C2 detected by CMD=POLL in connection.  NetSupport is often used in malware attacks, so be sure to check the endpoints.  Payload is in sub field.";

	NOTICE([ $note=NetSupport::C2_Traffic_Observed_CMD_POLL, $msg=msg, $sub=data,
	    $conn=state$conn, $identifier=state$conn$uid ]);

	return T;
	}
