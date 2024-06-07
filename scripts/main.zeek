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

	local msg = "NetSupport (potential malware) C2, detected via HTTP headers.";

	NOTICE([ $note=NetSupport::C2_Traffic_Observed_HTTP_Headers, $msg=msg, $conn=c,
	    $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
	}

# Signature match function for CMD=ENCD
function netsupport_cmd_encd_match(state: signature_state, data: string): bool
    &is_used
	{
	local id = state$conn$id;
	local msg = "NetSupport (potential malware) C2, detected by CMD=ENCD in connection.  Payload is in sub field.";

	NOTICE([ $note=NetSupport::C2_Traffic_Observed_CMD_ENCD, $msg=msg, $sub=data,
	    $conn=state$conn, $identifier=cat(state$conn$id$orig_h,
	    state$conn$id$resp_h) ]);

	return T;
	}

# Signature match function for CMD=POLL
function netsupport_cmd_poll_match(state: signature_state, data: string): bool
    &is_used
	{
	local id = state$conn$id;
	local msg = "NetSupport (potential malware) C2, detected by CMD=POLL in connection.  Payload is in sub field.";

	NOTICE([ $note=NetSupport::C2_Traffic_Observed_CMD_POLL, $msg=msg, $sub=data,
	    $conn=state$conn, $identifier=cat(state$conn$id$orig_h,
	    state$conn$id$resp_h) ]);

	return T;
	}
