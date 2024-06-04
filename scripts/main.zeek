module NetSupport;

export {
	## The notice when NetSupport C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed };
}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if (name != "USER-AGENT" && name != "SERVER")
		return;

	if ("NetSupport" !in value)
		return;

	local msg = fmt("NetSupport (potential malware) C2 between %s and %s.",
			c$id$orig_h, c$id$resp_h);

	NOTICE([$note=NetSupport::C2_Traffic_Observed, $msg=msg, $conn=c, $identifier=cat(c$id$orig_h, c$id$resp_h)]);
	}
