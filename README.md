# NetSupport

### Background

- https://unit42.paloaltonetworks.com/cortex-xdr-detects-netsupport-manager-rat-campaign/

### Testing PCAP:

- https://app.any.run/tasks/b5d9853f-0dca-45ef-9532-83feeedcbf42

### Example:

```
$ zeek -Cr b5d9853f-0dca-45ef-9532-83feeedcbf42.pcap

$ cat notice.log

#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2024-06-04-21-07-34
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1717442617.920239	CQ7b0y4Vd4NVQ3nJRi	192.168.100.146	49741	45.134.174.143	443	-	-	-	tcp	NetSupport::C2_Traffic_Observed	NetSupport (potential malware) C2 between 192.168.100.146 and 45.134.174.143.	-	192.168.100.146	45.134.174.143	443	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2024-06-04-21-07-34
```