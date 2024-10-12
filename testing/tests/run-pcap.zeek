# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/b5d9853f-0dca-45ef-9532-83feeedcbf42.pcap $PACKAGE %INPUT >output
#
# We've observed that signature matches on the same payload have nondeterministic
# ordering, so we canonicalize the notices.
# @TEST-EXEC: sort notice.log >notice.log.srt
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff notice.log.srt
