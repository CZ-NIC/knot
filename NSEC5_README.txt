NSEC5 Instructions
==================

Issuing queries:
 If the server is already set up issue a query with kdig. E.g., kdig @localhost +dnssec dns3.example.com A. You may also be able to use dig but you will see generically encoded responses. For span8, knotd is currently listening to port 2053.

Setting up the server:
 First see the KNOT DNS standard Readme file for instructions on setting the configuration file, the zone file, and generating DNS ZSK and KSK (overall very similar to BIND). Configure with --disable-fastparser (optimized zone scanner does not "speak" NSEC5 at the moment). Then generate NSEC5KEY pair with the same tool (dnssec-keygen) using an RSA algorithm (e.g., 8) and 2048 bits as per the draft. Manually  set the Algorithm in the public key file to 1, the RRtype to NSEC5KEY, and remove the protocol identifier (3), to form a proper NSEC5KEY RR (you can check this by passing the file to the zscanner-tool utility). Finally, add “nsec5” to BOTH name files (public and private), e.g., testkey.private -> testkey_nsec5.private. This is currently the only way to signal to the server that NSEC5 should be used (similar to the existence of NSEC3PARAM record in the zonefile for NSEC3). Proceed to run sudo knotd (runs the server in the foreground —sudo knotd -d for daemonize). 

Re-signing:
 To re-sign a zone (while the server is running) run sudo knotc [zonename]. 


Issues
——————
- If you have issues while executing make (e.g., no rule to build knsec5hash dependencies) try make distclean first (temporary till I remove misplaced files from repo).

- NXDOMAIN, WILDCARD NO DATA, NODATA, WILDCARD synthesis, and unsigned delegation responses are accommodated.

- One issue to be fixed is that the NSEC5 signed zone is not parsed correctly by zonefile_load. The problem is that the next_hashed field of NSEC5 records is parsed by zscanner as base32. Unfortunately the RFC specifies no padding and the parsing fails (the data is stored in 52 octets instead of 56, i.e., the last group of 5 octets is not full). One way to fix this is to change the way zscanner parses the zone. Temporarily, two easy work-arounds are to change the encoding of next_hashed to include padding (from nsec5-chain.c) or disable the error checks for zonefile_load. This issue only comes up if one tries to perform the original signing with an already set up NSEC5 zone, or when running knotc checkzone (not with signzone —this is “forced” resigning, it ignores the old journal and re-writes it). 

- Multiple NSEC5KEY’s are accommodated but only ONE of them must be active at any given time. This serves to add a “pre-publish” key in the zone which is not used to create the NSEC5 chain until a rollover occurs. Use dnssec-keygen with publish-now-activate-later options. To rollover, “deactivate” old key and activate the new one (by manipulating dates in the corresponding keyless). Actual rollover NOT tested yet.



  
