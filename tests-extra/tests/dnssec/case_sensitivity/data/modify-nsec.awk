# expected-changes -1 +1

# NSEC: signer name
$1 == "example." && $3 == "NSEC" { $4 = toupper($4); }

# output
{ print }
