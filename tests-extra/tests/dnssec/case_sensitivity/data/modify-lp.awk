# expected-changes -1 +1

# LP: signer name
$3 == "LP" { $5 = toupper($5); }

# output
{ print }
