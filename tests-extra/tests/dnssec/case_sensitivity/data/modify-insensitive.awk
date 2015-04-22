# expected-changes -4 +5

# SOA: name server, admin contect
$3 == "SOA" { $4 = toupper($4); $5 = toupper($5) }

# NS: duplicate with different case
$3 == "NS" && $4 ~ /^ns2\./ { print; $4 = toupper($4); }

# MX: server address
$3 == "MX" { $5 = toupper($5); }

# CNAME: target
$3 == "CNAME" { $4 = toupper($4); }

# RRSIG: signer name
$3 == "RRSIG" && $4 == "A" { $11 = toupper($11); }

# output
{ print }
