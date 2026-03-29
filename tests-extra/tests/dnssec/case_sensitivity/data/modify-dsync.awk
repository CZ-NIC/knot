# expected-changes -1 +1

# DSYNC: target
$3 == "DSYNC" { $7 = toupper($7); }

# output
{ print }
