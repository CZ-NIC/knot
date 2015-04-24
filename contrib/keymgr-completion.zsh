#compdef keymgr


local -a matchany policy_list policies zone_list zones files
matchany=(/$'[^\0]##\0'/)
key_list=( \( $(keymgr keystore list 2>/dev/null) \) )
keys=( \( $matchany ":keys:keys:$key_list" \) )
policy_list=( \( $(keymgr policy list 2>/dev/null) \) )
policies=( \( $matchany ":policies:policies:$policy_list" \) )
zone_list=( \( $(keymgr zone list 2>/dev/null) \) )
zones=( \( $matchany ":zones:zones:$zone_list" \) )
files=(/$'[^\0]##\0'/ ':file:file name:_files')

local -a keystore_cmds
_regex_words keystore-commands "keystore commands" \
	'l*ist:list all keys'
keystore_cmds=("$reply[@]")

local -a policy_subcmds policy_add_cmds policy_set_cmds
_regex_words policy-add-commands "policy add commands" \
	'a*lgorithm' \
	'de*lay' \
	'dn*skey-ttl' \
	'k*sk-size' \
	'n*sec3' \
	'rrsig-l*ifetime' \
	'rrsig-r*efresh' \
	's*oa-min-ttl' \
	'zo*ne-max-ttl' \
	'zsk-l*ifetime' \
	'zsk-s*ize'
policy_subcmds=("$reply[@]")
policy_add_cmds=( $matchany $policy_subcmds )
policy_set_cmds=( $policies $policy_subcmds )

local -a policy_cmds
_regex_words policy-commands "policy commands" \
	'a*dd:add a policy:$policy_add_cmds' \
	'l*ist:list all added policies' \
	'r*emove:remove a policy:$policies' \
	'se*t:set policy attributes:$policy_set_cmds' \
	'sh*ow:show policy attributes:$policies'
policy_cmds=("$reply[@]")

local -a zone_add_cmds
_regex_words zone-add-commands "zone add commands" \
	'p*olicy:set zone policy:$policies'
zone_add_cmds=( $matchany "$reply[@]")

local -a zone_key_generate_cmds
_regex_words zone-key-generate-commands "zone key generate commands" \
	'ac*tive' \
	'al*gorithm' \
	'k*sk' \
	'p*ublish' \
	'rem*ove' \
	'ret*ire' \
	's*ize'
zone_key_generate_cmds=( $matchany "$reply[@]")

local -a zone_key_import_cmds
zone_key_import_cmds=( $zones $files )

local -a zone_key_set_cmds
_regex_words zone-key-set-commands "zone key set commands" \
	'a*ctive' \
	'p*ublish' \
	'rem*ove' \
	'ret*ire'
zone_key_set_cmds=( $zones "$reply[@]")

local -a zone_key_cmds
_regex_words zone-key-commands "zone key commands" \
	'g*enerate:generate a key:$zone_key_generate_cmds' \
	'i*mport:import keys from file:$zone_key_import_cmds' \
	'l*ist:list keys:$zones' \
	'sh*ow:show a key:$zones' \
	'se*t:set attributes of a key:$zone_key_set_cmds'
zone_key_cmds=("$reply[@]")

local -a zone_remove_cmds
_regex_words zone-remove-commands "zone remove commands" \
	'f*orce:force remove'
zone_remove_cmds=( $zones "$reply[@]")

local -a zone_set_cmds
_regex_words zone-set-commands "zone set commands" \
	'p*olicy:set zone policy:$policies'
zone_set_cmds=( $zones "$reply[@]")

local -a zone_cmds
_regex_words zone-commands "zone commands" \
	'a*dd:add a zone:$zone_add_cmds' \
	'k*ey:manipulate zone keys:$zone_key_cmds' \
	'l*ist:list all added zones' \
	'r*emove:remove a zone:$zones' \
	'se*t:set zone attributes:$zone_set_cmds' \
	'sh*ow:show zone attributes:$zones'
zone_cmds=("$reply[@]")

# Arguments to _regex_arguments, built up in array $args.
local -a args reply
# Command word.  Don't care what that is.
args=( $matchany )

_regex_words commands "keymgr command" \
	'i*nit:initialize KASP directory and default keystore' \
	'k*eystore:manipulate keystore:$keystore_cmds' \
	'p*olicy:manipulate policies:$policy_cmds' \
	'z*one:manipule zones:$zone_cmds'
args+=("$reply[@]")

_regex_arguments _keymgr "${args[@]}"

_keymgr "$@"
