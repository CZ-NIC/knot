#compdef keymgr


local -a matchany policy_list policies zone_list zones
matchany=(/$'[^\0]##\0'/)
policy_list=( \( $(keymgr policy list) \) )
policies=( \( $matchany ":policies:policies:$policy_list" \) )
zone_list=( \( $(keymgr zone list) \) )
zones=( \( $matchany ":zones:zones:$zone_list" \) )

local -a keystore_cmds
_regex_words keystore-commands "keystore commands" \
    'l*ist:list all keys'
keystore_cmds=("$reply[@]")


local -a policy_cmds
_regex_words policy-commands "policy commands" \
    'a*dd:add a policy' \
    'l*ist:list all added policies' \
    'r*emove:remove a policy:$policies' \
    'se*t:set policy attributes:$policies' \
    'sh*ow:show policy attributes::$policies'
policy_cmds=("$reply[@]")


local -a zone_cmds
_regex_words zone-commands "zone commands" \
    'a*dd:add a zone' \
    'k*ey:manipulate zone keys:$zones' \
    'l*ist:list all added zones' \
    'r*emove:remove a zone:$zones' \
    'se*t:set zone attributes:$zones' \
    'sh*ow:show zone attributes::$zones'
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

# Local Variables: 
# mode:shell-script
# End:             
