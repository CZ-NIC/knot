# keymgr(1) completion                                         -*- shell-script -*-

_keymgr() 
{
	local cur prev words cword
	_init_completion || return


	case $prev in
		-V|-version)
			return 0
			;;
		-h|--help)
			return 0
			;;
		-d|--dir)
			_filedir
			return 0;
			;;
	esac

	#local subcword cmd subcmd
	#for (( subcword=1; subcword < ${#words[@]}-1; subcword++ )); do
		#[[ ${words[subcword]} == @(-d|--dir) ]] && return 0
		#[[ -n $cmd ]] && subcmd=${words[subcword]} && break
		#[[ ${words[subcword]} != -* ]] && \
			#cmd=${words[subcword]}
	#done

	local count start cmd sub1cmd sub2cmd sub3cmd
	count=$(( ${#words[@]} - 1 ))
	if [[ ${words[1]} == -* ]]; then
		start=3
	else
		start=1
	fi
	cmd=${words[start]}
	sub1cmd=${words[$((start + 1))]}
	sub2cmd=${words[$((start + 2))]}
	sub3cmd=${words[$((start + 3))]}

	#echo $count
	#echo -n "[cmd:"
	#echo -n $cmd
	#echo -n "; sub1cmd:"
	#echo -n $sub1cmd
	#echo -n "; sub2cmd:"
	#echo -n $sub2cmd
	#echo -n "; sub3cmd:"
	#echo -n $sub3cmd
	#echo "]"

	#if [[ -z $cmd ]]; then
		#case $cur in
			#-*)
				#local c="--version --help --dir"
				#COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
				#return 0
				#;;
			#*)
				#local c="init zone policy keystore"
				#COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
				#return 0
				#;;
		#esac
	#fi

	case $cmd in
		init)
			;;
		keystore)
			case $sub1cmd in
				list)
					;;
				*)
					[[ $cword -eq $subcword ]] && \
						COMPREPLY=( $( compgen -W 'list' \
						-- "$cur" ) )
					;;
			esac
			;;
		policy)
			case $sub1cmd in
				add)
					if [[ -n $sub2cmd ]]; then
						case $sub3cmd in
							*)
								COMPREPLY=( $( compgen -W 'algorithm dnskey-ttl \
									ksk-size zsk-size zsk-lifetime rrsig-lifetime \
									rrsig-refresh nsec3 soa-min-ttl zone-max-ttl delay' \
									-- "$cur" ) )
								;;
						esac
					fi
					;;
				list)
					;;
				remove|show)
					local c=$( keymgr policy list )
					COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					;;
				set)
					if [[ -z $sub2cmd ]]; then
						local c=$( keymgr policy list )
						COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					else
						COMPREPLY=( $( compgen -W 'algorithm dnskey-ttl \
									ksk-size zsk-size zsk-lifetime rrsig-lifetime \
									rrsig-refresh nsec3 soa-min-ttl zone-max-ttl delay' \
									-- "$cur" ) )
					fi
					;;
				*)
					COMPREPLY=( $( compgen -W 'add list remove set show' \
						-- "$cur" ) )
					;;
			esac
			;;
		zone)
			case $sub1cmd in
				add)
					;;
				list)
					;;
				key)
					;;
				remove|show)
					local c=$( keymgr zone list )
					COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					;;
				set)
					;;
				*)
					COMPREPLY=( $( compgen -W 'add key list remove set show' \
						-- "$cur" ) )
					;;
			esac
			;;
		-d|--dir)
			_filedir
			;;
		-v|--version|-h|--help)
			;;
		-*)
			local c="--version --help --dir"
			COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
			;;
		*)
			local c="init zone policy keystore"
			COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
			;;
	esac
}
complete -F _keymgr keymgr
