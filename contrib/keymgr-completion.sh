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
			return 0
			;;
	esac

	local subcword cmd subcmd
	for (( subcword=1; subcword < ${#words[@]}-1; subcword++ )); do
		[[ ${words[subcword]} == @(-d|--dir) ]] && return 0
		[[ -n $cmd ]] && subcmd=${words[subcword]} && break
		[[ ${words[subcword]} != -* ]] && \
			cmd=${words[subcword]}
	done

	if [[ -z $cmd ]]; then
		case $cur in
			-*)
				local c="--version --help --dir"
				COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
				return 0
				;;
			*)
				local c="init zone policy keystore"
				COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
				return 0
				;;
		esac
	fi

	[[ $subcmd == help ]] && return 0

	case $cmd in
		init)
			;;
		keystore)
			case $subcmd in
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
			case $subcmd in
				add|list)
					;;
				remove|set|show)
					local c=$( keymgr policy list )
					COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					;;
				*)
					[[ $cword -eq $subcword ]] && \
						COMPREPLY=( $( compgen -W 'add list remove set show' \
						-- "$cur" ) )
					;;
			esac
			;;
		zone)
			case $subcmd in
				add|list)
					;;
				key|remove|set|show)
					local c=$( keymgr zone list )
					COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					;;
				*)
					[[ $cword -eq $subcword ]] && \
						COMPREPLY=( $( compgen -W 'add key list remove set show' \
						-- "$cur" ) )
					;;
			esac
			;;
	esac
}
complete -F _keymgr keymgr
