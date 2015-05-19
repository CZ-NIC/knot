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
			_filedir -d
			return 0;
			;;
	esac

	local count start cmd sub1cmd sub2cmd sub3cmd
	if [[ ${words[1]} == -* ]]; then
		start=3
	else
		start=1
	fi
	cmd=${words[start]}
	sub1cmd=${words[$((start + 1))]}
	sub2cmd=${words[$((start + 2))]}
	sub3cmd=${words[$((start + 3))]}

	if [[ -z $cmd ]]; then
		case $cur in
			-*)
				local c="--version --help --dir"
				COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
				return 0
				;;
		esac
	fi

	count=1      #counts how many levels are we deep; required for user-input strings
	case $cmd in
		init)
			;;
		keystore)
			case $sub1cmd in
				list)
					;;
				*)
					COMPREPLY=( $( compgen -W 'list' -- "$cur" ) )
					;;
			esac
			;;
		policy)
			count=$((count + 1))
			case $sub1cmd in
				add)
					count=$((count + 1))
					if [[ $count -ne $cword ]]; then
						COMPREPLY=( $( compgen -W 'algorithm dnskey-ttl
							ksk-size zsk-size zsk-lifetime rrsig-lifetime
							rrsig-refresh nsec3 soa-min-ttl zone-max-ttl delay' \
							-- "$cur" ) )
					fi
					;;
				list|remove|show)
					count=$((count + 1))
					if [[ $count -eq $cword ]]; then
						local c=$( keymgr policy list 2>/dev/null )
						COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					fi
					;;
				set)
					count=$((count + 1))
					if [[ $count -ne $cword ]]; then
						COMPREPLY=( $( compgen -W 'algorithm dnskey-ttl
									ksk-size zsk-size zsk-lifetime rrsig-lifetime
									rrsig-refresh nsec3 soa-min-ttl zone-max-ttl delay' \
									-- "$cur" ) )
					else
						local c=$( keymgr policy list 2>/dev/null )
						COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					fi
					;;
				*)
					COMPREPLY=( $( compgen -W 'add list remove set show' \
						        -- "$cur" ) )
					;;
			esac
			;;
		zone)
			count=$((count + 1))
			case $sub1cmd in
				add)
					count=$((count + 1))
					if [[ $count -ne $cword ]]; then
						count=$((count + 1))
						case $sub3cmd in
							policy)
								count=$((count + 1))
								if [[ $count -eq $cword ]]; then
									local c=$( keymgr policy list 2>/dev/null )
									COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
								fi
								;;
							*)
								COMPREPLY=( $( compgen -W 'policy' -- "$cur" ) )
								;;
						esac
					fi
					;;
				key)
					count=$((count + 1))
					case $sub2cmd in
						generate)
							count=$((count + 1))
							if [[ $count -eq $cword ]]; then
								local c=$( keymgr zone list 2>/dev/null )
								COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
							else
								COMPREPLY=( $( compgen -W 'algorithm size
								    ksk publish active retire remove' -- "$cur" ) )
							fi
							;;
						import)
							count=$((count + 1))
							if [[ $count -ne $cword ]]; then
								_filedir
							else
								local c=$( keymgr zone list 2>/dev/null )
								COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
							fi
							;;
						list)
							count=$((count + 1))
							if [[ $count -eq $cword ]]; then
								local c=$( keymgr zone list 2>/dev/null )
								COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
							fi
							;;
						set)
							count=$((count + 1))
							if [[ $count -ne $cword ]]; then
								count=$((count + 1))
								if [[ $count -ne $cword ]]; then
									COMPREPLY=( $( compgen -W ' publish
										active retire remove' -- "$cur" ) )
								else
									local c=$( keymgr zone key list "$sub3cmd" 2>/dev/null | cut -f 2 -d ' ' )
									COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
								fi
							else
								local c=$( keymgr zone list 2>/dev/null )
								COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
							fi
							;;
						show)
							count=$((count + 1))
							if [[ $count -ne $cword ]]; then
								local c=$( keymgr zone key list "$sub3cmd" 2>/dev/null | cut -f 2 -d ' ' )
								COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
							else
								local c=$( keymgr zone list 2>/dev/null )
								COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
							fi
							;;
						*)
							COMPREPLY=( $( compgen -W 'generate import
						        list set show' -- "$cur" ) )
							;;
					esac
					;;
				list)
					;;
				remove)
					count=$((count + 1))
					if [[ $count -ne $cword ]]; then
						case $sub3cmd in
							force)
								;;
							*)
								COMPREPLY=( $( compgen -W 'force' -- "$cur" ) )
								;;
						esac
					else
						local c=$( keymgr zone list 2>/dev/null )
						COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					fi
					;;
				show)
					count=$((count + 1))
					if [[ $count -eq $cword ]]; then
						local c=$( keymgr zone list 2>/dev/null )
						COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					fi
					;;
				set)
					count=$((count + 1))
					if [[ $count -ne $cword ]]; then
						count=$((count + 1))
						case $sub3cmd in
							policy)
								count=$((count + 1))
								if [[ $count -eq $cword ]]; then
									local c=$( keymgr policy list 2>/dev/null )
									COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
								fi
								;;
							*)
								COMPREPLY=( $( compgen -W 'policy' -- "$cur" ) )
								;;
						esac
					else
						local c=$( keymgr zone list 2>/dev/null )
						COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
					fi
					;;
				*)
					COMPREPLY=( $( compgen -W 'add key list remove set show' \
					    -- "$cur" ) )
					;;
			esac
			;;
		*)
			local c="init zone policy keystore"
			COMPREPLY=( $( compgen -W "$c" -- "$cur" ) )
			;;
	esac
}
complete -F _keymgr keymgr
