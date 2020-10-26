example.com.		3600	IN SOA	dns2.example.com. hostmaster.example.com. (
					2010135808 ; serial
					10800      ; refresh (3 hours)
					3600       ; retry (1 hour)
					1209600    ; expire (2 weeks)
					7200       ; minimum (2 hours)
					)
			3600	RRSIG	SOA 13 2 3600 (
					20601231235959 20201012144147 25752 example.com.
					dEDk41MHSAAoc2eboWOXxGQHYFj1gXuD/gfX
					Qz6HEq44narP0IHuOWt4ni9HUhYDBuanPp7S
					j/8nYnZc6gdpMg== )
			3600	NS	dns2.example.com.
			3600	RRSIG	NS 13 2 3600 (
					20601231235959 20201012144147 25752 example.com.
					1HFpOHudUJp7hvrsTmdX6qt+X0I4K9RYo/Uy
					gpWbJBNhNsPVENVrw8AabhnPaETJGbreS/4T
					slgbxM1Ks/erzA== )
			3600	MX	10 mail.example.com.
			3600	RRSIG	MX 13 2 3600 (
					20601231235959 20201012144147 25752 example.com.
					EA9rtC9Ub4LPDwS6Q8wE4g9nGddbVrg9ivHN
					oHQzUjTFlxtn8gFPaJkUfHwqwg3PsSVGagyx
					Bjsool21k/TG7A== )
			7200	NSEC	dns2.example.com. NS SOA MX RRSIG NSEC DNSKEY CDS CDNSKEY
			7200	RRSIG	NSEC 13 2 7200 (
					20601231235959 20201012144147 25752 example.com.
					YLQPkC55O9bpQI/Hg/Ih91UkieeM3wtQvJMT
					ro3QJ2eDImSyeoIbWsF+ghtoQ+6IUulXLu3k
					PtDViOe2tfaL/Q== )
			3600	DNSKEY	256 3 8 (
					AwEAAdKraxDdGTL4HDOkXTDI1Md1UdHuYhVw
					YkB+u2umVjTJ1H9Qb2oBryqwXI+gklnuCqrH
					1znkDvzGEAeHRQUCbtKbjmqErTAcRRHW3D+6
					jsOGXzbyGCfbyzRBwsbNCLWr3ONpPi5JOWEe
					CUJfyc/mRXcmh5uYl1JvzAM1zprtljZt
					) ; ZSK; alg = RSASHA256 ; key id = 48849
			3600	DNSKEY	256 3 13 (
					1J1lDp/FQFgAGv7EFeDTAru7rUIcUCc7bkYj
					8OlczfdQjo9IfS5MFg6MqIrE/KPC18CDX1Ki
					DzaCFaMGDlavjQ==
					) ; ZSK; alg = ECDSAP256SHA256 ; key id = 25752
			3600	DNSKEY	257 3 8 (
					AwEAAcQ1EqTPebcJyUnpxO3Xjx6ehRtsiZYT
					oARoJsJG12XR6Ci9yy4SCCsejtaWIFO4XVfM
					2BHzFWqmABtQHtN7AazXAFMLsrSE4DYbgk5W
					mnQv5Jloi6jhhmmXwr8EOi3HR2jdG0gVq/Ta
					x7ztNNZsflJrs3rZs2TVO00BkyyOkmO35jCN
					bGPUwm5cW1vse137BMa7jAcMyNLPIiQubj1/
					mJcIyzF2duvfpjBTgEmSvNcXqLfYFjK8lG4N
					odQG8AcK0MvWqN4mxW/hK0U9nMSjhCnfzPg5
					tjyqdheWRyhkLGjM/mR7gBhtqoSPMr+2KMJQ
					EHYAd/AP8YgaovS8N1fJyh0=
					) ; KSK; alg = RSASHA256 ; key id = 53851
			3600	DNSKEY	257 3 8 (
					AwEAAetE6qfN/GbtMmvM0PXUTyskauES2FKf
					jqLVz7EQlfS8iAFWLi1eHjHXDkueZ1OYRzQ4
					IBy6MIsce4XVXLQoS8njtfaU7c5NZvktH5la
					7JuH32KYr3PdWL5KDsUdED3GSxfNV+DbcYU8
					0AZxTxy6Bm6EP+DztL1dpYrmqr8JRl+qlSbm
					LIrPemZFUEQzhiepcYMWviDUz+ixSVzjEzpM
					CLsrNxA30Ziiq9GKA8KKlFHdAmxuNcH0TzRn
					dpo6bu5nKyJHiREIazHVuPBEzUmHtcWETCDs
					9UVsbji2Z2ozqLz9cqnfYV/kOD+OZBAqvZ0n
					/4lgdSiBtvByLCXoWEYIGRs=
					) ; KSK; alg = RSASHA256 ; key id = 19420
			3600	DNSKEY	257 3 13 (
					hRcbHnvrTqCb215+XsIn96tvHacV5d15lcnS
					h91pg8Htes3H0vOoG98C5oWXoj7RM4V/tDoH
					/0ahiLyRzRnvBA==
					) ; KSK; alg = ECDSAP256SHA256 ; key id = 20197
			3600	RRSIG	DNSKEY 13 2 3600 (
					20601231235959 20201012144147 20197 example.com.
					JLKC5uLW1+JPkOyVcc8D6B6lCC/0FOlak/Qd
					Na6Nb33hi9io1HMFI1eYiG7u7lxWmXsKnBo9
					ONROz+WYGds++Q== )
			3600	CDS	53851 8 2 (
					6F8129D687EC387C948E6F4B0AC9AA01481C
					CEBF7570AFEC582897E7725122D6 )
			3600	RRSIG	CDS 13 2 3600 (
					20601231235959 20201012144147 20197 example.com.
					pgi1+O/TWU6WCmLLYEibCYj+RzbcOuodnF1i
					wlBQxDZLTcGYG+1KEC0spZTN1nQncEfdeEKc
					jnYQUa0izPQRnA== )
			3600	RRSIG	CDS 13 2 3600 (
					20601231235959 20201012144147 25752 example.com.
					MaFyQcB908WIXS+RiLeLXiKdjOo/R6tl9AM/
					6xokhcvRqQzuyQeoH4snUvcht0m5ghz09Km7
					MPN0uzJcXIGg0Q== )
			3600	CDNSKEY	257 3 8 (
					AwEAAcQ1EqTPebcJyUnpxO3Xjx6ehRtsiZYT
					oARoJsJG12XR6Ci9yy4SCCsejtaWIFO4XVfM
					2BHzFWqmABtQHtN7AazXAFMLsrSE4DYbgk5W
					mnQv5Jloi6jhhmmXwr8EOi3HR2jdG0gVq/Ta
					x7ztNNZsflJrs3rZs2TVO00BkyyOkmO35jCN
					bGPUwm5cW1vse137BMa7jAcMyNLPIiQubj1/
					mJcIyzF2duvfpjBTgEmSvNcXqLfYFjK8lG4N
					odQG8AcK0MvWqN4mxW/hK0U9nMSjhCnfzPg5
					tjyqdheWRyhkLGjM/mR7gBhtqoSPMr+2KMJQ
					EHYAd/AP8YgaovS8N1fJyh0=
					) ; KSK; alg = RSASHA256 ; key id = 53851
			3600	RRSIG	CDNSKEY 13 2 3600 (
					20601231235959 20201012144147 20197 example.com.
					Vdo7aYGIByxiC85dyqLKrrNAYYDFBnKXm8uE
					rYSXBMWiQoFHwzvlavyqhUWlEABfvYD0pUrX
					PZ27Hz8rPFCSLQ== )
			3600	RRSIG	CDNSKEY 13 2 3600 (
					20601231235959 20201012144147 25752 example.com.
					9Llt7e4nm8uMLqliT2NZJINmAmLmKDYqjloj
					Q3/wNI4K+J0RUmWpg3f6xODVkKjjuVnwpxkK
					eWV9zqY4jUTAGg== )
dns2.example.com.	3600	IN A	192.0.2.1
			3600	RRSIG	A 13 3 3600 (
					20601231235959 20201012144147 25752 example.com.
					lZSHyLdXGFvoL9fhk26y70ifFwui2A5bpdir
					Su7VhfsnNdLgNuCceRXbYwxQaUyODCl7dcJ9
					UkRzq2eDs0evKQ== )
			7200	NSEC	example.com. A RRSIG NSEC
			7200	RRSIG	NSEC 13 3 7200 (
					20601231235959 20201012144147 25752 example.com.
					dDE1XApt4lZ9u20Z/vXwhJxE27AZJQzKwLkk
					jpwEDVJo6/SdV2smB7s7+qmGnSKhIehVpUFX
					wv3/3YaFxSTifQ== )
