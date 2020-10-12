example.com.		3600	IN SOA	dns2.example.com. hostmaster.example.com. (
					2010135808 ; serial
					10800      ; refresh (3 hours)
					3600       ; retry (1 hour)
					1209600    ; expire (2 weeks)
					7200       ; minimum (2 hours)
					)
			3600	RRSIG	SOA 13 2 3600 (
					20601231235959 20201012144646 56106 example.com.
					1CRyeUic9BIwBWcjk95VQJktQng6f3dLQm64
					JwGGqivUM3Hgp7URguNIx0BsCvfo67NIpk7N
					mMIFwMkMGOHmgg== )
			3600	NS	dns2.example.com.
			3600	RRSIG	NS 13 2 3600 (
					20601231235959 20201012144646 56106 example.com.
					pB4+Z3ltuzY+/NkAeCb9LOS7Zlh7QLfHKimR
					JPtvdOuIhd8vB0NZLzcYX0lIkrqyP3LadbrS
					u8r9BMIlu4cKpg== )
			3600	MX	10 mail.example.com.
			3600	RRSIG	MX 13 2 3600 (
					20601231235959 20201012144646 56106 example.com.
					x8XhP7r3/glI7AenoSLVmfqhZXQfj6YllgxA
					jkVxExiM9OJZOPdyeDTuRyUD1PFiBOEsP7Wu
					vNgWA9eyQFOslA== )
			7200	NSEC	dns2.example.com. NS SOA MX RRSIG NSEC DNSKEY CDS CDNSKEY
			7200	RRSIG	NSEC 13 2 7200 (
					20601231235959 20201012144646 56106 example.com.
					TCn7V7sHR2TNY5ywyEpbYZMegZwTX+I/TPeO
					76D3WORu9pN0kJWjGPAebwTvL/a7p8xS8B9U
					X9ivUVFORG+mJA== )
			3600	DNSKEY	256 3 8 (
					AwEAAdKraxDdGTL4HDOkXTDI1Md1UdHuYhVw
					YkB+u2umVjTJ1H9Qb2oBryqwXI+gklnuCqrH
					1znkDvzGEAeHRQUCbtKbjmqErTAcRRHW3D+6
					jsOGXzbyGCfbyzRBwsbNCLWr3ONpPi5JOWEe
					CUJfyc/mRXcmh5uYl1JvzAM1zprtljZt
					) ; ZSK; alg = RSASHA256 ; key id = 48849
			3600	DNSKEY	256 3 13 (
					cOjtacSzGkoh6bO4clqYPM2y+g5ezQUtCNdx
					iRqickHCvQnL9OM/h7V8txqEsSulG5ZCeW+O
					LDhDQDUchpNv7A==
					) ; ZSK; alg = ECDSAP256SHA256 ; key id = 56106
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
					pB2mCNXFJ8e+UaMeMmy1LSCv6TJ92Fs3kFxY
					I8NyZPyGvfePpMlzWZr7Bw7wS6G6Jhayhj94
					MMJ4lM/5+ZzVJw==
					) ; KSK; alg = ECDSAP256SHA256 ; key id = 45911
			3600	RRSIG	DNSKEY 13 2 3600 (
					20601231235959 20201012144646 45911 example.com.
					uOAPEzDkPNI9Uo2N+iiRkIb2p1Y0VhgqwUom
					+Dssd6X0CEdQEmD8YQ43Cuq9ZNwk8Bm+lgm3
					X+ImdIKeE4MvNQ== )
			3600	CDS	0 0 0 (
					01 )
			3600	RRSIG	CDS 13 2 3600 (
					20601231235959 20201012144646 45911 example.com.
					IN5tLpm7OKjIL4VpucR1ero1Gv5UEyVqjzB9
					rRJefwUtlZFKNaTbU0oQD33vQXEjUiIMr66b
					zIC3Ju/YtYFDLg== )
			3600	RRSIG	CDS 13 2 3600 (
					20601231235959 20201012144646 56106 example.com.
					f8VJa9GRwSWNmg0AR4nA3OD4X8im7BriZjME
					2ypYUOJkdIafolyb0LDz7XWTaVsFHQWO0z+J
					14g0CgCroTm3pQ== )
			3600	CDNSKEY	0 3 0 (
					AA==
					) ; ZSK; alg = 0 ; key id = 768
			3600	RRSIG	CDNSKEY 13 2 3600 (
					20601231235959 20201012144646 45911 example.com.
					89oeIQuH82i2RYIj/fnX/71s8kspDHcI8lIa
					R02OZZ9bF37bi6LbGkypdXpmxN9/rEjk4ThF
					IHRX2USEPtl+wQ== )
			3600	RRSIG	CDNSKEY 13 2 3600 (
					20601231235959 20201012144646 56106 example.com.
					Hgf4SgtoV0IHsF6feSP8YqeibPTtwZelLpLs
					hux/D94MFKtYa6OseyzT3qIDdixav+mlI2ud
					0JyflYZ6MCBlxg== )
dns2.example.com.	3600	IN A	192.0.2.1
			3600	RRSIG	A 13 3 3600 (
					20601231235959 20201012144646 56106 example.com.
					XdhVQ3Na3LsvdtT2HwdsM3ItiD3UH0HO6TZD
					W6/jy8r0NA6fTN4b4oVr6wSqHAQIQVYUbWER
					7pav2Ek03LDa0Q== )
			7200	NSEC	example.com. A RRSIG NSEC
			7200	RRSIG	NSEC 13 3 7200 (
					20601231235959 20201012144646 56106 example.com.
					dVTxTNAfZy5sa0SW8eme+KMx3hByBnPIrRlF
					zGDsGN1Xzw3OBhsTmuOwhbnZSnnvdBrhBOJw
					8eU/6zpcZypyFQ== )
