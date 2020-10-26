example.com.		3600	IN SOA	dns2.example.com. hostmaster.example.com. (
					2010135808 ; serial
					10800      ; refresh (3 hours)
					3600       ; retry (1 hour)
					1209600    ; expire (2 weeks)
					7200       ; minimum (2 hours)
					)
			3600	RRSIG	SOA 13 2 3600 (
					20601231235959 20201012144942 8996 example.com.
					ThTlvNtautK64IeJRxNCr5acLrRu8jXkTR3N
					y5TlXrei2DIagbPja++4vLjhUJAcKTGndD+x
					wgMrDpCY6pMAYQ== )
			3600	NS	dns2.example.com.
			3600	RRSIG	NS 13 2 3600 (
					20601231235959 20201012144942 8996 example.com.
					3OJiG3v9Nq9OHkyysT3A6PNPRVn9sYTQkHNS
					6JL5BzLCQ+uYKJBCu0ZPxDlYpbYnO0HKQ7Ta
					iZYCjm7vzqtvwA== )
			3600	MX	10 mail.example.com.
			3600	RRSIG	MX 13 2 3600 (
					20601231235959 20201012144942 8996 example.com.
					9vi3n2cVyr+ghB0ql4Wc8vhpLfAuclopapXw
					BQV328nEwftj0okcPz4Z7Iye9by4X6NDd13x
					vzWXDKjZCSxLJg== )
			7200	NSEC	dns2.example.com. NS SOA MX RRSIG NSEC DNSKEY CDS CDNSKEY
			7200	RRSIG	NSEC 13 2 7200 (
					20601231235959 20201012144942 8996 example.com.
					HP8iIlUO+EKFRgoHUrQWLcaX8oSGEb/tldEP
					GcJKM+rGMeJvxXOJnjSskUm7AyRK1TKK4RqE
					xaOHTgIz1uUkzw== )
			3600	DNSKEY	256 3 8 (
					AwEAAdKraxDdGTL4HDOkXTDI1Md1UdHuYhVw
					YkB+u2umVjTJ1H9Qb2oBryqwXI+gklnuCqrH
					1znkDvzGEAeHRQUCbtKbjmqErTAcRRHW3D+6
					jsOGXzbyGCfbyzRBwsbNCLWr3ONpPi5JOWEe
					CUJfyc/mRXcmh5uYl1JvzAM1zprtljZt
					) ; ZSK; alg = RSASHA256 ; key id = 48849
			3600	DNSKEY	256 3 13 (
					bkP3kBcYNsUB6jpKA764AJeNBzGJjNIRPxDl
					2wK1O7I/bvZDILscWSMUsSRmxZuPWGLjevpp
					Tve1UMe+dP9VIA==
					) ; ZSK; alg = ECDSAP256SHA256 ; key id = 8996
			3600	DNSKEY	257 3 8 (
					AwEAAaulfU2biYVBiUsGwAyCXbA+gm0yWgH2
					Z71S16R2YNERlb0he9Od28DcFd0HbaKdFnw/
					CtX7Z2UWs6/IRu8QmHGn6SKDsLzZ5StdPsJD
					KilfvSlEcQeqrRAncug1SnA5BogNQSD0/02Y
					w5KDGn7ALCSYlNgOgy7l+D/urlkuxgsPWvqY
					XnlxaIcKt96fndwmkfZ5eF+WAqxguaNcvm14
					6NA53wRrWx8BQbcHk1R+WcQGqFcVOlifCs9z
					V+87QJy2H660QKqOVDgt8PF8QmRRJqzOKpu2
					9T+Vd1dM3zjBJ7deLaNH2E5p7Bbp1eeOCeOt
					WpCG6XfaRmZIF3ZWVM6Ways=
					) ; KSK; alg = RSASHA256 ; key id = 56474
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
					1OgEqruDg7pI2dTIRMdP9ihhdl3wFngZW9bP
					E4jMg4ByKKoKM/C1QN4Q+BQiQDkcprwE9vLf
					D/cLgFNspjcBgQ==
					) ; KSK; alg = ECDSAP256SHA256 ; key id = 63865
			3600	RRSIG	DNSKEY 13 2 3600 (
					20601231235959 20201012144942 63865 example.com.
					9d2q8pWH1AftoDmPq3DNblta3oPV+6ROZmVR
					BvjHj7xJjI27aY514C0qNkQVhioe2mhQjikO
					gyxvkWwBV/owPg== )
			3600	CDS	53851 8 2 (
					6F8129D687EC387C948E6F4B0AC9AA01481C
					CEBF7570AFEC582897E7725122D6 )
			3600	CDS	56474 8 2 (
					260E7ADB07D1ECC40DEE79EFF6527CF7119C
					0AFC1CFA5DAC1ADFE342568CF32D )
			3600	RRSIG	CDS 13 2 3600 (
					20601231235959 20201012144942 8996 example.com.
					E7iVsJZjRyGbjMUADsi9Chz74+t1W75zTPmm
					MYVD77dkRHiEpN41MJB6Z7Fn1lNOE6f8q2B5
					iL/3UXULB1vpwA== )
			3600	RRSIG	CDS 13 2 3600 (
					20601231235959 20201012144942 63865 example.com.
					fsMqYcBDcTBtaDEqDTYrHHivnuQKb629drhm
					77RFfBxFJAxlq176PzaddA++zHfWsBgIlJzy
					VHFy3S3huuyfaQ== )
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
					20601231235959 20201012144942 8996 example.com.
					hhpJcQ4cMcq9fLNtZrTEVAMGB2bjMwcDvv4C
					Sss9wWDBNxIVOsi4x3j/08PZTqbfmYePWtK8
					k2R5GOOK1lpVlw== )
			3600	RRSIG	CDNSKEY 13 2 3600 (
					20601231235959 20201012144942 63865 example.com.
					xU82j/dJf8oBd1Ti2lHH0YoxBvgCQo2MOdwJ
					yOc6fDrT/c39rCMT//VoDmmKj3SavQ92ABBt
					18JqxCXK7+tnYQ== )
dns2.example.com.	3600	IN A	192.0.2.1
			3600	RRSIG	A 13 3 3600 (
					20601231235959 20201012144942 8996 example.com.
					D3O6XOYrOT1tlCieJJvw7zys0ClqXcCvs5+D
					qSEpKcE6RNNeJG2d3SJg95fbO+eTkw30MROF
					ajnNh5xJ+8xsMQ== )
			7200	NSEC	example.com. A RRSIG NSEC
			7200	RRSIG	NSEC 13 3 7200 (
					20601231235959 20201012144942 8996 example.com.
					sGBFze6wRGj8n0B8izUNHO2ufA72sR55U3OQ
					RLYTx2XqBRvdmapMKK6QDu/6lmwqgYMbjiBJ
					XqDLv/1RP4DisQ== )
