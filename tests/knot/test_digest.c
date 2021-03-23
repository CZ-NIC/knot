/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot/zone/digest.h"

#include <string.h>
#include <tap/basic.h>

#include "knot/zone/zonefile.h"
#include "libzscanner/scanner.h"

// copy-pasted from knot/zone/zonefile.c
static void process_data(zs_scanner_t *scanner)
{
	zcreator_t *zc = scanner->process.data;
	if (zc->ret != KNOT_EOK) {
		scanner->state = ZS_STATE_STOP;
		return;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (owner == NULL) {
		zc->ret = KNOT_ENOMEM;
		return;
	}

	knot_rrset_t rr;
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class, scanner->r_ttl);

	int ret = knot_rrset_add_rdata(&rr, scanner->r_data, scanner->r_data_length, NULL);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		zc->ret = ret;
		return;
	}

	ret = knot_rrset_rr_to_canonical(&rr);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		zc->ret = ret;
		return;
	}

	zc->ret = zcreator_step(zc, &rr);
	knot_rrset_clear(&rr, NULL);
}

static void process_error(zs_scanner_t *s)
{
	(void)s;
	assert(0);
}

static zone_contents_t *str2contents(const char *zone_str)
{
	char origin_str[KNOT_DNAME_TXT_MAXLEN];
	sscanf(zone_str, "%s", origin_str); // NOTE assuming that first token in zone_str is origin name!

	knot_dname_t *origin = knot_dname_from_str_alloc(origin_str);
	assert(origin != NULL);

	zone_contents_t *cont = zone_contents_new(origin, false);
	assert(cont != NULL);
	knot_dname_free(origin, NULL);

	zcreator_t zc = { cont, true, KNOT_EOK };

	zs_scanner_t sc;
	int ret = zs_init(&sc, origin_str, KNOT_CLASS_IN, 3600);
	assert(ret == 0);

	ret = zs_set_input_string(&sc, zone_str, strlen(zone_str));
	assert(ret == 0);

	ret = zs_set_processing(&sc, process_data, process_error, &zc);
	assert(ret == 0);

	ret = zs_parse_all(&sc);
	assert(ret == 0);

	zs_deinit(&sc);

	return cont;
}

static int check_contents(const char *zone_str)
{
	zone_contents_t *cont = str2contents(zone_str);
	int ret = zone_contents_digest_verify(cont);
	zone_contents_deep_free(cont);
	return ret;
}

const char *simple_zone = "\
example.      86400  IN  SOA     ns1 admin 2018031900 (  \n\
                                 1800 900 604800 86400 ) \n\
              86400  IN  NS      ns1                     \n\
              86400  IN  NS      ns2                     \n\
              86400  IN  ZONEMD  2018031900 1 1 (        \n\
                                 c68090d90a7aed71        \n\
                                 6bc459f9340e3d7c        \n\
                                 1370d4d24b7e2fc3        \n\
                                 a1ddc0b9a87153b9        \n\
                                 a9713b3c9ae5cc27        \n\
                                 777f98b8e730044c )      \n\
ns1           3600   IN  A       203.0.113.63            \n\
ns2           3600   IN  AAAA    2001:db8::63";

const char *complex_zone = "\
example.      86400  IN  SOA     ns1 admin 2018031900 (                 \n\
                                 1800 900 604800 86400 )                \n\
              86400  IN  NS      ns1                                    \n\
              86400  IN  NS      ns2                                    \n\
              86400  IN  ZONEMD  2018031900 1 1 (                       \n\
                                 a3b69bad980a3504                       \n\
                                 e1cffcb0fd6397f9                       \n\
                                 3848071c93151f55                       \n\
                                 2ae2f6b1711d4bd2                       \n\
                                 d8b39808226d7b9d                       \n\
                                 b71e34b72077f8fe )                     \n\
ns1           3600   IN  A       203.0.113.63                           \n\
NS2           3600   IN  AAAA    2001:db8::63                           \n\
occluded.sub  7200   IN  TXT     \"I'm occluded but must be digested\"  \n\
sub           7200   IN  NS      ns1                                    \n\
duplicate     300    IN  TXT     \"I must be digested just once\"       \n\
duplicate     300    IN  TXT     \"I must be digested just once\"       \n\
foo.test.     555    IN  TXT     \"out-of-zone data must be excluded\"  \n\
UPPERCASE     3600   IN  TXT     \"canonicalize uppercase owner names\" \n\
*             777    IN  PTR     dont-forget-about-wildcards            \n\
mail          3600   IN  MX      20 MAIL1                               \n\
mail          3600   IN  MX      10 Mail2.Example.                      \n\
sortme        3600   IN  AAAA    2001:db8::5:61                         \n\
sortme        3600   IN  AAAA    2001:db8::3:62                         \n\
sortme        3600   IN  AAAA    2001:db8::4:63                         \n\
sortme        3600   IN  AAAA    2001:db8::1:65                         \n\
sortme        3600   IN  AAAA    2001:db8::2:64                         \n\
non-apex      900    IN  ZONEMD  2018031900 1 1 (                       \n\
                                 616c6c6f77656420                       \n\
                                 6275742069676e6f                       \n\
                                 7265642e20616c6c                       \n\
                                 6f77656420627574                       \n\
                                 2069676e6f726564                       \n\
                                 2e20616c6c6f7765 )";

const char *multiple_digests = "\
example.      86400  IN  SOA     ns1 admin 2018031900 (                \n\
                                 1800 900 604800 86400 )               \n\
example.      86400  IN  NS      ns1.example.                          \n\
example.      86400  IN  NS      ns2.example.                          \n\
example.      86400  IN  ZONEMD  2018031900 1 1 (                      \n\
                                 62e6cf51b02e54b9                      \n\
                                 b5f967d547ce4313                      \n\
                                 6792901f9f88e637                      \n\
                                 493daaf401c92c27                      \n\
                                 9dd10f0edb1c56f8                      \n\
                                 080211f8480ee306 )                    \n\
example.      86400  IN  ZONEMD  2018031900 1 2 (                      \n\
                                 08cfa1115c7b948c                      \n\
                                 4163a901270395ea                      \n\
                                 226a930cd2cbcf2f                      \n\
                                 a9a5e6eb85f37c8a                      \n\
                                 4e114d884e66f176                      \n\
                                 eab121cb02db7d65                      \n\
                                 2e0cc4827e7a3204                      \n\
                                 f166b47e5613fd27 )                    \n\
example.      86400  IN  ZONEMD  2018031900 1 240 (                    \n\
                                 e2d523f654b9422a                      \n\
                                 96c5a8f44607bbee )                    \n\
example.      86400  IN  ZONEMD  2018031900 241 1 (                    \n\
                                 e1846540e33a9e41                      \n\
                                 89792d18d5d131f6                      \n\
                                 05fc283e )                            \n\
ns1.example.  3600   IN  A       203.0.113.63                          \n\
ns2.example.  86400  IN  TXT     \"This example has multiple digests\" \n\
NS2.EXAMPLE.  3600   IN  AAAA    2001:db8::63";

const char *signed_zone = "\
uri.arpa.	3600 IN SOA	sns.dns.icann.org. noc.dns.icann.org. 2018100702 10800 3600 1209600 3600 \n\
uri.arpa.	3600 IN RRSIG	SOA 8 2 3600 20210217232440 20210120232440 37444 uri.arpa. GzQw+QzwLDJr13REPGVmpEChjD1D2XlX0ie1DnWHpgaEw1E/dhs3lCN3 +BmHd4Kx3tffTRgiyq65HxR6feQ5v7VmAifjyXUYB1DZur1eP5q0Ms2y gCB3byoeMgCNsFS1oKZ2LdzNBRpy3oace8xQn1SpmHGfyrsgg+WbHKCT 1dY= \n\
uri.arpa.	86400 IN NS	a.iana-servers.net. \n\
uri.arpa.	86400 IN NS	b.iana-servers.net. \n\
uri.arpa.	86400 IN NS	c.iana-servers.net. \n\
uri.arpa.	86400 IN NS	ns2.lacnic.net. \n\
uri.arpa.	86400 IN NS	sec3.apnic.net. \n\
uri.arpa.	86400 IN RRSIG	NS 8 2 86400 20210217232440 20210120232440 37444 uri.arpa. M+Iei2lcewWGaMtkPlrhM9FpUAHXFkCHTVpeyrjxjEONeNgKtHZor5e4 V4qJBOzNqo8go/qJpWlFBm+T5Hn3asaBZVstFIYky38/C8UeRLPKq1hT THARYUlFrexr5fMtSUAVOgOQPSBfH3xBq/BgSccTdRb9clD+HE7djpqr LS4= \n\
uri.arpa.	600 IN MX	10 pechora.icann.org. \n\
uri.arpa.	600 IN RRSIG	MX 8 2 600 20210217232440 20210120232440 37444 uri.arpa. kQAJQivmv6A5hqYBK8h6Z13ESY69gmosXwKI6WE09I8RFetfrxr24ecd nYd0lpnDtgNNSoHkYRSOoB+C4+zuJsoyAAzGo9uoWMWj97/2xeGhf3PT C9meQ9Ohi6hul9By7OR76XYmGhdWX8PBi60RUmZ1guslFBfQ8izwPqzu phs= \n\
uri.arpa.	3600 IN NSEC	ftp.uri.arpa. NS SOA MX RRSIG NSEC DNSKEY ZONEMD \n\
uri.arpa.	3600 IN RRSIG	NSEC 8 2 3600 20210217232440 20210120232440 37444 uri.arpa. dU/rXLM/naWd1+1PiWiYVaNJyCkiuyZJSccr91pJI673T8r3685B4ODM YFafZRboVgwnl3ZrXddY6xOhZL3n9V9nxXZwjLJ2HJUojFoKcXTlpnUy YUYvVQ2kj4GHAo6fcGCEp5QFJ2KbCpeJoS+PhKGRRx28icCiNT4/uXQv O2E= \n\
uri.arpa.	3600 IN DNSKEY	256 3 8 AwEAAbMxuFuLeVDuOwIMzYOTD/bTREjLflo7wOi6ieIJhqltEzgjNzmW Jf9kGwwDmzxU7kbthMEhBNBZNn84zmcyRSCMzuStWveL7xmqqUlE3swL 8kLOvdZvc75XnmpHrk3ndTyEb6eZM7slh2C63Oh6K8VR5VkiZAkEGg0u ZIT3NjsF \n\
uri.arpa.	3600 IN DNSKEY	257 3 8 AwEAAdkTaWkZtZuRh7/OobBUFxM+ytTst+bCu0r9w+rEwXD7GbDs0pIM hMenrZzoAvmv1fQxw2MGs6Ri6yPKfNULcFOSt9l8i6BVBLI+SKTY6XXe DUQpSEmSaxohHeRPMQFzpysfjxINp/L2rGtZ7yPmxY/XRiFPSO0myqwG Ja9r06Zw9CHM5UDHKWV/E+zxPFq/I7CfPbrrzbUotBX7Z6Vh3Sarllbe 8cGUB2UFNaTRgwB0TwDBPRD5ER3w2Dzbry9NhbElTr7vVfhaGWeOGuqA UXwlXEg6CrNkmJXJ2F1Rzr9WHUzhp7uWxhAbmJREGfi2dEyPAbUAyCjB qhFaqglknvc= \n\
uri.arpa.	3600 IN DNSKEY	257 3 8 AwEAAenQaBoFmDmvRT+/H5oNbm0Tr5FmNRNDEun0Jpj/ELkzeUrTWhNp QmZeIMC8I0kZ185tEvOnRvn8OvV39B17QIdrvvKGIh2HlgeDRCLolhao jfn2QM0DStjF/WWHpxJOmE6CIuvhqYEU37yoJscGAPpPVPzNvnL1HhYT aao1VRYWQ/maMrJ+bfHg+YX1N6M/8MnRjIKBif1FWjbCKvsn6dnuGGL9 oCWYUFJ3DwofXuhgPyZMkzPc88YkJj5EMvbMH4wtelbCwC+ivx732l0w /rXJn0ciQSOgoeVvDio8dIJmWQITWQAuP+q/ZHFEFHPlrP3gvQh5mcVS 48eLX71Bq7c= \n\
uri.arpa.	3600 IN RRSIG	DNSKEY 8 2 3600 20210217232440 20210120232440 12670 uri.arpa. DBE2gkKAoxJCfz47KKxzoImN/0AKArhIVHE7TyTwy0DdRPo44V5R+vL6 thUxlQ1CJi2Rw0jwAXymx5Y3Q873pOEllH+4bJoIT4dmoBmPXfYWW7Cl vw9UPKHRP0igKHmCVwIeBYDTU3gfLcMTbR4nEWPDN0GxlL1Mf7ITaC2I oabo79Ip3M/MR8I3Vx/xZ4ZKKPHtLn3xUuJluPNanqJrED2gTslL2xWZ 1tqjsAjJv7JnJo2HJ8XVRB5zBto0IaJ2oBlqcjdcQ/0VlyoM8uOy1pDw HQ2BJl7322gNMHBP9HSiUPIOaIDNUCwW8eUcW6DIUk+s9u3GN1uTqwWz sYB/rA== \n\
uri.arpa.	3600 IN RRSIG	DNSKEY 8 2 3600 20210217232440 20210120232440 30577 uri.arpa. Kx6HwP4UlkGc1UZ7SERXtQjPajOF4iUvkwDj7MEG1xbQFB1KoJiEb/ei W0qmSWdIhMDv8myhgauejRLyJxwxz8HDRV4xOeHWnRGfWBk4XGYwkejV zOHzoIArVdUVRbr2JKigcTOoyFN+uu52cNB7hRYu7dH5y1hlc6UbOnzR pMtGxcgVyKQ+/ARbIqGG3pegdEOvV49wTPWEiyY65P2urqhvnRg5ok/j zwAdMx4XGshiib7Ojq0sRVl2ZIzj4rFgY/qsSO8SEXEhMo2VuSkoJNio fVzYoqpxEeGnANkIT7Tx2xJL1BWyJxyc7E8Wr2QSgCcc+rYL6IkHDtJG Hy7TaQ== \n\
uri.arpa.	3600 IN ZONEMD	2018100702 1 1 0DBC3C4DBFD75777C12CA19C337854B1577799901307C482E9D91D5D 15CD934D16319D98E30C4201CF25A1D5A0254960 \n\
uri.arpa.	3600 IN RRSIG	ZONEMD 8 2 3600 20210217232440 20210120232440 37444 uri.arpa. QDo4XZcL3HMyn8aAHyCUsu/Tqj4Gkth8xY1EqByOb8XOTwVtA4ZNQORE 1siqNqjtJUbeJPtJSbLNqCL7rCq0CzNNnBscv6IIf4gnqJZjlGtHO30o hXtKvEc4z7SU3IASsi6bB3nLmEAyERdYSeU6UBfx8vatQDIRhkgEnnWU Th4= \n\
ftp.uri.arpa.	604800 IN	NAPTR	0 0 \"\" \"\" \"!^ftp://([^:/?#]*).*$!\\\\1!i\" . \n\
ftp.uri.arpa.	604800 IN	RRSIG	NAPTR 8 3 604800 20210217232440 20210120232440 37444 uri.arpa. EygekDgl+Lyyq4NMSEpPyOrOywYf9Y3FAB4v1DT44J3R5QGidaH8l7ZF jHoYFI8sY64iYOCV4sBnX/dh6C1L5NgpY+8l5065Xu3vvjyzbtuJ2k6Y YwJrrCbvl5DDn53zAhhO2hL9uLgyLraZGi9i7TFGd0sm3zNyUF/EVL0C cxU= \n\
ftp.uri.arpa.	3600 IN NSEC	http.uri.arpa. NAPTR RRSIG NSEC \n\
ftp.uri.arpa.	3600 IN RRSIG	NSEC 8 3 3600 20210217232440 20210120232440 37444 uri.arpa. pbP4KxevPXCu/bDqcvXiuBppXyFEmtHyiy0eAN5gS7mi6mp9Z9bWFjx/ LdH9+6oFGYa5vGmJ5itu/4EDMe8iQeZbI8yrpM4TquB7RR/MGfBnTd8S +sjyQtlRYG7yqEu77Vd78Fme22BKPJ+MVqjS0JHMUE/YUGomPkAjLJJw wGw= \n\
http.uri.arpa.	604800 IN	NAPTR	0 0 \"\" \"\" \"!^http://([^:/?#]*).*$!\\\\1!i\" . \n\
http.uri.arpa.	604800 IN	RRSIG	NAPTR 8 3 604800 20210217232440 20210120232440 37444 uri.arpa. eTqbWvt1GvTeXozuvm4ebaAfkXFQKrtdu0cEiExto80sHIiCbO0WL8UD a/J3cDivtQca7LgUbOb6c17NESsrsVkc6zNPx5RK2tG7ZQYmhYmtqtfg 1oU5BRdHZ5TyqIXcHlw9Blo2pir1Y9IQgshhD7UOGkbkEmvB1Lrd0aHh AAg= \n\
http.uri.arpa.	3600 IN NSEC	mailto.uri.arpa. NAPTR RRSIG NSEC \n\
http.uri.arpa.	3600 IN RRSIG	NSEC 8 3 3600 20210217232440 20210120232440 37444 uri.arpa. R9rlNzw1CVz2N08q6DhULzcsuUm0UKcPaGAWEU40tr81jEDHsFHNM+kh CdOI8nDstzA42aee4rwCEgijxJpRCcY9hrO1Ysrrr2fdqNz60JikMdar vU5O0p0VXeaaJDfJQT44+o+YXaBwI7Qod3FTMx7aRib8i7istvPm1Rr7 ixA= \n\
mailto.uri.arpa. 604800 IN	NAPTR	0 0 \"\" \"\" \"!^mailto:(.*)@(.*)$!\\\\2!i\" . \n\
mailto.uri.arpa. 604800 IN	RRSIG	NAPTR 8 3 604800 20210217232440 20210120232440 37444 uri.arpa. Ch2zTG2F1plEvQPyIH4Yd80XXLjXOPvMbiqDjpJBcnCJsV8QF7kr0wTL nUT3dB+asQudOjPyzaHGwFlMzmrrAsszN4XAMJ6htDtFJdsgTMP/NkHh YRSmVv6rLeAhd+mVfObY12M//b/GGVTjeUI/gJaLW0fLVZxr1Fp5U5CR jyw= \n\
mailto.uri.arpa. 3600 IN NSEC	urn.uri.arpa. NAPTR RRSIG NSEC \n\
mailto.uri.arpa. 3600 IN RRSIG	NSEC 8 3 3600 20210217232440 20210120232440 37444 uri.arpa. fQUbSIE6E7JDi2rosah4SpCOTrKufeszFyj5YEavbQuYlQ5cNFvtm8Ku E2xXMRgRI4RGvM2leVqcoDw5hS3m2pOJLxH8l2WE72YjYvWhvnwc5Rof e/8yB/vaSK9WCnqN8y2q6Vmy73AGP0fuiwmuBra7LlkOiqmyx3amSFiz wms= \n\
urn.uri.arpa.	604800 IN	NAPTR	0 0 \"\" \"\" \"/urn:([^:]+)/\\\\1/i\" . \n\
urn.uri.arpa.	604800 IN	RRSIG	NAPTR 8 3 604800 20210217232440 20210120232440 37444 uri.arpa. CVt2Tgz0e5ZmaSXqRfNys/8OtVCk9nfP0zhezhN8Bo6MDt6yyKZ2kEEW JPjkN7PCYHjO8fGjnUn0AHZI2qBNv7PKHcpR42VY03q927q85a65weOO 1YE0vPYMzACpua9TOtfNnynM2Ws0uN9URxUyvYkXBdqOC81N3sx1dVEL cwc= \n\
urn.uri.arpa.	3600 IN NSEC	uri.arpa. NAPTR RRSIG NSEC \n\
urn.uri.arpa.	3600 IN RRSIG	NSEC 8 3 3600 20210217232440 20210120232440 37444 uri.arpa. JuKkMiC3/j9iM3V8/izcouXWAVGnSZjkOgEgFPhutMqoylQNRcSkbEZQ zFK8B/PIVdzZF0Y5xkO6zaKQjOzz6OkSaNPIo1a7Vyyl3wDY/uLCRRAH RJfpknuY7O+AUNXvVVIEYJqZggd4kl/Rjh1GTzPYZTRrVi5eQidI1LqC Oeg=";

const char *no_zonemd = "\
example.      86400  IN  SOA     ns1 admin 2018031900 (  \n\
                                 1800 900 604800 86400 ) \n\
              86400  IN  NS      ns1                     \n\
              86400  IN  NS      ns2                     \n\
ns1           3600   IN  A       203.0.113.63            \n\
ns2           3600   IN  AAAA    2001:db8::63";

const char *wrong_soa = "\
example.      86400  IN  SOA     ns1 admin 2018031900 (  \n\
                                 1800 900 604800 86400 ) \n\
              86400  IN  NS      ns1                     \n\
              86400  IN  NS      ns2                     \n\
              86400  IN  ZONEMD  2018031901 1 1 (        \n\
                                 c68090d90a7aed71        \n\
                                 6bc459f9340e3d7c        \n\
                                 1370d4d24b7e2fc3        \n\
                                 a1ddc0b9a87153b9        \n\
                                 a9713b3c9ae5cc27        \n\
                                 777f98b8e730044c )      \n\
ns1           3600   IN  A       203.0.113.63            \n\
ns2           3600   IN  AAAA    2001:db8::63";

const char *duplicate_schemalg = "\
example.      86400  IN  SOA     ns1 admin 2018031900 (  \n\
                                 1800 900 604800 86400 ) \n\
              86400  IN  NS      ns1                     \n\
              86400  IN  NS      ns2                     \n\
              86400  IN  ZONEMD  2018031900 1 1 (        \n\
                                 c68090d90a7aed71        \n\
                                 6bc459f9340e3d7c        \n\
                                 1370d4d24b7e2fc3        \n\
                                 a1ddc0b9a87153b9        \n\
                                 a9713b3c9ae5cc27        \n\
                                 777f98b8e730044c )      \n\
              86400  IN  ZONEMD  2018031901 1 1 (        \n\
                                 c68090d90a7aed71        \n\
                                 6bc459f9340e3d7c        \n\
                                 1370d4d24b7e2fc3        \n\
                                 a1ddc0b9a87153b9        \n\
                                 a9713b3c9ae5cc27        \n\
                                 777f98b8e730044c )      \n\
ns1           3600   IN  A       203.0.113.63            \n\
ns2           3600   IN  AAAA    2001:db8::63";

const char *wrong_hash = "\
example.      86400  IN  SOA     ns1 admin 2018031900 (  \n\
                                 1800 900 604800 86400 ) \n\
              86400  IN  NS      ns1                     \n\
              86400  IN  NS      ns2                     \n\
              86400  IN  ZONEMD  2018031900 1 1 (        \n\
                                 c68090d90a7aed71        \n\
                                 6bc459f9340e3d7c        \n\
                                 1370d4d24b7e2fc3        \n\
                                 a1ddc0b9a87153b9        \n\
                                 a9713b3c9ae5cc27        \n\
                                 777f98b8e730044d )      \n\
ns1           3600   IN  A       203.0.113.63            \n\
ns2           3600   IN  AAAA    2001:db8::63";

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret = check_contents(simple_zone);
	is_int(KNOT_EOK, ret, "simple zone");

	ret = check_contents(complex_zone);
	is_int(KNOT_EOK, ret, "complex zone");

	ret = check_contents(multiple_digests);
	is_int(KNOT_EOK, ret, "multiple digests");

	ret = check_contents(signed_zone);
	is_int(KNOT_EOK, ret, "signed zone");

	ret = check_contents(no_zonemd);
	is_int(KNOT_ENOENT, ret, "no zonemd");

	ret = check_contents(wrong_soa);
	is_int(KNOT_ENOTSUP, ret, "wrong SOA serial");
	// TODO tests for different scheme / algorithm ?

	ret = check_contents(duplicate_schemalg);
	is_int(KNOT_ESEMCHECK, ret, "duplicate scheme+algorithm pair");

	ret = check_contents(wrong_hash);
	is_int(KNOT_EMALF, ret, "wrong hash");

	return 0;
}
