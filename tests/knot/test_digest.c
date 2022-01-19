/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
	knot_dname_txt_storage_t origin_str;
	sscanf(zone_str, "%s", origin_str); // NOTE assuming that first token in zone_str is origin name!

	knot_dname_t *origin = knot_dname_from_str_alloc(origin_str);
	assert(origin != NULL);

	zone_contents_t *cont = zone_contents_new(origin, false);
	assert(cont != NULL);
	knot_dname_free(origin, NULL);

	zcreator_t zc = { cont, true, KNOT_EOK };

	zs_scanner_t sc;
	ok(zs_init(&sc, origin_str, KNOT_CLASS_IN, 3600) == 0 &&
	   zs_set_input_string(&sc, zone_str, strlen(zone_str)) == 0 &&
	   zs_set_processing(&sc, process_data, process_error, &zc) == 0 &&
	   zs_parse_all(&sc) == 0, "zscanner initialization");
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

const char *nsec3_zone = "\
arpa.	86400	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2021051902 1800 900 604800 86400		\n\
arpa.	518400	IN	NS	a.root-servers.net.		\n\
arpa.	518400	IN	NS	b.root-servers.net.		\n\
arpa.	518400	IN	NS	c.root-servers.net.		\n\
arpa.	518400	IN	NS	d.root-servers.net.		\n\
arpa.	518400	IN	NS	e.root-servers.net.		\n\
arpa.	518400	IN	NS	f.root-servers.net.		\n\
arpa.	518400	IN	NS	g.root-servers.net.		\n\
arpa.	518400	IN	NS	h.root-servers.net.		\n\
arpa.	518400	IN	NS	i.root-servers.net.		\n\
arpa.	518400	IN	NS	k.root-servers.net.		\n\
arpa.	518400	IN	NS	l.root-servers.net.		\n\
arpa.	518400	IN	NS	m.root-servers.net.		\n\
arpa.	518400	IN	RRSIG	NS 8 1 518400 20210616170429 20210519170429 29094 arpa. gyq/RdMYEGuTElq9QCbqmZSEUAF3aeBc+MGOMVK0hgmYKfVr8DDrh9UZJy4Ht+24+FHXGgAh8OkW4UbnmiIHQnsSflbQiyHljNYZGX3/H2fUs2FFWAjjAww2iPKuuPUkHgjZZQk0683FQuI9Ium0VK7dXGAvNKFh4Ay4LMjkQ6Y=		\n\
arpa.	86400	IN	RRSIG	SOA 8 1 86400 20210616170429 20210519170429 29094 arpa. BnSptCxxljkkYItDfsphqUzCz4fALNhOqWrLtYx5aDRWAydcG0N7owhGTqy56VBop+lTzYKmlHfO5/bb/fRCYAXkDhsmVEqS00cDYTqpygTJbVB8Xd+ia1tBeF8cqsbngRhigF4y0cts+bkn7Wrvw21j7nhs01KROimudGH08hs=		\n\
arpa.	86400	IN	RRSIG	DNSKEY 8 1 86400 20210616170429 20210519170429 18949 arpa. be6sPsu3+7kzDMkAHDsUM0FSoUhULtajWemX95PIVS4wpiEpVMsvF71YLIGRTzw+GfFI2NgsL/idFbUW2Fo7bZIBhbj8JXyZwvsoxt+cLfSfZtVGllKO1XQn5u7/PGU6U8YRSyzRA+ocpdjKqyohkMmOqiqkM7mOSvchDkcZDiw=		\n\
arpa.	3600	IN	RRSIG	NSEC3PARAM 8 1 3600 20210616170429 20210519170429 29094 arpa. CHmmYN1DJGWraPdMPurcXadDO7ODWoz6gv0B7ln0Gwz5L4Mwb5SEtGAinO5R0T2M4OxQEkN0xhy73VERrZb5FvsxyEGJu0M5S6icvyKkJ1Zq+US5b3FX6MI/bIKu2pI5x7/ubpzWKZJ9itNWBRONBiuBsGT9c3Tb2IreuQWziH0=	\n\
arpa.	86400	IN	RRSIG	TYPE63 8 1 86400 20210616170429 20210519170429 29094 arpa. Aqb9IQoNaga9euw67potZbiQYeyEAqd/zVYhDFxfLNfC4Qf6v7aPxW8Tyl+foNob91/KX5JGcS5tD4pq+G+IV+heLRH57s+moF3C0lsid8oZLqCbctmR/hr0YUQc5+dGQ/iy2erEPZq1W4eLsWX+YlUsQfajb5y4ggp7OMTmRuY=		\n\
arpa.	86400	IN	DNSKEY	256 3 8 AwEAAdMaRW2okM0GrfInisiH9HWsqokdnmeXnJjKUwVQ8dy5sxm0DyCtzNapj54SF4ofgJxYufQCzYoe3Y3WsB6dKW15pTvu6ggqwuTTxvAnkMSHAlMGBE0sybRBIM38WswPcjAXmpITj7Zvgm8qh80dcusK5vwqJhb2CDWHRezUwiIB ;{id = 29094 (zsk), size = 1024b}			\n\
arpa.	86400	IN	DNSKEY	257 3 8 AwEAAdQP1t2ookuQYFNUNGDmLHcoA6LFSImvULaUgChKiIO6Vv5yDyHB0Ng6ZkfHM0586cLcbXNBLj/9u5A4vqzOFj8phzW4WLZREZBLYMcuHhvQdqzuDJ0J5mxmLLis5eNaCwukVm6Zpf/otzCJsx9LyrhQBTyx6FF+h7dbSCvjh7tD ;{id = 18949 (ksk), size = 1024b}			\n\
arpa.	3600	IN	NSEC3PARAM	1 0 1 - 		\n\
arpa.	86400	IN	TYPE63	\\# 54 7876cdfe01019a84145013e13e3de2328868888c65aa46b7381213990f83d496c642d2324029cc852e09bffa38afd8e9197977776591		\n\
0js82oec35lbbc4hl35476cm5icacksf.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. PRVkH4+Nm17QlFgwFLnoqwaiIwWZ4pvscanHdMb6HOKkSxwtDoWAGhZubvYGt/Je735nQkGQPPXW2tkMkJa3D7e6RkX/8AoxcqqXOimC6BlG6LuSL4rSousDlbrulyh87qgIHXkUtrHyYUNAMZMKOjMHo7t5IxwjBO0SGADoglk=	\n\
0js82oec35lbbc4hl35476cm5icacksf.arpa. 86400 IN NSEC3 1 0 1 - 2UB8EN7BK0T6DENIGO3I729IVQVME3VE NS			\n\
2ub8en7bk0t6denigo3i729ivqvme3ve.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. JsSiqDiPs0juQxKEcCKTFvKXzUdvIvCILEzcN79+qAxaiQuulHUxTSMDvrsxm83m9juvoOUYtBlPyZdI9erAfiEkpF71ZIl8iP7AKGgqTeV1C4SHnf2KsFi69qimdLbWeIfFGYEq+54Vj5vF1SrRounvj63avhI/Zf0tTWz11+4=	\n\
2ub8en7bk0t6denigo3i729ivqvme3ve.arpa. 86400 IN NSEC3 1 0 1 - 3MKQ4F9MV3H6JSJNUJ6G31KRJLHKN9KJ NS DS RRSIG		\n\
3mkq4f9mv3h6jsjnuj6g31krjlhkn9kj.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. NAt7ul6uWzK19LyTcxbtfIt0SppVHyVjj4S/j0zxqcOH7gkJwf36+uIsb0lP7QzdYoB7dDeMFKnZfOCjBu+OkXTnOmfdwS5XA5OTM3dpi6g8plVRkcBDoWqz+UtQljD66A2XyuVl5vBmhP3OWe8TnlnA3jrHYO5zneEM/MdsoEE=	\n\
3mkq4f9mv3h6jsjnuj6g31krjlhkn9kj.arpa. 86400 IN NSEC3 1 0 1 - BA4462JFP3IQK2KT4COIMT6532KSV55K NS DS RRSIG		\n\
as112.arpa.	172800	IN	NS	a.iana-servers.net.	\n\
as112.arpa.	172800	IN	NS	b.iana-servers.net.	\n\
as112.arpa.	172800	IN	NS	c.iana-servers.net.	\n\
as112.arpa.	86400	IN	DS	20236 8 1 1307e5595598b25fe2eb07bcef767c9d96c3ecdc				\n\
as112.arpa.	86400	IN	DS	20236 8 2 72c9e5d15accc54a32c8c76fe5944bcbf3aabc2b13dc417609763e57bd89d515	\n\
as112.arpa.	86400	IN	DS	49400 8 1 0236339d6c1fb0fdf6069a9babe455b443fe2f95				\n\
as112.arpa.	86400	IN	DS	49400 8 2 f8e230e43e20e14200e46beb6e0a67ced274790c8c8c169df7fec5fb7dfa321f	\n\
as112.arpa.	86400	IN	DS	53690 8 1 85d712965f3aa6556f40e11ba29c638565444acf				\n\
as112.arpa.	86400	IN	DS	53690 8 2 354c6ef7b8b46a4c87ce6a21f3a9043898e68427ad64d029097ce2a38933b82e	\n\
as112.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. Hs6t8f1s8NCPO1yzQIqCWWpGADwHqTVLCRVJIxMkpiWpDPP8zXxQRFp2BHNQ8jAcsp5w5OwIfIR27+5N7O73/y5qjcjDe6Yyzeh7L/nut0fuOuqne47a6VkuXJHmdilGeNFitAFZ+1iP9KnFVxb3NxNLByemx8mO30jYDw14O4Y=	\n\
ba4462jfp3iqk2kt4coimt6532ksv55k.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. MrpAQuo8eH4CAA2jjsLHGiMJ8DexXMDI7LHzQbX7k5L4oUTtBNoTnKFdxqKdxZoEXvO39GB5s0nD0qgR8g5xFAFfj+pcF2y4GC+LqXqV5N6gXKa23zEEN5mfxSuwnQ/JXw95ct2IuQkuU80MIU0ZdE/FVhSyHnlJYMGE3uB2DyY=	\n\
ba4462jfp3iqk2kt4coimt6532ksv55k.arpa. 86400 IN NSEC3 1 0 1 - C26TIAI64HA5JPB4P8KII6P9JHH3TJFH NS DS RRSIG		\n\
c26tiai64ha5jpb4p8kii6p9jhh3tjfh.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. FSQuCmqKEUtYHqhkXDC8uikAIi5ZpMtS14jeaeWEn6Mip3uP1pFNuSQHgFhX9L20hdbeuOG3ribTqs3d4kz9VQ51g4KqD3uhHMVuQZyzpBJWq4Xwynt9cetvSK0f/kaf/wtAARo9HLkciJTBYiYUmYZVdmknIto4TqDNy2kkMrA=	\n\
c26tiai64ha5jpb4p8kii6p9jhh3tjfh.arpa. 86400 IN NSEC3 1 0 1 - DKAS8UE0E261D6338P2GMF52ALH64LA6 NS DS RRSIG		\n\
dkas8ue0e261d6338p2gmf52alh64la6.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. pPD9lqm6kAoLwagCrQwBWBq4McfrHywg4RkQ20ZjuVcnmopggO6UkjlmYUnBn53Si5eqRY9CwtSEvYjKztXcyXnkwbD1xWExAsYucRYVbUPZmOllulYezphTHi1Qp7fRrhEjb/TCYcBUXvLJfU+S9OeVqefruYnIw3VevMPp518=	\n\
dkas8ue0e261d6338p2gmf52alh64la6.arpa. 86400 IN NSEC3 1 0 1 - EARMJ48JEL1C2RDHIGD36N68U3V8Q1KV NS DS RRSIG		\n\
e164.arpa.	172800	IN	NS	ns3.lacnic.net.			\n\
e164.arpa.	172800	IN	NS	ns3.afrinic.net.		\n\
e164.arpa.	172800	IN	NS	ns4.apnic.net.			\n\
e164.arpa.	172800	IN	NS	pri.authdns.ripe.net.		\n\
e164.arpa.	172800	IN	NS	rirns.arin.net.			\n\
e164.arpa.	86400	IN	DS	46334 8 2 550664875d1121c6edd01f9602577640fed5ad19a749ae1e3fd68476af454578		\n\
e164.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. A07roaG8r7ns0YydNMhaURb741akipIL8UCgRRMAs3BzzneUtXW3EmS50C7vxb5ikH84a39FerXHOetifGTKETjVMtuQmdPw1F8ClHMkWfdRyR5a+lWwosV3fgnSItoekfbggUZop1dZxzie93pv4RM89Jf/SMlOW/3bYJ1p7Hk=	\n\
earmj48jel1c2rdhigd36n68u3v8q1kv.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. yNYXtZ4dGDdJW3VNoLRtktV93mZmQsQv3Tvy6+iBTGx+W7T0ipSCZq+l5yvblfqGKXXnWWzYf/xKktaLmXnAzvdsacWaKGtudvvtSwLkhlxNWlL018Eoe2md0tsSLd5tSiTbufahrd4p1lv09ne//sGoSw/amfvY5hsRvmnhNhA=	\n\
earmj48jel1c2rdhigd36n68u3v8q1kv.arpa. 86400 IN NSEC3 1 0 1 - H2D0RTQ108UOOUB5UDNN9D2PGQBVABC9 NS DS RRSIG			\n\
h2d0rtq108uooub5udnn9d2pgqbvabc9.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. isNpvWJ3TpDmEl66a9J9Q2GdlNqh9HculGjNFVIbiSfTb5aNgCITkgrKSoxjfZ8go3pDSeqwo5fhaBlbZQ4xGNGlc/T5U2qh2hJPGZpBwHYkR9a1YzMhzMx33oRXfMzsuC+6sasS8BLRHPmS4X89jPeA+lItEJPd1rQlHb1wt1I=	\n\
h2d0rtq108uooub5udnn9d2pgqbvabc9.arpa. 86400 IN NSEC3 1 0 1 - KSH70CK6POGI86ENT4ONT3I9UJ71QE8K NS SOA RRSIG DNSKEY NSEC3PARAM TYPE63		\n\
home.arpa.	172800	IN	NS	blackhole-1.iana.org.		\n\
home.arpa.	172800	IN	NS	blackhole-2.iana.org.		\n\
in-addr.arpa.	172800	IN	NS	a.in-addr-servers.arpa.		\n\
in-addr.arpa.	172800	IN	NS	b.in-addr-servers.arpa.		\n\
in-addr.arpa.	172800	IN	NS	c.in-addr-servers.arpa.		\n\
in-addr.arpa.	172800	IN	NS	d.in-addr-servers.arpa.		\n\
in-addr.arpa.	172800	IN	NS	e.in-addr-servers.arpa.		\n\
in-addr.arpa.	172800	IN	NS	f.in-addr-servers.arpa.		\n\
in-addr.arpa.	86400	IN	DS	47054 8 2 5cafccec201d1933b4c9f6a9c8f51e51f3b39979058ac21b8df1b1f281cbc6f2		\n\
in-addr.arpa.	86400	IN	DS	53696 8 2 13e5501c56b20394da921b51412d48b7089c5eb6957a7c58553c4d4d424f04df		\n\
in-addr.arpa.	86400	IN	DS	63982 8 2 aaf4fb5d213ef25ae44679032ebe3514c487d7abd99d7f5fec3383d030733c73		\n\
in-addr.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. lr32Q5rTcwVyBASuYq2Mc1t8XPCSSXJDNtK+MzisWifCZ0b0m/GARo34QKR2y3afqeFdqVXWrYrBVjAF2Rg21izsWqpMNyfLloesNNl63A9uQi4dFT3Zfz3OdQOGhWcy51ydn8KVtieIubRTBQAgExgZsDzyRC4PXjzh4Jj872g=				\n\
in-addr-servers.arpa.	172800	IN	NS	a.in-addr-servers.arpa.	\n\
in-addr-servers.arpa.	172800	IN	NS	b.in-addr-servers.arpa.	\n\
in-addr-servers.arpa.	172800	IN	NS	c.in-addr-servers.arpa.	\n\
in-addr-servers.arpa.	172800	IN	NS	d.in-addr-servers.arpa.	\n\
in-addr-servers.arpa.	172800	IN	NS	e.in-addr-servers.arpa.	\n\
in-addr-servers.arpa.	172800	IN	NS	f.in-addr-servers.arpa.	\n\
in-addr-servers.arpa.	86400	IN	DS	1987 8 2 dacfdeb02a489a514c6408d0d54e0904fe6e09a6e111abc9eacb27f6552805e1	\n\
in-addr-servers.arpa.	86400	IN	DS	45104 8 2 50136f7a8d3ffe4f9887ad234ff8ce945cabd331feb12569b2f61f99ce40fdbf	\n\
in-addr-servers.arpa.	86400	IN	DS	62996 8 2 836537710efc1e5570e3aeff7c0c80d3957a16ddf8005034bc9082898968dc81	\n\
in-addr-servers.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. j+2AVMMc1xfd/ua7lHpNQUr95kUTcr8SIQJk6prTkYnPdDvMNZPIhhdVNw7WzFjIvGLF3iumbYY46I3KN3P1eZUKtn0OFvTZ/UG/tlbWaj473XNxWnbwp8sPuT46nuLH6P14gNEhbPGGrh2VE+hFPkM/4ZdfwlCbDC5vEsQNYko=			\n\
a.in-addr-servers.arpa.	172800	IN	A	199.180.182.53		\n\
a.in-addr-servers.arpa.	172800	IN	AAAA	2620:37:e000::53	\n\
b.in-addr-servers.arpa.	172800	IN	A	199.253.183.183		\n\
b.in-addr-servers.arpa.	172800	IN	AAAA	2001:500:87::87		\n\
c.in-addr-servers.arpa.	172800	IN	A	196.216.169.10		\n\
c.in-addr-servers.arpa.	172800	IN	AAAA	2001:43f8:110::10	\n\
d.in-addr-servers.arpa.	172800	IN	A	200.10.60.53		\n\
d.in-addr-servers.arpa.	172800	IN	AAAA	2001:13c7:7010::53	\n\
e.in-addr-servers.arpa.	172800	IN	A	203.119.86.101		\n\
e.in-addr-servers.arpa.	172800	IN	AAAA	2001:dd8:6::101		\n\
f.in-addr-servers.arpa.	172800	IN	A	193.0.9.1		\n\
f.in-addr-servers.arpa.	172800	IN	AAAA	2001:67c:e0::1		\n\
ip6.arpa.	172800	IN	NS	a.ip6-servers.arpa.		\n\
ip6.arpa.	172800	IN	NS	b.ip6-servers.arpa.		\n\
ip6.arpa.	172800	IN	NS	c.ip6-servers.arpa.		\n\
ip6.arpa.	172800	IN	NS	d.ip6-servers.arpa.		\n\
ip6.arpa.	172800	IN	NS	e.ip6-servers.arpa.		\n\
ip6.arpa.	172800	IN	NS	f.ip6-servers.arpa.		\n\
ip6.arpa.	86400	IN	DS	13880 8 2 068554efcb5861f42af93ef8e79c442a86c16fc5652e6b6d2419ed527f344d17		\n\
ip6.arpa.	86400	IN	DS	45094 8 2 e6b54e0a20ce1edbfcb6879c02f5782059cecb043a31d804a04afa51af01d5fb		\n\
ip6.arpa.	86400	IN	DS	64060 8 2 8a11501086330132be2c23f22dedf0634ad5ff668b4aa1988e172c6a2a4e5f7b		\n\
ip6.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. aNklM0l2ixPusry6KMt0PYGuKgLXqAJArq3KSZgG0QgMjGC0ChVwAO2+vq4wwR8QuqA6vAWHKKpw79l8MYV9I7+a50WPFyEOugl1s+konVjzkgMboPaOZbg52g47mPdQ7Q0N9MPLA8/FJx13cHauimQjZ+1FOiiWhveqgR2Jg8o=				\n\
ip6-servers.arpa.	172800	IN	NS	a.ip6-servers.arpa.	\n\
ip6-servers.arpa.	172800	IN	NS	b.ip6-servers.arpa.	\n\
ip6-servers.arpa.	172800	IN	NS	c.ip6-servers.arpa.	\n\
ip6-servers.arpa.	172800	IN	NS	d.ip6-servers.arpa.	\n\
ip6-servers.arpa.	172800	IN	NS	e.ip6-servers.arpa.	\n\
ip6-servers.arpa.	172800	IN	NS	f.ip6-servers.arpa.	\n\
ip6-servers.arpa.	86400	IN	DS	16169 8 2 27fb5354c3c011c2851ee25ba32929b645d63262779ac101a6f28cd631991269	\n\
ip6-servers.arpa.	86400	IN	DS	19720 8 2 f154d00f5759c274de9cad621910cc0b87d720d35b7de4b0b566e135196c38e2	\n\
ip6-servers.arpa.	86400	IN	DS	54832 8 2 ff0d5f44a086a7a31b99c81cfd1135524b5896878e6de78f12b3f609bf7279dc	\n\
ip6-servers.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. fYShlxJWViKV2SbFCqyxUa64AKAedJ2udqcw/VtKNxg2T6i5IQzFc2aPB7V/+MtE64vHWwbrThgOvNC4Xmc7jVqKNsSc1X4Q8ZSQy+/CgmS5pBkI4XpLBb6kTUJMGorgAOI1ek1OMpl25mGmeJ6lE8e5PTNUisz/7ybIx5pBTz0=			\n\
a.ip6-servers.arpa.	172800	IN	A	199.180.182.53		\n\
a.ip6-servers.arpa.	172800	IN	AAAA	2620:37:e000::53	\n\
b.ip6-servers.arpa.	172800	IN	A	199.253.182.182		\n\
b.ip6-servers.arpa.	172800	IN	AAAA	2001:500:86::86		\n\
c.ip6-servers.arpa.	172800	IN	A	196.216.169.11		\n\
c.ip6-servers.arpa.	172800	IN	AAAA	2001:43f8:110::11	\n\
d.ip6-servers.arpa.	172800	IN	A	200.7.86.53		\n\
d.ip6-servers.arpa.	172800	IN	AAAA	2001:13c7:7012::53	\n\
e.ip6-servers.arpa.	172800	IN	A	203.119.86.101		\n\
e.ip6-servers.arpa.	172800	IN	AAAA	2001:dd8:6::101		\n\
f.ip6-servers.arpa.	172800	IN	A	193.0.9.2		\n\
f.ip6-servers.arpa.	172800	IN	AAAA	2001:67c:e0::2		\n\
ipv4only.arpa.	172800	IN	NS	a.iana-servers.net.		\n\
ipv4only.arpa.	172800	IN	NS	b.iana-servers.net.		\n\
ipv4only.arpa.	172800	IN	NS	c.iana-servers.net.		\n\
ipv4only.arpa.	172800	IN	NS	ns.icann.org.			\n\
iris.arpa.	172800	IN	NS	a.iana-servers.net.		\n\
iris.arpa.	172800	IN	NS	b.iana-servers.net.		\n\
iris.arpa.	172800	IN	NS	c.iana-servers.net.		\n\
iris.arpa.	172800	IN	NS	ns3.lacnic.net.			\n\
iris.arpa.	172800	IN	NS	ns4.apnic.net.			\n\
iris.arpa.	86400	IN	DS	38534 8 2 163416c9dcaf8d1babfec16552ed109029607907ab80b195e1dab40f1792a59c		\n\
iris.arpa.	86400	IN	DS	39464 8 2 1e09a2d6374800d54cfd0e52293906ccf7db7e923dcab7015e4bb697d76d9846		\n\
iris.arpa.	86400	IN	DS	44285 8 2 05cbf77375a8bf5702cf8e261ff947be8c8ab7a0b9485a0241edcfe2f155c7f3		\n\
iris.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. oikOvs9AfaPv1Po/E76SZ7VBoYjqHqzZEzrA0N4gWXlemmsUKyXh9fiXqtusFIZD7QUBJMvOYkIpWnAOliWnk/oj4lmmwnYMqqLWDMWVoXiUAUtmwQHm89cAjyWc9nRuDVBweKtqH5GQKtEWxu4nkKPIbuUVNHBgxtKZP7Jbzic=				\n\
ksh70ck6pogi86ent4ont3i9uj71qe8k.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. YPnC0imYz+x2dNwUQwvp2CB1Ini1dEcn9Vur9T4KwzAMqVr+PPkheMRiIQcAbmkSLG1D1p/qVzaFEC7ixlaxuEFlvGwM+c5OvukbWek1QtdCDJpgtse3HBajoRTgBDGRwvj+DFej9ppygZpe+vlgSDmiC2fgPMhcG4Z6jMmVAec=	\n\
ksh70ck6pogi86ent4ont3i9uj71qe8k.arpa. 86400 IN NSEC3 1 0 1 - MKQDDR5C3MPRP6DRU5TO19BB27TDVCVT NS DS RRSIG			\n\
mkqddr5c3mprp6dru5to19bb27tdvcvt.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. sUTu2ijBQlhCmn/fNl8O+UofW4ERQ0tgmK0LY8ggHCnvY26k4RCrGieZ6YXl8lCereSyx1DEPuScBA7YRCUEw/FtrW8rCKMo+wQhb4Uon2UUZRl/mrjNNsYxtYwjIN7u/BzfDhBHq2/8vVCybAS8GhqqJhOYpEcDgsITuDKVFOE=	\n\
mkqddr5c3mprp6dru5to19bb27tdvcvt.arpa. 86400 IN NSEC3 1 0 1 - SRGGVLP1DI07IJT2IA31AGJRPFCNC616 NS DS RRSIG			\n\
srggvlp1di07ijt2ia31agjrpfcnc616.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. ep49bJfQ1c1dNMIlFO+EgeG4iW7pHyJvKbK6MJBBj/LJwVfhzwTa8ellqgHp3AH63j8tNPutowc1shlQwE7G/f3KfiVBUwPtAZHtqNYBFdNm0WdxoqRueJmyVR0h+vUfY+r1F4IYzwfjn+ldfj5lhKqQ+gX2HFR3M/FI6H97nHQ=	\n\
srggvlp1di07ijt2ia31agjrpfcnc616.arpa. 86400 IN NSEC3 1 0 1 - SSTSS4TF3ICJ43RCMUQTSJORRDDSRSRL NS				\n\
sstss4tf3icj43rcmuqtsjorrddsrsrl.arpa.	86400	IN	RRSIG	NSEC3 8 2 86400 20210616170429 20210519170429 29094 arpa. 0GVjQFd8YAYSXMh526fZ5Rx4WDHIf84MTzIsAYuLwM00H6uagrFxQv8mrGExWPummQ+Q+nHDuCBC5lEXjTF4/1qAu7MI627/mKtpcQevTvF3iE2ocf1/vfAFWVCzyLQ3AuFbGGuYQ6nlZzbOu2oRtma6/m4WpDhNszOhuONNlbY=	\n\
sstss4tf3icj43rcmuqtsjorrddsrsrl.arpa. 86400 IN NSEC3 1 0 1 - 0JS82OEC35LBBC4HL35476CM5ICACKSF NS DS RRSIG			\n\
uri.arpa.	172800	IN	NS	a.iana-servers.net.		\n\
uri.arpa.	172800	IN	NS	b.iana-servers.net.		\n\
uri.arpa.	172800	IN	NS	c.iana-servers.net.		\n\
uri.arpa.	172800	IN	NS	ns3.lacnic.net.			\n\
uri.arpa.	172800	IN	NS	ns4.apnic.net.			\n\
uri.arpa.	86400	IN	DS	15796 8 2 7f8fa18fdd9a826eb08a4d4e9ce94dbba7a5b7b2b3ce1d74afd150242e9f572f		\n\
uri.arpa.	86400	IN	DS	28547 8 2 deaefd0c163175350152da7b127dc7c4f9ec8bdf04ccc02829455df86c5ca035		\n\
uri.arpa.	86400	IN	DS	57851 8 2 8feda13f642ed9be2e4aaa3d50099dd422ca6081b6bf8188f804343b58d39cb7		\n\
uri.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. jwQhmqBE2EWCE2yi14CqgjMfYWq4/W//IuL/EHSRZPJjyP7R7cnUgh/7rDO4JUcYebviO4s9hidjfpnLQWxpR2Jy2SH6aeNERLo76O28UW2Y28eused7aWMDWAnWW4HxURsQSBy2cyQbNwPCLGVLeQZaeZbKRBJUbWJ4MT4UpDE=				\n\
urn.arpa.	172800	IN	NS	a.iana-servers.net.		\n\
urn.arpa.	172800	IN	NS	b.iana-servers.net.		\n\
urn.arpa.	172800	IN	NS	c.iana-servers.net.		\n\
urn.arpa.	172800	IN	NS	ns3.lacnic.net.			\n\
urn.arpa.	172800	IN	NS	ns4.apnic.net.			\n\
urn.arpa.	86400	IN	DS	28996 8 2 8e66d01a1e5864bcdb8e1f85579aec7c8c536c9d6fc7032ee708e869fd27f3d3		\n\
urn.arpa.	86400	IN	DS	34555 8 2 bd743967def1caf0812fe9eff2371d3adf29e27251db272145a5d523c92f7101		\n\
urn.arpa.	86400	IN	DS	45052 8 2 7685b675f93ada412cfe534820c8dcc55654b1711f677ba83a8564c12943f695		\n\
urn.arpa.	86400	IN	RRSIG	DS 8 2 86400 20210616170429 20210519170429 29094 arpa. BHHa1YLYUOABgiloeQQRIMXRKxXNIwRken6E6ETFAWw3Js1ocu6H/X3bcPvBTjID/B+GRGgIyCnDnZ9iWeU41Tw1GnMNT9EM35DmnUgfzUU79shVzRtiYDV6JHF9Kidc90IxNrQOGAcUy0J9jhMa4KYEjfQab8sJSo0M+uJkNMw=";

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

	ret = check_contents(nsec3_zone);
	is_int(KNOT_EOK, ret, "nsec3 zone");

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
