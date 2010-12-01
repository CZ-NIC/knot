#include <unistd.h>
#include <stdlib.h>
#include "zonec.h"

/* Total errors counter */
long int totalerrors = 0;

int
main (int argc, char **argv)
{
//	struct namedb *db;
//	zdb_database_t *db;
	char *origin = NULL;
	int c;
//	region_type *global_region;
//	region_type *rr_region;
//	const char* configfile= CONFIGFILE;
//	const char* zonesdir = NULL;
	const char* singlefile = NULL;
//	nsd_options_t* nsd_options = NULL;
//
//	log_init("zonec");
//
//	global_region = region_create(xalloc, free);
//	rr_region = region_create(xalloc, free);
//	totalerrors = 0;
//
//	/* Parse the command line... */
	while ((c = getopt(argc, argv, "d:f:vhCF:L:o:c:z:")) != -1) {
		switch (c) {
//		case 'c':
//			configfile = optarg;
//			break;
//		case 'v':
//			++vflag;
//			break;
//		case 'f':
//			dbfile = optarg;
//			break;
//		case 'd':
//			zonesdir = optarg;
//			break;
//		case 'C':
//			configfile = 0;
//			break;
//#ifndef NDEBUG
//		case 'F':
//			sscanf(optarg, "%x", &nsd_debug_facilities);
//			break;
//		case 'L':
//			sscanf(optarg, "%d", &nsd_debug_level);
//			break;
//#endif /* NDEBUG */
		case 'o':
			origin = optarg;
			break;
		case 'z':
			singlefile = optarg;
			break;
//		case 'h':
//			usage();
//			exit(0);
//		case '?':
		default:
//			usage();
			exit(1);
		}
	}
//
//	argc -= optind;
//	argv += optind;
//
//	if (argc != 0) {
//		usage();
//		exit(1);
//	}
//
//	/* Read options */
//	if(configfile != 0) {
//		nsd_options = nsd_options_create(global_region);
//		if(!parse_options_file(nsd_options, configfile))
//		{
//			fprintf(stderr, "zonec: could not read config: %s\n", configfile);
//			exit(1);
//		}
//	}
//	if(nsd_options && zonesdir == 0) zonesdir = nsd_options->zonesdir;
//	if(zonesdir && zonesdir[0]) {
//		if (chdir(zonesdir)) {
//			fprintf(stderr, "zonec: cannot chdir to %s: %s\n", zonesdir, strerror(errno));
//			exit(1);
//		}
//	}
//	if(dbfile == 0) {
//		if(nsd_options && nsd_options->database) dbfile = nsd_options->database;
//		else dbfile = DBFILE;
//	}
//
	/* Create the database */
//	if ((db = zdb_create()) == NULL) {
//		fprintf(stderr, "zonec: error creating the database (%s): %s\n");
//		exit(1);
//	}

	parser = zparser_create();
	if (!parser) {
		fprintf(stderr, "zonec: error creating the parser\n");
		exit(1);
	}
//
//	/* Unique pointers used to mark errors.	 */
//	error_dname = (dname_type *) region_alloc(global_region, 0);
//	error_domain = (domain_type *) region_alloc(global_region, 0);
//
//	if (singlefile || origin) {
//		/*
//		 * Read a single zone file with the specified origin
//		 */
//		if(!singlefile) {
//			fprintf(stderr, "zonec: must have -z zonefile when reading single zone.\n");
//			exit(1);
//		}
//		if(!origin) {
//			fprintf(stderr, "zonec: must have -o origin when reading single zone.\n");
//			exit(1);
//		}
//		if (vflag > 0)
//			fprintf(stdout, "zonec: reading zone \"%s\".\n", origin);
		zone_read(origin, singlefile); //, nsd_options);
//		if (vflag > 0)
//			fprintf(stdout, "zonec: processed %ld RRs in \"%s\".\n", totalrrs, origin);
//	} else {
//		zone_options_t* zone;
//		if(!nsd_options) {
//			fprintf(stderr, "zonec: no zones specified.\n");
//			exit(1);
//		}
//		/* read all zones */
//		RBTREE_FOR(zone, zone_options_t*, nsd_options->zone_options)
//		{
//			if (vflag > 0)
//				fprintf(stdout, "zonec: reading zone \"%s\".\n",
//					zone->name);
//			zone_read(zone->name, zone->zonefile, nsd_options);
//			if (vflag > 0)
//				fprintf(stdout,
//					"zonec: processed %ld RRs in \"%s\".\n",
//					totalrrs, zone->name);
//			totalrrs = 0;
//		}
//	}
//	check_dname(db);
//
//#ifndef NDEBUG
//	if (vflag > 0) {
//		fprintf(stdout, "global_region: ");
//		region_dump_stats(global_region, stdout);
//		fprintf(stdout, "\n");
//		fprintf(stdout, "db->region: ");
//		region_dump_stats(db->region, stdout);
//		fprintf(stdout, "\n");
//	}
//#endif /* NDEBUG */
//
//	/* Close the database */
//	if (namedb_save(db) != 0) {
//		fprintf(stderr, "zonec: error writing the database (%s): %s\n", db->filename, strerror(errno));
//		namedb_discard(db);
//		exit(1);
//	}
//
//	/* Print the total number of errors */
//	if (vflag > 0 || totalerrors > 0) {
//		fprintf(stderr, "\nzonec: done with %ld errors.\n",
//			totalerrors);
//	}
//
//	/* Disable this to save some time.  */
//#if 0
//	region_destroy(global_region);
//#endif
//
	return totalerrors ? 1 : 0;
}
