#pragma once

enum redis_event {
        ZONE_CREATED,
        ZONE_UPDATED,
        ZONE_PURGED,
        RRSET_UPDATED
};