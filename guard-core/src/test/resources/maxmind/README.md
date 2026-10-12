# MaxMind test database fixture

`GeoIP2-Country-Test.mmdb` comes from MaxMind's Apache-2.0 licensed
MaxMind-DB repository (github.com/maxmind/MaxMind-DB, test-data/), vendored
for the IpInfoManager reader tests; the Apache-2.0 license text ships
alongside this file. The fixture is a TEST RESOURCE: it is never shipped in
any published artifact. Note the GeoIP2 layout nests `country` as an object,
so `MmdbCountryRecord` lookups over it take the lookup-failure arm by
construction (the production format is the flat ipinfo country layout); the
fixture exists to exercise the reader open/refresh/replace lifecycle.
