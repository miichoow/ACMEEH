# High-availability deployment templates

Production templates for the three-node design described in [`docs/ha-postgres.rst`](../../docs/ha-postgres.rst):
Patroni + etcd + HAProxy in front of PostgreSQL, ACMEEH on every node, a load balancer in front.

Replace every `<PLACEHOLDER>`; each file says which lines differ from one node to the next.

| File | Goes to | Status |
|------|---------|--------|
| `etcd.conf.yml` | `/etc/etcd/etcd.conf.yml` (each node) | TLS + client-certificate auth validated on the test cluster |
| `patroni.yml` | `/etc/patroni/patroni.yml` (each node) | Validated on the test cluster except the **watchdog** and **pgBackRest** parts |
| `systemd/patroni.service` | `/etc/systemd/system/` | Adapted from Patroni's reference unit; **not exercised** (the test cluster uses containers) |
| `haproxy-db.cfg`, `systemd/haproxy-db.service` | each node | Config validated on the test cluster; unit **not exercised** |
| `haproxy-lb.cfg` | load balancer(s) | Validated on the test cluster (settings are the tuned part) |
| `keepalived.conf` | load balancer(s), optional | **Not validated** (VRRP does not run on the test cluster) |
| `systemd/acmeeh.service` | each node | **Not exercised** as a unit; behaviour it relies on validated |
| `pgbackrest.conf`, `pgbackrest-cron.sh` | each node | Backup, point-in-time restore and a full disaster-recovery drill validated on the test cluster (`pgbackrest-cron.sh` itself and S3 repositories not exercised) |
| `../../examples/ha-patroni.yaml` | `/etc/acmeeh/config.yaml` (each node) | Validated on the test cluster (same settings) |

"Not exercised" means it was written from the product documentation but never run in this
project's test cluster. Run the validation plan in the guide on your servers before relying on it.
