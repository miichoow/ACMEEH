=====================================
High Availability with PostgreSQL
=====================================

*A three-node production design: Patroni + etcd + HAProxy, TLS everywhere, validated with a real ACME client*

.. contents::
   :local:
   :depth: 2

Summary
=======

ACMEEH keeps all of its state in PostgreSQL, so making ACMEEH highly available means making
PostgreSQL highly available **and** keeping the ACMEEH instances from tripping over each other
during a failover.  This guide describes a design that was built, load-tested and attacked in a
test cluster, together with the production configuration, procedures and acceptance tests that go with it.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Requirement
     - Result of the design
   * - Servers
     - 3 identical servers (VMs are fine). Each one runs PostgreSQL, etcd, a local HAProxy and an
       ACMEEH instance.  One more component, a load balancer, sits in front.
   * - Acknowledged writes lost on failover
     - **None** in every scenario tested (quorum synchronous replication).
   * - Planned switchover
     - About 5 s without database writes; ACME clients see no error or one retried request.
   * - Crash of the primary (process or server)
     - 25 to 40 s without database writes (bounded by Patroni's ``ttl``); a real ACME client
       (lego) rode through it, issuances that straddled the outage taking 30-90 s.
   * - Loss of a standby node
     - No interruption (writes continue on the remaining quorum).
   * - Loss of one ACMEEH instance
     - Transparent: the load balancer routes around it.
   * - Encryption
     - Clients to load balancer, ACMEEH to PostgreSQL (``verify-full``), PostgreSQL replication,
       Patroni REST API and etcd are all TLS; nothing travels in clear text.

The measured figures are in `Validation results`_; **they come from a test cluster on one machine and must
be re-measured on your servers** with the plan in `Validation plan for your servers`_.

Architecture
============

.. code-block:: text

                         ACME clients (certbot, lego, acme.sh, Caddy, ...)
                                          |  HTTPS :443
                              +-----------v-----------+
                              |     load balancer     |   terminates TLS, GET /readyz health check
                              +-----+-----+-----+-----+
                                    |     |     |         HTTP :8443 (private network)
        +---------------------------+     |     +---------------------------+
        |                                 |                                 |
   +----v-----------------+       +-------v--------------+       +----------v-----------+
   | node 1               |       | node 2               |       | node 3               |
   |  ACMEEH              |       |  ACMEEH              |       |  ACMEEH              |
   |   | 127.0.0.1:5000   |       |   | 127.0.0.1:5000   |       |   | 127.0.0.1:5000   |
   |  HAProxy ------------+---+   |  HAProxy ------------+---+   |  HAProxy ------------+---+
   |  PostgreSQL+Patroni  |   |   |  PostgreSQL+Patroni  |   |   |  PostgreSQL+Patroni  |   |
   |  etcd                |   |   |  etcd                |   |   |  etcd                |   |
   +----------------------+   |   +----------------------+   |   +----------------------+   |
                              +--> every HAProxy follows the same primary, wherever it runs <+

.. list-table::
   :header-rows: 1
   :widths: 18 32 50

   * - Component
     - Role
     - Why it is needed
   * - PostgreSQL 16
     - Stores everything ACMEEH knows.  One **primary** accepts writes; two **standbys** replicate
       it.
     - ACMEEH needs a single writable database (see the next section).
   * - Patroni 4.x
     - Supervises PostgreSQL on each node: starts it, promotes a standby when the primary fails,
       reconfigures replication, resynchronises a former primary (``pg_rewind``).
     - PostgreSQL replicates data but cannot decide by itself who the primary is.
   * - etcd 3.5
     - Small distributed key-value store holding the "who is the leader" lock.  Majority (2 of 3)
       required.
     - The lock is what prevents two primaries (split-brain): a node that cannot reach the
       majority must stop being primary.
   * - HAProxy (local)
     - Listens on ``127.0.0.1:5000`` and forwards to whichever node Patroni says is primary.
       Cuts the sessions of a node that stops being primary.
     - ACMEEH takes one database host; this keeps the cluster topology out of its configuration.
   * - ACMEEH
     - The ACME server (gunicorn).  Stateless apart from its configuration and CA key files.
     - Active on all three nodes at the same time.
   * - Load balancer
     - Terminates TLS and spreads clients across the ACMEEH instances.
     - ACME clients require HTTPS; one entry point, health-checked.

What ACMEEH requires from the database tier
===========================================

These constraints come from reading the ACMEEH code, not from the project documentation, and they
decide which database topologies are valid.

.. list-table::
   :header-rows: 1
   :widths: 40 35 25

   * - Behaviour of ACMEEH
     - Where
     - Consequence
   * - Background workers (challenges, cleanup, expiration) and the CRL cache take a **session-level
       advisory lock** (``pg_try_advisory_lock``) around each cycle.
     - ``db/init.py``, ``ca/crl.py``
     - One writable primary only.  **No multi-master**, and **no connection pooler in transaction
       mode** (PgBouncer ``pool_mode=transaction``): the lock would be released on another
       session.  The lock gives **mutual exclusion**, not deduplication: measured with three
       single-process instances and a 20 s task interval, each instance ran every task on its own
       schedule (36 ``nonce_gc`` runs in four minutes across the cluster, against 12 for a single
       runner).  Each gunicorn worker process behaves the same, so a task runs *nodes x workers*
       times per interval.  The tasks are idempotent or deduplicated in the database (expiration
       notices, per-challenge claims, CRL cache), so this costs database load, not correctness.
   * - Replay nonces are consumed with ``DELETE ... RETURNING``.
     - ``repositories/nonce.py``
     - Two writable nodes would each accept the same nonce: anti-replay protection lost.
   * - Certificate serial numbers come from a PostgreSQL sequence (``serial_source: database``).
     - ``services/certificate.py``
     - With asynchronous replication a failover can hand out a serial again.  Use **synchronous
       replication**.  (A unique index on ``serial_number`` turns a duplicate into an error
       rather than a silent duplicate.)
   * - ``database.host`` is a single host; libpq multi-host is not exposed.
     - ``config/schema.json``
     - Put a local HAProxy in front (this design).
   * - Each gunicorn worker process owns its own connection pool.
     - ``db/init.py``
     - PostgreSQL sees up to *nodes x workers x* ``database.max_connections`` connections.
   * - State outside PostgreSQL: the YAML configuration, the CA key and certificate files (internal
       backend), and ``admin_api.token_secret``.
     - ``config/``, ``ca/internal.py``
     - Identical on every node.  (The HSM backend keeps the key in the HSM instead.)
   * - The default in-memory rate limiter counts per process.
     - ``app/rate_limiter.py``
     - Use ``security.rate_limits.backend: database``.

.. note::

   The statement "ACMEEH is stateless, all state is in PostgreSQL" is true of *runtime* state
   only.  The list above is what you must keep consistent across nodes.

Requirements and sizing
=======================

* **3 servers**, same OS and PostgreSQL major version, clocks synchronised (chrony/NTP; etcd and
  TLS are sensitive to drift).
* **Network**: a low-latency private network between the three servers.  Every commit waits for
  one standby, so inter-node round-trip time adds directly to write latency.  Spreading the nodes
  over several sites is possible but measure the latency first; with 3 nodes, at most one site
  may fail, so put no more than one node per site.
* **Per server**: 2 vCPU, 4 GB RAM, 50 GB disk is a sensible start for ACMEEH's workload (see
  ``Database Sizing`` in :doc:`deployment`).  Give etcd's data directory a disk that PostgreSQL
  cannot saturate.
* **A load balancer** (enterprise one, or HAProxy + keepalived: ``deploy/ha/haproxy-lb.cfg``,
  ``deploy/ha/keepalived.conf``).
* **A watchdog** device on each server (``softdog`` or a hypervisor watchdog) for Patroni.
* **A backup repository** that survives the loss of all three servers (object storage, NFS or a
  backup host).

Network and firewall
====================

.. list-table::
   :header-rows: 1
   :widths: 12 20 30 38

   * - Port
     - Service
     - Allowed from
     - Notes
   * - 443
     - Load balancer
     - ACME clients
     - HTTPS.
   * - 8443
     - ACMEEH
     - Load balancer only
     - Plain HTTP between the balancer and ACMEEH on a private network (or terminate TLS again).
   * - 5432
     - PostgreSQL
     - The 3 nodes
     - Replication, and every node's HAProxy (which may target any node as primary).
   * - 8008
     - Patroni REST
     - The 3 nodes, monitoring
     - HAProxy health checks, Patroni-to-Patroni calls, ``/metrics``.
   * - 2379
     - etcd client
     - The 3 nodes
     - Patroni.
   * - 2380
     - etcd peer
     - The 3 nodes
     - etcd to etcd.
   * - 5000
     - Local HAProxy
     - ``127.0.0.1`` **only**
     - ACMEEH to its database route.  Never expose it.
   * - out
     - ACMEEH
     - to clients on :80, to DNS
     - http-01 / dns-01 validation, as in a single-server deployment.

TLS everywhere
==============

Use your organisation's internal CA and issue one certificate per server.

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - Used by
     - Subject alternative names
     - Extended key usage
   * - Load balancer
     - The public name of the ACME service (``acme.example.org``)
     - serverAuth
   * - PostgreSQL + Patroni REST (per node)
     - The node's FQDN, ``localhost``, ``127.0.0.1`` and the name each client really connects
       with
     - serverAuth **and** clientAuth (Patroni also uses it as its etcd client certificate)
   * - etcd (per node)
     - The node's FQDN, ``localhost``
     - serverAuth **and** clientAuth (peer connections)

``sslmode: verify-full`` checks the name the client typed against the certificate, which is the
property that makes TLS worth having.  ACMEEH reaches PostgreSQL through ``127.0.0.1:5000``, so the
PostgreSQL certificate must contain ``127.0.0.1`` (or you connect to ``localhost`` and list that
name).  A wrong name fails with ``server certificate for "x" does not match host name "y"``; the
test cluster confirmed it.

Rotation: PostgreSQL re-reads its certificate on ``pg_ctl reload``, Patroni on ``SIGHUP``, HAProxy
on reload; etcd needs a restart, one member at a time.  Put certificate expiry in your monitoring.

Installing and configuring
==========================

All templates are in ``deploy/ha/`` and are annotated.  Replace every ``<PLACEHOLDER>``.

#. **Packages** on each node: PostgreSQL 16 (PGDG), ``patroni`` 4.x with the ``etcd3`` extra
   (``pip install "patroni[etcd3]" psycopg2-binary``), ``etcd`` 3.5, ``haproxy`` 2.x, ACMEEH.
   Disable the distribution's PostgreSQL service: Patroni starts and stops PostgreSQL itself
   (``systemctl disable --now postgresql``).

#. **etcd**: ``deploy/ha/etcd.conf.yml``.  Start the three members together the first time.
   Check: ``etcdctl --endpoints=... --cacert ... --cert ... --key ... endpoint health``.

#. **Patroni + PostgreSQL**: ``deploy/ha/patroni.yml`` and ``deploy/ha/systemd/patroni.service``.
   Start Patroni on one node first; once it is Leader, start the others, which clone it.
   Check: ``patronictl -c /etc/patroni/patroni.yml list`` shows one ``Leader`` and two
   ``Quorum Standby`` in state ``streaming``.

   The settings that matter:

   * ``synchronous_mode: quorum`` with ``synchronous_node_count: 1``: PostgreSQL's
     ``synchronous_standby_names`` becomes ``ANY 1 (standby1, standby2)``.  Every commit is
     acknowledged by at least one standby, and losing one standby does not stop writes.  (With the
     older ``synchronous_mode: true`` on two standbys, losing the synchronous one froze writes for
     about ``ttl`` = 30 s on the test cluster.)
   * ``failsafe_mode: true``: if etcd as a whole is unreachable, the primary keeps accepting
     writes while it can still reach every Patroni member, instead of demoting itself.
   * ``ttl: 30``, ``loop_wait: 10``, ``retry_timeout: 10``: the crash-detection time of Patroni is
     about ``ttl``.  Lowering it shortens a crash failover but makes a slow network trigger
     needless failovers; measure before changing.
   * ``pg_hba``: ``hostssl`` only, restricted to the nodes' subnet, ``hostnossl ... reject``.
   * ``watchdog.mode: required``: see below.

#. **Watchdog**.  If Patroni hangs or the machine freezes, the watchdog resets the machine, so an
   old primary cannot keep accepting writes after a new one was elected.

   .. code-block:: bash

      modprobe softdog
      echo softdog > /etc/modules-load.d/softdog.conf
      echo 'KERNEL=="watchdog", OWNER="postgres", MODE="0600"' > /etc/udev/rules.d/99-watchdog.rules
      udevadm control --reload && udevadm trigger

   This cannot be exercised in containers: **test it on your servers** (see the validation plan).

#. **Local HAProxy**: ``deploy/ha/haproxy-db.cfg``, ``deploy/ha/systemd/haproxy-db.service``.
   Bind ``127.0.0.1:5000`` only.  Check: ``psql "host=127.0.0.1 port=5000 sslmode=verify-full
   sslrootcert=... user=acmeeh dbname=acmeeh" -c 'select pg_is_in_recovery()'`` returns ``f``.

#. **ACMEEH**: ``examples/ha-patroni.yaml`` is the same file on all three nodes, with
   ``deploy/ha/systemd/acmeeh.service``.  The points that are specific to this design:

   * ``database.host: 127.0.0.1``, ``port: 5000``, ``sslmode: verify-full`` and ``sslrootcert``.
   * ``server.worker_class: gthread`` with ``server.threads: 4``.  gunicorn defaults to **one
     thread per worker**, which means one request at a time per worker; a stalled database call
     then also blocks ``/readyz``.  ACMEEH logs a warning when ``gthread`` runs with
     ``threads: 1``.
   * ``security.rate_limits.backend: database``.
   * ``ari.enabled: true``: ACME clients (certbot, lego) then spread their renewals over a window.
   * ``proxy.trusted_proxies``: the load balancer's addresses.
   * ``database.max_connections``: one pool **per worker process**.  Keep
     ``nodes x workers x max_connections`` below PostgreSQL's ``max_connections`` (3 x 2 x 30 = 180
     under 200 in the example).

#. **Load balancer**: ``deploy/ha/haproxy-lb.cfg`` or the same settings on your own.  The
   settings are tuned; see `Load balancer settings`_.

First deployment
================

#. Start etcd on the three nodes; verify the three members are healthy.
#. Start Patroni on node 1; wait for ``Leader``.  Start it on nodes 2 and 3.
#. Start the local HAProxy on each node.
#. Create the role and the database **once**, through any node's HAProxy:

   .. code-block:: sql

      CREATE ROLE acmeeh LOGIN PASSWORD '...';
      CREATE DATABASE acmeeh OWNER acmeeh;

#. Create the schema **once**, from one node, with a copy of the configuration that has
   ``database.auto_setup: true``: ``acmeeh -c config-migrate.yaml db migrate``.  The running
   configuration keeps ``auto_setup: false``: a standby cannot run DDL.
#. Start ACMEEH on the three nodes.  Starting them simultaneously is safe: the creation of the
   initial ``admin`` user tolerates the race (see `Changes made to ACMEEH`_).  The initial admin
   password is printed once on **stderr** of the instance that created it (``journalctl -u
   acmeeh``).  Change it immediately.
#. Check ``GET /readyz`` on each instance, then a full issuance through the load balancer with a
   real client.

Load balancer settings
======================

These values were tuned with measurements and are the part to carry over to an existing load
balancer.

.. list-table::
   :header-rows: 1
   :widths: 28 22 50

   * - Setting
     - Value
     - Why
   * - Health check
     - ``GET /readyz`` = 200
     - It exercises the CA backend and the database path.  Its own database probe gives up after
       2 s, so it answers 503 instead of hanging.  Under full load during an outage, instances whose
       workers are all waiting for the database can answer later than that (10 s was measured),
       which is why the removal threshold below tolerates several failures.
   * - Interval / timeout
     - 2 s / 3 s
     - ``/readyz`` answers or fails within about 2 s.
   * - Failures before removal
     - **4** (8 s)
     - Longer than a planned database switchover (~5 s).  With 2 failures every switchover emptied
       the pool, and the load balancer answered 503 itself (see the results).
   * - Successes before return
     - **1**
     - Back in rotation as soon as the database is back.
   * - Retries on another instance
     - **Connection failure only**
     - Never replay a request after a 5xx or a reset: an ACME POST carries a single-use nonce, so a
       replay returns ``badNonce`` and multiplies the load during the incident.  The ACME client
       retries, with a fresh nonce.
   * - ``X-Forwarded-For`` / ``X-Forwarded-Proto``
     - Set
     - ACMEEH ``proxy.trusted_proxies`` must list the balancer.

Operations
==========

Status
------

.. code-block:: bash

   patronictl -c /etc/patroni/patroni.yml list           # roles, lag, timeline
   patronictl -c /etc/patroni/patroni.yml show-config    # cluster-wide settings in etcd
   curl -s --cacert ca.pem https://node:8008/primary     # 200 only on the primary
   psql -h 127.0.0.1 -p 5000 ... -c "select client_addr, ssl from pg_stat_activity a join pg_stat_ssl s using (pid)"

Planned switchover (maintenance of the primary)
-----------------------------------------------

.. code-block:: bash

   patronictl -c /etc/patroni/patroni.yml switchover --leader pg1 --candidate pg2 --force

About 5 s without writes.  ACME clients that hit that window receive a 503 with ``Retry-After``
and retry.  Orders that were mid-finalisation at that instant end ``invalid`` after 10 minutes
(``stale_processing_recovery``) and the client simply requests a new certificate.

Rolling maintenance (OS patches, PostgreSQL minor upgrade)
----------------------------------------------------------

Never take two nodes down at once (quorum).  For each node in turn:

#. Standbys first.  ``patronictl restart acmeeh-pg <node> --force`` (or stop Patroni, patch,
   start it) and wait until ``list`` shows the node ``streaming`` again.
#. The primary last: ``patronictl switchover`` away from it, then treat it as a standby.
#. etcd: restart or patch its member, wait for ``endpoint health`` to be green, move on.

The test cluster ran this sequence (restart of the two standbys, switchover, restart of the former primary)
under load; see the results.

Replacing a failed server
-------------------------

#. Build a new server with the same hostname/IP, certificates and ``patroni.yml``.
#. etcd: remove the dead member and add the new one (``etcdctl member remove`` /
   ``member add``), start it with ``initial-cluster-state: existing``.
#. Start Patroni: with an empty data directory it clones the primary automatically.
   ``patronictl reinit acmeeh-pg <node>`` forces a rebuild of an existing standby.

Loss of the quorum (two of three servers)
-----------------------------------------

The surviving PostgreSQL demotes itself to read-only: **ACMEEH issues nothing until a second node
is back**.  This is by design (it is what prevents two primaries).  Restore the two nodes; the
cluster reforms by itself.  Measured on the test cluster: the survivor left the primary role within about
6 s of losing the others and no node was primary for the rest of the outage; writes resumed 3 s
after the two nodes were restarted (on real servers add their boot time); no acknowledged write
was lost.  Do not force a lone survivor to become primary unless you accept
losing whatever the others had that it lacks; that procedure is deliberately not automated here.

Monitoring and alerting
=======================

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Source
     - Endpoint
     - Use
   * - Patroni
     - ``https://node:8008/metrics`` (Prometheus)
     - role, timeline, lag, sync standbys, PostgreSQL running
   * - etcd
     - ``https://node:2379/metrics``
     - leader changes, quorum, database size, fsync latency
   * - HAProxy
     - stats socket / ``:7000``
     - backend up/down, queue, sessions
   * - ACMEEH
     - ``/metrics`` (see :doc:`deployment`), ``/healthz``
     - issuance rate, errors, pool state
   * - PostgreSQL
     - ``pg_stat_replication``, ``pg_stat_ssl``
     - replication state; any non-TLS session is an incident

Alerts worth having:

* No Patroni leader for more than 30 s; **more than one** leader (page immediately).
* Fewer than two streaming standbys (the next failure becomes an outage).
* Replication lag above a threshold; WAL archiving failures (``pg_stat_archiver``).
* etcd: no leader, member down, database near its quota.
* ``patroni.service`` failed (it is not restarted automatically, by design).
* ACMEEH ``/readyz`` failing on an instance; HAProxy backend with no server.
* TLS certificate expiry for every certificate above (30 and 7 days).
* Disk space on the data and WAL volumes.

Backup and restore
==================

Replication is not a backup.  Use pgBackRest (``deploy/ha/pgbackrest.conf``) with WAL archiving
from Patroni (``archive_command`` in ``patroni.yml``) and the wrapper
``deploy/ha/pgbackrest-cron.sh``, which runs on all three nodes but acts only on the current
primary.

Also back up, separately: the CA private key (or rely on the HSM), the ACMEEH configuration, the
TLS CA and the Patroni/etcd secrets.  Losing the CA key means no new certificates can be issued.

What was exercised on the test cluster
--------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Drill
     - Result
   * - Enable archiving on the running cluster (``patronictl edit-config`` + rolling restart with a
       switchover)
     - Cluster stayed available; ``pgbackrest check`` OK
   * - Full backup of a 93 MB database, encrypted repository on a volume shared by the 3 nodes
     - 13 s; 18 MB in the repository
   * - Point-in-time restore into a throwaway server
     - Exact: rows written after the target absent, rows before it present, 14,439 / 14,439
       certificates
   * - **Disaster: the 3 data servers and Patroni's state in etcd destroyed**, rebuilt from the
       backup to a chosen instant
     - Primary back in 20 s, two standbys re-cloned in 27 s; state exactly that of the target
       instant; ACMEEH reconnected by itself; a real client issued a certificate right after

Enabling archiving
------------------

Order matters.  Create the stanza **first**, then turn archiving on:

#. ``pgbackrest --stanza=acmeeh stanza-create`` on the primary.
#. Put ``archive_mode: "on"``, ``archive_command``, ``restore_command`` in ``bootstrap.dcs`` of
   ``patroni.yml`` (already the case in ``deploy/ha/patroni.yml``) **and** apply them to the running
   cluster with ``patronictl edit-config -s postgresql.parameters.archive_mode=on ...``, then restart
   the members (standbys, a switchover, the old primary).  Without the first part, a cluster rebuilt
   after a disaster archives nothing (``pgbackrest check`` answers ``[087]: archive_mode must be
   enabled``), as the test cluster showed.
#. ``pgbackrest --stanza=acmeeh check``, then a first full backup.

Turning archiving on before the stanza exists makes ``archive_command`` fail (and PostgreSQL
retain WAL) until it does; ``pg_stat_archiver.failed_count`` shows it.

Disaster recovery: all data servers lost
----------------------------------------

#. Stop Patroni on every node.  Clear the cluster's keys from etcd, or build a new etcd:
   ``etcdctl del --prefix /service/acmeeh-pg/`` (client certificate flags as usual).
#. Make sure each node's data directory is **empty** (new server, or wipe it).  A directory that
   still contains ``postmaster.pid`` makes ``pgbackrest restore`` refuse (``[038] unable to restore
   while PostgreSQL is running``); and a directory restored by hand is *adopted as is* by Patroni,
   which then replays all the archived WAL and **ignores the recovery target**.
#. On **one** node, add a custom bootstrap to ``patroni.yml`` (``bootstrap.method`` selects it; the
   ``initdb`` default is used otherwise).  Patroni runs the restore itself and keeps the recovery
   settings:

   .. code-block:: yaml

      bootstrap:
        method: pgbackrest_restore
        pgbackrest_restore:
          command: pgbackrest --stanza=acmeeh --delta restore
          no_params: true                # otherwise Patroni appends --scope/--datadir
          keep_existing_recovery_conf: false
          recovery_conf:
            restore_command: pgbackrest --stanza=acmeeh archive-get %f "%p"
            recovery_target_time: "2026-10-18 09:48:33+00"   # omit to recover to the end of the archive
            recovery_target_action: promote
            recovery_target_timeline: latest
        dcs: { ... }                     # unchanged

#. Start Patroni on that node and wait for ``Leader``; then start the other two with empty data
   directories: they clone it.
#. **Before reopening the service**, deal with the consequences below.
#. Take a new full backup (the timeline changed) and check ``pgbackrest check``.

Consequences of restoring to a point in the past
------------------------------------------------

A restore forgets everything after its target.  For a certificate authority that matters:

* **Serial numbers are reused.**  Certificates issued after the target are gone from the database
  but were delivered to clients, and the serial sequence is back at its old value, so the next
  certificate gets the serial of a certificate that exists in the field.  The test cluster showed it (serial
  ``3a5c`` issued twice).  Move the sequence well ahead before reopening, with a margin far above
  the number of certificates that could have been issued since the target:

  .. code-block:: sql

     SELECT setval('certificate_serial_seq', (SELECT last_value FROM certificate_serial_seq) + 100000);

  (``ca.internal.serial_source: random`` avoids the sequence altogether.)
* **Revocations made after the target are forgotten**, so a revoked certificate becomes valid
  again.  Re-apply them from your own records (audit export, tickets) and rebuild the CRL.
* **Orders, accounts and nonces after the target are gone**; clients will register again.
* Restoring to the *end of the archive* (no target) keeps the loss to at most ``archive_timeout``
  (60 s in the template); choose a point in the past only to undo something harmful.

Timings measured on the test cluster (a 93 MB database on one workstation) are small; time a restore of
your real data volume, since that is what decides your recovery time.


Validation results
==================

Method
------

Test cluster on **one workstation** (3 nodes in Docker, everything including the load generator sharing
8 CPUs), so absolute latencies are pessimistic; the *behaviour* is what carries over.  The
17-run tables below were taken before the availability check (see "Why ``badNonce`` appeared")
was added; a final subset on the finished code is reported at the end of this section, and the
A/B of that check compares both.  Each scenario
applies 90 s of load, injects the failure 30 s in, then restores the failed parts.  Three measurements
run throughout:

* a **write probe** committing a row every ~50 ms through the database route and keeping the list
  of acknowledged writes: it measures the write interruption and counts acknowledged writes missing
  afterwards (a blocked ``COMMIT`` shows up as latency, not as an error);
* ``GET /readyz`` on every ACMEEH instance;
* **ACME clients**: *k6* (synthetic: full order lifecycle, **no retries**) and **lego v5** (a real
  client: 4 parallel loops, a new domain each time, with its own retry logic).

Properties that held in all 17 runs
-----------------------------------

.. list-table::
   :header-rows: 1
   :widths: 55 45

   * - Property
     - Result
   * - Acknowledged writes lost
     - **0** of 33,936 (plus a few *ambiguous* writes: committed, acknowledgement lost, see below)
   * - Duplicate certificate serial numbers
     - **0** across 9,528 certificates issued during the runs
   * - Nodes believing they are primary (sampled every 3 s during and after the failure)
     - never more than **1**
   * - HTTP 500 returned by ACMEEH
     - **0** (connection losses answer 503 + ``Retry-After``)
   * - Replicas after recovery
     - identical row counts on the 3 nodes
   * - Cluster after each run
     - returned to one leader and two ``Quorum Standby`` by itself

Synthetic load (k6, no retry)
-----------------------------

.. list-table::
   :header-rows: 1
   :widths: 24 30 14 32

   * - Failure
     - Write interruption
     - Cycles ok
     - Comment
   * - Planned switchover
     - errors 0.6 s, a commit waited up to 4.1 s
     - 99.8 %
     - The 5 s blip is absorbed by connection waits.
   * - Rolling maintenance (3 nodes)
     - one 5.2 s interruption (the leader move)
     - 99.6 %
     - Standby restarts are invisible.
   * - Kill the primary process
     - 35.3 s
     - 62.4 %
     - Bounded by Patroni's ``ttl``.
   * - Lose the primary's server
     - 37.0 s
     - 29.0 %
     - Same, plus the instance on that node.
   * - Partition: primary isolated
     - 38.0 s
     - 64.8 %
     - The isolated primary demoted itself; a new one was elected; never two.
   * - Partition: primary cannot reach its standbys
     - **writes blocked** until healed (one commit waited 68.5 s)
     - 45.1 %
     - Safe, not available: see below.
   * - Lose a standby (process or server)
     - none (0.3 s at most)
     - 99.5-100 %
     - Quorum replication: nothing waits for the lost standby.
   * - Lose one etcd member
     - none
     - 100 %
     -
   * - Lose all 3 etcd
     - none
     - 100 %
     - ``failsafe_mode``: the primary stays writable.
   * - Lose one ACMEEH instance
     - none
     - 99.5 %
     - The load balancer routes around it.

A client that does not retry loses every request made during an interruption, which is what these
percentages mostly measure.  The next table is the realistic one.

Real client (lego v5)
---------------------

.. list-table::
   :header-rows: 1
   :widths: 30 18 18 34

   * - Failure
     - Issuances ok
     - Longest ok
     - Failures
   * - Planned switchover
     - 215 / 215
     - 22 s
     -
   * - Rolling maintenance
     - 742 / 742
     - 10 s
     -
   * - Kill the primary process (31 s outage)
     - 175 / 176
     - 73 s
     - 1: 503 after lego's 6 attempts
   * - Lose the primary's server (25 s outage)
     - 173 / 177
     - 86 s
     - 3 ``badNonce``, 1 503, all after 5-6 attempts
   * - Partition: primary isolated (38 s)
     - 208 / 209
     - 55 s
     - 1 ``badNonce`` after 6 attempts
   * - Lose one ACMEEH instance
     - 317 / 317
     - 10 s
     -
   * - Lose **two of three** servers (quorum lost)
     - 125 / 129
     - 4 s
     - 4 x 503 after 6 attempts.  Nothing can be issued while two nodes are down; the first
       issuance after they came back succeeded

lego retries each request itself (up to 6 attempts with growing delays), so it rides through a
crash failover: issuances that straddle the outage simply take 30-90 s.  Failures only occur when
an outage outlasts that retry budget.  In every case the same domain was issued successfully
right afterwards, and a run of fresh issuances after recovery succeeded 100 %: **nothing is left
in a bad state**.

Why ``badNonce`` appeared (and what changed)
--------------------------------------------

An ACME request carries a single-use nonce.  ACMEEH consumed it *first* and only then touched the
database for the real work.  When the database failed at that point the request returned 503 with
its nonce already spent, so a client replaying the same signed request received ``badNonce``, again
and again for as long as the outage lasted.  Several requests were also observed holding a worker
for 8-16 s (one or two pool waits) before answering 503, which made things worse and starved
``/readyz`` (it measured 10 s on instances whose workers were all waiting for the database).

ACMEEH now checks that the database is reachable (a probe cached for one second) **before**
consuming the nonce.  If it is not, the request is refused at once with 503 and ``Retry-After``,
the nonce is untouched and the client can replay the very same signed request, and no worker is
held for the pool timeout.  Measured with lego, same scenarios, alternating images (10 runs):

.. list-table::
   :header-rows: 1
   :widths: 44 28 28

   * -
     - With the check
     - Without it
   * - lego, primary killed or server lost (3 runs each): issuances ok
     - 594 / 601 (98.8 %)
     - 550 / 556 (98.9 %)
   * - ... failures that are ``badNonce``
     - 3
     - 6
   * - ... failures that are a 503 after lego's 6 attempts
     - 4
     - 0
   * - ... longest successful issuance
     - 53 s
     - 86 s
   * - lego, planned switchover
     - 400 / 400
     - 391 / 391
   * - k6, planned switchover
     - 99.5 %
     - 99.0 %

The success rate does not move.  What changes is the *kind* of failure and the tail: the nonce is
no longer spent, failures resolve in seconds instead of 8-16 s per attempt, and the worst
issuance is 33 s shorter.  The trade-off is visible too: because the 503 now arrives quickly, a
client's fixed retry budget (lego: 6 attempts) is used up sooner, so the few failures that remain
are mostly "503 after 6 attempts" rather than ``badNonce``.  A client that retries for longer, or a
renewal job that runs again later, simply succeeds.  Planned switchovers are not degraded.


Partition between the primary and its standbys
----------------------------------------------

If the primary can still reach etcd but not its standbys, it keeps the leader lock, so no failover
happens, and every ``COMMIT`` waits for an acknowledgement that cannot arrive.  Nothing is lost and
nothing diverges (the blocked commits were never acknowledged), but ACMEEH issues nothing until the
link is repaired.  ``statement_timeout`` does not interrupt that wait.  Operator choices: repair
the network, or ``patronictl failover --candidate <standby> --force`` to move the lead to the
reachable side (the transactions lost that way are exactly the unacknowledged, blocked ones).

Ambiguous writes
----------------

A client that receives an error exactly at a failover may have had its request committed anyway;
the test cluster saw it once (one row present in the database that the probe had not seen acknowledged).
This is inherent to any system with a network between client and database; make automation around
ACMEEH idempotent.

Final confirmation on the finished code
---------------------------------------

A subset of the scenarios was run again on the finished code: availability check before the
nonce, worker metrics fixed, WAL archiving to pgBackRest on, TLS everywhere, ``server.threads: 4``.

.. list-table::
   :header-rows: 1
   :widths: 30 10 30 30

   * - Scenario
     - Client
     - Finished code
     - Earlier 17-run battery
   * - Planned switchover
     - lego
     - 396 / 396
     - 215 / 215
   * - Kill the primary process
     - lego
     - 169 / 169 (34 s write interruption)
     - 175 / 176 (31 s)
   * - Lose the primary's server
     - k6
     - 66.4 % (34 s)
     - 29.0 % (37 s)
   * - Rolling maintenance
     - lego
     - 723 / 723
     - 742 / 742
   * - Lose all 3 etcd
     - k6
     - 100 %, no interruption
     - 100 %
   * - Partition: primary isolated
     - lego
     - 235 / 237 (32 s)
     - 208 / 209 (38 s)

The invariants are unchanged: 0 acknowledged writes lost, 0 duplicate serials, never more than one
primary, 0 HTTP 500.  Archiving did not change the failover behaviour.

Repeatability of the planned switchover under heavy synthetic load
------------------------------------------------------------------

The same planned switchover was repeated nine times on the finished code with k6 (no retries, 8
issuances per second on a saturated workstation).  Cycles ok: **87.7, 96.0, 98.1, 98.6, 99.1, 99.3,
99.3, 99.7, 99.8 %** (median 99.1 %; seven of nine above 98.5 %).  The write interruption itself was
the same each time (about 4-5 s).

The worst run is an unexplained tail event.  Two of the three instances kept their connection pools
exhausted (``size=13-15/30 available=0 waiting=2..11``) for about 15 s after writes had resumed;
requests answered 503 after 8-10 s, ``/readyz`` timed out, and the load balancer took those
instances out for a while.  Sampling ``pg_stat_activity`` during six further repeats showed no pile-up
of sessions waiting for synchronous replication (at most 3, once 9), so that is not the cause, and
the event was not reproduced.  Treat it as a reason to:

* run planned switchovers outside peak load;
* keep the load balancer tolerant (``fall 4``) and clients retrying;
* alert on ACMEEH's ``Pool pressure at request teardown`` log lines and on ``/readyz`` failures;
* re-measure on your own hardware, where the saturation that likely contributed will not exist.


What these numbers do **not** cover
-----------------------------------

The numbers come from one workstation under combined load: absolute durations will differ on your
servers.  The kernel watchdog, VRRP, pgBackRest against your repository and the timing of your
storage and network are not exercised.  The validation plan below covers them.


Validation plan for your servers
================================

Run these on the real servers before going live, and again after any change to the design.

.. list-table::
   :header-rows: 1
   :widths: 24 38 38

   * - Test
     - How
     - Expect
   * - Planned switchover
     - ``patronictl switchover --leader A --candidate B --force``
     - ~5 s of 503 at most, one primary at all times, nothing lost
   * - Crash of PostgreSQL
     - ``kill -9`` the postgres main process on the primary
     - New primary within ~30 s; the old one rejoins as standby
   * - Crash of a server
     - Power it off from the hypervisor
     - Same as above; ACMEEH instance of that node leaves the load balancer
   * - Reboot
     - ``systemctl reboot`` on a standby, then on the primary
     - Node comes back and resynchronises by itself
   * - Network partition of the primary
     - On the primary: ``iptables -I INPUT -s <node2> -j DROP; iptables -I OUTPUT -d <node2> -j DROP``
       (and node 3).  Undo with ``iptables -D``.
     - The isolated primary demotes itself; the other two elect a new one; never two primaries
   * - Asymmetric partition
     - On the primary: drop ports 5432 and 8008 to/from the standbys only
     - Writes block (no standby acknowledges) instead of diverging; recover when removed
   * - Watchdog
     - ``kill -STOP`` Patroni on the primary
     - The machine resets; a new primary is elected; **never** two writable primaries
   * - Loss of the quorum
     - Power off two of the three servers
     - The survivor becomes read-only within seconds (never two primaries); service resumes by
       itself when a second server is back
   * - etcd
     - Stop one member; then stop all three
     - One: no effect.  All three: the primary stays writable (``failsafe_mode``)
   * - ACMEEH
     - Stop one instance under load
     - Clients keep being served
   * - Load balancer
     - Stop the active one (VIP) / one backend
     - Service continues
   * - Backup and disaster recovery
     - Take a backup, restore it on a scratch server; then destroy the data directories and etcd
       state of a test cluster and rebuild it with the custom bootstrap
     - Same data at the chosen instant; serial sequence moved ahead before reopening

Security checklist
==================

* Secrets in ``/etc/patroni/patroni.env`` or a vault, mode 0600; none in the YAML in version
  control.
* ``pg_hba`` limited to the nodes' subnet; no ``trust`` entries.
* Patroni REST write operations require the password; consider a firewall rule so only the three
  nodes and your operators' hosts reach port 8008.
* etcd with client-certificate authentication; port 2379/2380 reachable by the three nodes only.
* HAProxy database route bound to ``127.0.0.1``.
* The ACMEEH database role owns only the ``acmeeh`` database.
* CA key mode 0600, owner ``acmeeh``, or in an HSM.
* Restrict ``admin_api`` to an administration network.

Known limitations and residual risks
====================================

* **A crash of the primary costs about 30 s of issuance** (``ttl``).  Clients retry; renewals are
  scheduled days ahead.  Lowering ``ttl`` trades this for the risk of needless failovers.
* **Loss of two of three servers stops issuance** until one returns (quorum).
* **Ambiguous commits**: a client that sees an error exactly during a failover may have had its
  request committed anyway (the test cluster saw one such write).  ACME order creation is retried by
  clients; design any automation around ACMEEH to be idempotent.
* **In-flight orders**: an order caught between "finalised" and "valid" at the instant of a crash
  becomes ``invalid`` after 10 minutes.  The client requests again.
* **Not validated on the test cluster**: the watchdog, the VRRP virtual IP, pgBackRest against an S3 or
  NFS repository of yours (the test cluster used a shared volume), real timing on your network and
  storage.  The validation plan above covers them.
* **A restore to a point in the past reuses serial numbers and forgets revocations** made
  after it (see "Consequences of restoring to a point in the past").
* **Background tasks are repeated by every worker process** (see above): keep the task intervals
  at minutes or more, never seconds, on a multi-node cluster.
* **Metrics are per gunicorn worker process**: a scrape returns the counters of whichever process
  answered.  Sum over the instances, and expect jumps with ``workers`` above 1.
* **lego waits**: the default ``lego run`` adds a random delay (minutes) before renewing; use
  ``--no-random-sleep`` when testing.

Changes made to ACMEEH
======================

Running the design above against a real client and a failing database exposed defects in ACMEEH.
They are fixed in the same change set, each with tests.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Change
     - Reason
   * - A connection lost during a request returns **503 + Retry-After**, not 500
     - A failover kills connections mid-request; clients treat 5xx other than 503 as a server bug.
   * - The connection pool **rejects connections attached to a standby**
       (``pg_is_in_recovery()`` at checkout)
     - After a failover, pooled connections stayed on the demoted node, which is read-only, and
       kept failing writes for minutes (the default pool check passes on a standby).  Hundreds of
       errors per switchover before, none after.
   * - ``/readyz`` and ``/healthz`` use a **2 s database probe** instead of waiting for a pool
       connection
     - They hung for ``connection_timeout`` (8 s) during a failover, longer than a load balancer's
       check timeout, so every instance was removed at once.
   * - New ``server.threads``
     - gunicorn's ``gthread`` ran one request at a time per worker, so a stalled database call
       blocked health checks and capped an instance at two concurrent requests.
   * - New ``database.sslrootcert`` / ``sslcert`` / ``sslkey``
     - ``sslmode: verify-full`` needs the CA; without these, only a libpq environment variable
       could provide it.
   * - **Initial admin creation is safe when instances start together**
     - The check-then-insert raced: two of three instances crashed at the first simultaneous start
       (``users_username_key`` violation).
   * - **ARI (RFC 9773) ``certID`` parsing fixed**
     - ``renewalInfo`` returned 404 for every certificate asked by a real client (lego): the ``certID``
       is two separately base64url-encoded parts, ACMEEH tried to decode the whole string.
   * - The worker counters are now filled (``acmeeh_cleanup_runs_total``, ``acmeeh_challenge_worker_*``,
       ``acmeeh_expiration_*``)
     - The metrics collector was never handed to the three background workers, so these
       documented counters stayed empty.
   * - A **database availability check runs before the nonce is consumed**
     - A request that failed after consuming its nonce could not be replayed: the client got
       ``badNonce`` repeatedly during an outage.  Now refused early with 503 + ``Retry-After``
       (see `Why badNonce appeared (and what changed)`_).
   * - Shipped ``gthread`` examples set ``threads: 4``; ``examples/ha-patroni.yaml`` added
     - Consistency with the above.
