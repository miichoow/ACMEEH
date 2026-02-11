============
Installation
============

*Prerequisites, dependency installation, and first run*

.. tip::

   **Prefer Docker?** Skip the manual setup — see :doc:`docker` for a
   single-command deployment with ``docker compose up -d``.

Prerequisites
-------------

.. list-table::
   :header-rows: 1

   * - Requirement
     - Version
     - Notes
   * - Python
     - 3.12+
     - Required for modern type syntax
   * - PostgreSQL
     - 14+
     - Primary data store
   * - pip
     - Latest
     - Package installer
   * - Git
     - Any
     - For cloning the repo

.. note::

   **Optional: HSM Support**

   If you plan to use the HSM (PKCS#11) CA backend, you also need the ``python-pkcs11`` package and a compatible PKCS#11 library installed on your system.

Clone the Repository
--------------------

.. code-block:: bash

   git clone https://github.com/miichoow/ACMEEH.git
   cd acmeeh

Create a Virtual Environment
-----------------------------

.. code-block:: bash

   # Linux / macOS
   python3.12 -m venv .venv
   source .venv/bin/activate

   # Windows
   python -m venv .venv
   .venv\Scripts\activate

Install Dependencies
--------------------

.. code-block:: bash

   # Core dependencies
   pip install flask cryptography dnspython jinja2 "psycopg[binary]"

   # ConfigKit (configuration management) & PyPGKit (PostgreSQL ORM layer)
   pip install pyConfigKit PyPGKit

   # Optional: HSM support
   pip install python-pkcs11

Set Up PostgreSQL
-----------------

Create a database and user for ACMEEH:

.. code-block:: bash

   # Connect to PostgreSQL as superuser
   psql -U postgres

   # Create database and user
   CREATE USER acmeeh WITH PASSWORD 'your_secure_password';
   CREATE DATABASE acmeeh OWNER acmeeh;
   \q

.. tip::

   **Auto-Setup**

   Set ``database.auto_setup: true`` in your config and ACMEEH will automatically create all tables and triggers on first startup. The SQL schema uses ``IF NOT EXISTS`` so it's safe to run repeatedly.

Create a Configuration File
----------------------------

Create a ``config.yaml`` with at minimum the required fields:

.. code-block:: yaml

   server:
     external_url: https://acme.example.com

   database:
     host: localhost
     port: 5432
     database: acmeeh
     user: acmeeh
     password: ${DB_PASSWORD}
     auto_setup: true

   ca:
     backend: internal
     internal:
       root_cert_path: /path/to/root-ca.pem
       root_key_path: /path/to/root-ca-key.pem

   challenges:
     enabled:
       - http-01

See the :doc:`configuration` for all available settings.

Generate a Test CA
------------------

For development and testing, generate a self-signed root CA:

.. code-block:: bash

   # Generate a root CA key and certificate using openssl
   openssl ecparam -genkey -name prime256v1 -out root-ca-key.pem
   openssl req -new -x509 -key root-ca-key.pem -out root-ca.pem \
       -days 3650 -subj "/CN=ACMEEH Development CA"

Validate Configuration
----------------------

.. code-block:: bash

   PYTHONPATH=src python -m acmeeh -c config.yaml --validate-only

This loads and validates the config file against the JSON Schema, resolves environment variables, builds the typed settings tree, and exits. If valid, it prints a summary:

.. code-block:: bash

     server.external_url   = https://acme.example.com
     server.bind           = 0.0.0.0:8443
     server.workers        = 4
     database              = acmeeh@localhost:5432/acmeeh
     ca.backend            = internal
     challenges.enabled    = ['http-01']
     logging.level         = INFO
     tos.require_agreement = False
     admin_api.enabled     = False
   Configuration valid: config.yaml

Start the Server
----------------

Development Mode
^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Flask development server with auto-reload
   PYTHONPATH=src DB_PASSWORD=secret python -m acmeeh -c config.yaml --dev

Production Mode
^^^^^^^^^^^^^^^

.. code-block:: bash

   # Gunicorn production server
   PYTHONPATH=src DB_PASSWORD=secret python -m acmeeh -c config.yaml

See the :doc:`deployment` for production setup recommendations.

Verify It Works
---------------

.. code-block:: bash

   # Fetch the ACME directory
   curl -sk https://localhost:8443/directory | python -m json.tool

You should see a JSON response with the ACME directory URLs:

.. code-block:: json

   {
       "newNonce": "https://acme.example.com/new-nonce",
       "newAccount": "https://acme.example.com/new-account",
       "newOrder": "https://acme.example.com/new-order",
       "newAuthz": "https://acme.example.com/new-authz",
       "revokeCert": "https://acme.example.com/revoke-cert",
       "keyChange": "https://acme.example.com/key-change"
   }

Test CA Signing
---------------

.. code-block:: bash

   # Verify the CA backend can sign certificates
   PYTHONPATH=src DB_PASSWORD=secret python -m acmeeh -c config.yaml ca test-sign
