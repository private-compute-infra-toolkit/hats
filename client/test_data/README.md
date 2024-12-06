# HATs CVM Test Data

The directory contains data used in unit and integration tests.

* launcher subdirectory: contains files used by launcher unit-tests.

* parc_data subdirectory: test data used in end to end testing.
    * parameters subdirectory contains a json file for parameters passed to
    KV-server. The file is loaded into a PARC server to which KV-server talks
    and get the parameters.
    * blob_root subdirectory: contains key value data in blob storage format.
    The plain text version is kept for reference in `blob_root/kv_data.csv`.
