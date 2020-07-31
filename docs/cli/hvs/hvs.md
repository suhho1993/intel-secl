# HVS CLI

This document describes the commands and behavior of hvs command line interface

## CLI help output

```
Usage:
        hvs <command> [arguments]

Avaliable Commands:
        help|-h|--help         Show this help message
        version|-v|--version   Show the version of current hvs build
        setup <task>           Run setup task
        start                  Start hvs
        status                 Show the status of hvs
        stop                   Stop hvs
        erase-data             Reset all tables in database and create default flavor groups
        config-db-rotation     Configure database table rotaition for audit log table, reference db_rotation.sql in documents
        uninstall [--purge]    Uninstall hvs
                --purge            all configuration and data files will be removed if this flag is set

Usage of hvs setup:
        hvs setup <task> [--help] [--force] [-f <answer-file>]
                --help                      show help message for setup task
                --force                     existing configuration will be overwritten if this flag is set
                -f|--file <answer-file>     the answer file with required arguments

Available Tasks for setup:
        all                             Runs all setup tasks
        server                          Setup http server on given port
        database                        Setup hvs database
        create-default-flavorgroup      Create default flavor groups in database
        create-dek                      Create data encryption key for HVS
        download-ca-cert                Download CMS root CA certificate
        download-cert-tls               Download CA certificate from CMS for tls
        download-cert-saml              Download CA certificate from CMS for saml
        download-cert-flavor-signing    Download CA certificate from CMS for flavor signing
        create-endorsement-ca           Generate self-signed endorsement certificate
        create-privacy-ca               Generate self-signed privacy certificate
        create-tag-ca                   Generate self-signed tag certificate
```

### Commands

Command | Description
--------|-------------
`hvs help` | Print help message for HVS
`hvs erase-data` | Reset all tables in database and create default flavor groups, will require reconfiguring database rotation
`hvs config-db-rotation` | Configure database rotation with SQL code specified in [db_rotation.sql](db_rotation.sql)
