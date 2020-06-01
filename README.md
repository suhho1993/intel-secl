# intel-secl

This is the main repository for holding all services and libraries

## Generation of Binary
Use command make <component_name> to build component and make <component_name>-installer to generate binary.
Example:

```
$ make hvs
% make hvs-installer
```

## Swagger Documentation
Use command make swagger to generate swagger/openapi documentation for APIs,

Pre-requisite:
```
$ wget https://github.com/go-swagger/go-swagger/releases/download/v0.21.0/swagger_linux_amd64 -O /usr/local/bin/swagger
$ chmod +x /usr/local/bin/swagger
```  

Command to generate swagger documentation:
```
$ make swagger
```