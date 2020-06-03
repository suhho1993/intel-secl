# Flavor Library

The Flavor library is responsible for retrieving the hardware/software measurements of the host in a pre-defined format. 
When integrated with the Host Verification service, Flavor would be equivalent to what is known today as the Whitelist.

## Key features
- Create flavors for VM and container images
- Create Platform Flavors for Intel and VMWare Hosts
- Create Software Flavors from Manifest XMLs
- Create Generic Flavors from Asset Tag Certificates

### Direct dependencies

| Name                  | Repo URL                        | Minimum Version Required              |
| ----------------------| --------------------------------| :------------------------------------:|
| logrus                | github.com/sirupsen/logrus      | v1.4.0                                |
| testify               | github.com/stretchr/testify     | v1.3.0                                |
| uuid                  | github.com/google/uuid          | v1.1.1                                |

*Note: All dependencies are listed in go.mod*

# Links
https://01.org/intel-secl/
