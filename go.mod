module github.com/intel-secl/intel-secl/v3

require (
	github.com/beevik/etree v1.1.0
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.12
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/onsi/ginkgo v1.13.0
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7
	github.com/sirupsen/logrus v1.4.0
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.3.0
	github.com/vmware/govmomi v0.22.2
	golang.org/x/sys v0.0.0-20200620081246-981b61492c35 // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/vmware/govmomi => github.com/arijit8972/govmomi fix-tpm-attestation-output
