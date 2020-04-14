`go build` will ignore this package. Put inter-components test codes here.

Possible structure
```
test 📁
    ├───aas 📁
    │    └───[components that use aas] 📁
    │        ├───test.go
    │        └───test_data.go
    └───cms 📁
        └───[components that use cms] 📁
            ├───test.go
            └───test_data.go
```
*Seems like a lot of dev work, is it worthwhile implementing?*

