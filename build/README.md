Scripts related to building installers and docker images. the `Makefile` under
root directory should utilize scripts in this folder for creating desired
output. The `config` folder under this directory holds configuration for
building individual component

The referenced GitHub repo suggested that there should be a `ci` subdirectory.
However, we are using GitLab CI/CD, which uses only `.gitlab-ci.yaml` for
configuring it in the project. In addition to the impracticality of creating
a submodule for only one file, extra configuration in GitLab web UI is required
for it to work with custom path of `.gitlab-ci.yaml`. As the conclusion,
using `ci` subdirectory does not worth the hassle.

