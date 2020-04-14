This directory holds everything for *deploying* a component. For each required
use case, there will be a corresponding subdirectory. Files in this directory
are either final product after compilation or `docker build`, and configuration
files to setup services. No building script nor intermediate binary (e.g. cli
binary of a service) should present under this directory.

**Note** `kubernets` and `helm` will be using same docker image as
`docker compose`, no need to duplicate it

