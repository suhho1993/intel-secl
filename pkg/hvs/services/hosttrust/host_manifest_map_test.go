package hosttrust

import (
	"encoding/json"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestGetHostManifestMap(t *testing.T) {
	var hm *types.HostManifest
	data, err := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	assert.NoError(t, err)

	err = json.Unmarshal(data, &hm)
	assert.NoError(t, err)

	flavorParts := []cf.FlavorPart{cf.FlavorPartHostUnique, cf.FlavorPartPlatform, cf.FlavorPartOs, cf.FlavorPartAssetTag, cf.FlavorPartSoftware}
	hostManifestMap, err := getHostManifestMap(hm, flavorParts)
	assert.NoError(t, err)
	assert.NotNil(t,hostManifestMap)
}

func TestGetMeasurementLabels(t *testing.T) {
	var hm *types.HostManifest
	data, err := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	assert.NoError(t, err)

	err = json.Unmarshal(data, &hm)
	assert.NoError(t, err)
	softwareLabels, err := getMeasurementLabels(hm)
	assert.NoError(t, err)
	assert.Equal(t, []string{"ISecL_Default_Application_Flavor_v2.1_TPM2.0", "ISecL_Default_Workload_Flavor_v2.1"},softwareLabels)
}