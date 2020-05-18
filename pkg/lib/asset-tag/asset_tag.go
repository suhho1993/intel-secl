package asset_tag

import hc "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"

// AssetTag interface is used to create and deploy an asset tag certificate on a host
type AssetTag interface{
	CreateAssetTag(TagCertConfig) ([]byte, error)
	DeployAssetTag(hc.HostConnector, string, string) (error)
}

// NewAssetTag returns an instance to the AssetTag interface
func NewAssetTag() *atag{
	return new(atag)
}