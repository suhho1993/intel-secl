/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package vmware

import (
	"context"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/types"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"net/url"
	"strings"
)

var log = commLog.GetDefaultLogger()

type VMWareClient interface {
	GetHostInfo() (taModel.HostInfo, error)
	GetTPMAttestationReport() (*types.QueryTpmAttestationReportResponse, error)
}

const HOST_SYSTEM_PROPERTY = "HostSystem"

func NewVMwareClient(vcenterApiUrl *url.URL, vcenterUserName string, vcenterPassword string,
	hostName string) (VMWareClient, error) {

	vmwareClient := vmwareClient{
		BaseURL:         vcenterApiUrl,
		HostName:        hostName,
		vCenterUsername: vcenterUserName,
		vCenterPassword: vcenterPassword,
	}
	//Set username and password in the same URL struct
	vmwareClient.BaseURL.User = url.UserPassword(vmwareClient.vCenterUsername, vmwareClient.vCenterPassword)

	ctx := context.Background()
	host, vCenterClient, err := getVmwareHostReference(&vmwareClient, ctx)
	if err != nil {
		return nil, errors.Wrap(err, "vmware/client:NewVMwareClient() Error creating Vmware client")
	}

	vmwareClient.hostReference = host
	vmwareClient.vCenterClient = vCenterClient
	vmwareClient.Context = ctx

	return &vmwareClient, nil
}

type vmwareClient struct {
	BaseURL         *url.URL
	HostName        string
	vCenterUsername string
	vCenterPassword string
	hostReference   mo.HostSystem
	vCenterClient   *govmomi.Client
	Context         context.Context
}

func (vc *vmwareClient) GetHostInfo() (taModel.HostInfo, error) {

	log.Trace("vmware/client:GetHostInfo() Entering ")
	defer log.Trace("vmware/client:GetHostInfo() Leaving ")
	var hostInfo taModel.HostInfo

	vcenterVersion := vc.vCenterClient.ServiceContent.About.Version

	hostInfo.HostName = vc.hostReference.Name
	hostInfo.VMMName = vc.hostReference.Config.Product.Name
	hostInfo.OSName = vc.hostReference.Config.Product.Name
	hostInfo.OSVersion = vc.hostReference.Config.Product.Version
	hostInfo.VMMVersion = vc.hostReference.Config.Product.Build
	hostInfo.BiosName = vc.hostReference.Hardware.SystemInfo.Vendor
	hostInfo.BiosVersion = vc.hostReference.Hardware.BiosInfo.BiosVersion
	hostInfo.NumberOfSockets = int(vc.hostReference.Hardware.CpuInfo.NumCpuPackages)
	hostInfo.ProcessorInfo = vc.hostReference.Summary.MaxEVCModeKey
	hostInfo.HardwareUUID = strings.ToUpper(vc.hostReference.Hardware.SystemInfo.Uuid)
	hostInfo.HardwareFeatures.TPM.Enabled = *vc.hostReference.Capability.TpmSupported
	if strings.Contains(vcenterVersion, "6.5") && hostInfo.HardwareFeatures.TPM.Enabled {
		hostInfo.HardwareFeatures.TPM.Meta.TPMVersion = "1.2"
		attestationReport, err := vc.GetTPMAttestationReport()
		if err != nil {
			return taModel.HostInfo{}, errors.Wrap(err, "vmware/client:GetHostInfo() Error getting attestation"+
				"report from vcenter api")
		}
		if attestationReport.Returnval.TpmLogReliable {
			hostInfo.HardwareFeatures.TXT = &taModel.HardwareFeature{Enabled: true}
		} else {
			hostInfo.HardwareFeatures.TXT = &taModel.HardwareFeature{Enabled: false}
		}
	} else {
		hostInfo.HardwareFeatures.TPM.Meta.TPMVersion = vc.hostReference.Capability.TpmVersion
		hostInfo.HardwareFeatures.TXT = &taModel.HardwareFeature{Enabled: *vc.hostReference.Capability.TxtEnabled}
	}

	return hostInfo, nil
}

func (vc *vmwareClient) GetTPMAttestationReport() (*types.QueryTpmAttestationReportResponse, error) {

	log.Trace("vmware/client:GetTPMAttestationReport() Entering ")
	defer log.Trace("vmware/client:GetTPMAttestationReport() Leaving ")

	query := types.QueryTpmAttestationReport{This: vc.hostReference.Reference()}
	attestationReport, err := methods.QueryTpmAttestationReport(vc.Context, vc.vCenterClient.RoundTripper, &query)
	if err != nil {
		return attestationReport, err
	}
	return attestationReport, nil
}

func getVmwareHostReference(vc *vmwareClient, ctx context.Context) (mo.HostSystem, *govmomi.Client, error) {

	log.Trace("vmware/client:getVmwareHostReference() Entering ")
	defer log.Trace("vmware/client:getVmwareHostReference() Leaving ")
	vmwareClient, err := govmomi.NewClient(ctx, vc.BaseURL, true)
	if err != nil {
		return mo.HostSystem{}, vmwareClient, errors.Wrap(err, "vmware/client:getVmwareHostReference() Error creating vmware client")
	}

	viewManager := view.NewManager(vmwareClient.Client)
	viewer, err := viewManager.CreateContainerView(ctx, vmwareClient.ServiceContent.RootFolder, []string{HOST_SYSTEM_PROPERTY}, true)
	if err != nil {
		return mo.HostSystem{}, vmwareClient, errors.Wrap(err, "vmware/client:getVmwareHostReference() Error " +
			"creating container view from client")
	}

	var hs []mo.HostSystem

	err = viewer.Retrieve(ctx, []string{HOST_SYSTEM_PROPERTY}, []string{"name", "summary", "config", "capability", "hardware", "runtime"}, &hs)
	if err != nil {
		return mo.HostSystem{}, vmwareClient, err
	}

	for _, host := range hs {
		if host.Name == vc.HostName {
			return host, vmwareClient, nil
		}
	}
	return mo.HostSystem{}, vmwareClient, errors.New("vmware/client:getVmwareHostReference() No host with hostname " +
		vc.HostName + " found in cluster")
}
