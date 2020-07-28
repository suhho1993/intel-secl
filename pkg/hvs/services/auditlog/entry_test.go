package auditlog

import (
	"testing"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

func TestStructDiff(t *testing.T) {
	idNoChange := uuid.New()
	rx := &models.HVSReport{
		ID:     idNoChange,
		HostID: uuid.New(),
		TrustReport: hvs.TrustReport{
			PolicyName: uuid.New().String(),
			HostManifest: types.HostManifest{
				AIKCertificate:        uuid.New().String(),
				BindingKeyCertificate: uuid.New().String(),
			},
		},
	}
	ry := &models.HVSReport{
		ID:     idNoChange,
		HostID: uuid.New(),
		TrustReport: hvs.TrustReport{
			PolicyName: uuid.New().String(),
			HostManifest: types.HostManifest{
				AIKCertificate:        uuid.New().String(),
				BindingKeyCertificate: uuid.New().String(),
			},
		},
	}
	hssx := &hvs.HostStatus{
		ID:     uuid.New(),
		HostID: idNoChange,
		HostManifest: types.HostManifest{
			AIKCertificate:        uuid.New().String(),
			BindingKeyCertificate: uuid.New().String(),
		},
		HostStatusInformation: hvs.HostStatusInformation{
			HostState: hvs.HostStateInvalid,
		},
	}
	hssy := &hvs.HostStatus{
		ID:     uuid.New(),
		HostID: idNoChange,
		HostManifest: types.HostManifest{
			AIKCertificate:        uuid.New().String(),
			BindingKeyCertificate: uuid.New().String(),
		},
		HostStatusInformation: hvs.HostStatusInformation{
			HostState: hvs.HostStateInvalid,
		},
	}
	t.Log(report2Cols(rx, ry))
	t.Log(hostStatus2Cols(hssx, hssy))
}
