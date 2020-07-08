/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"reflect"
	"strings"
	"time"
)

var (
	TagCert1 = ` {"id":"fda6105d-a340-42da-bc35-0555e7a5e360","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"00ecd3ab-9af4-e711-906e-001560a04062","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"80ecce40-04b8-e811-906e-00163566263e"}`
	TagCert2 = ` {"id":"3966e9e8-4f44-4a9e-9231-b4a83743de55","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"80ecce40-04b8-e811-906e-00163566263e"}`
	TagCert3 = ` {"id":"a4b46350-d60b-44db-88e8-6d1ada16e282","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(0, 6, 0).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`
	TagCert4 = ` {"id":"dbed7b6b-3d01-4e53-82e7-d1c62f8b6a5c","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 4, 15).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`
	TagCert5 = ` {"id":"390784a9-d83f-4fa1-b6b5-a77bd13a3c7b","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-3, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`
	TagCert6 = ` {"id":"cf197a51-8362-465f-9ec1-d88ad0023a27","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"7a569dad-2d82-49e4-9156-069b0065b262"}`
	TagCert7 = ` {"id":"7ce60664-faa3-4c2e-8c45-41e209e4f1db","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"00e4d709-8d72-44c3-89ae-c5edc395d6fe"}`
)

// MockTagCertificateStore provides a mocked implementation of interface hvs.TagCertificateStore
type MockTagCertificateStore struct {
	TagCertificateStore map[uuid.UUID]*hvs.TagCertificate
}

// Create inserts a TagCertificate into the store
func (store *MockTagCertificateStore) Create(tc *hvs.TagCertificate) (*hvs.TagCertificate, error) {
	store.TagCertificateStore[tc.ID] = tc
	return tc, nil
}

// Retrieve returns a single TagCertificate record from the store
func (store *MockTagCertificateStore) Retrieve(id uuid.UUID) (*hvs.TagCertificate, error) {
	if tc, ok := store.TagCertificateStore[id]; ok {
		return tc, nil
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Delete deletes TagCertificate from the store
func (store *MockTagCertificateStore) Delete(tagCertId uuid.UUID) error {
	if _, ok := store.TagCertificateStore[tagCertId]; ok {
		delete(store.TagCertificateStore, tagCertId)
		return nil
	}
	return errors.New(commErr.RowsNotFound)
}

// Search returns a filtered list of TagCertificates per the provided TagCertificateFilterCriteria
func (store *MockTagCertificateStore) Search(criteria *models.TagCertificateFilterCriteria) ([]*hvs.TagCertificate, error) {

	var tcc []*hvs.TagCertificate
	// start with all rows
	for _, tc := range store.TagCertificateStore {
		tcc = append(tcc, tc)
	}

	// TagCertificate filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, models.TagCertificateFilterCriteria{}) {
		return tcc, nil
	}

	// TagCertificate ID filter
	if criteria.ID != uuid.Nil {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.ID == criteria.ID {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// HostHardwareID filter
	if criteria.HardwareUUID != uuid.Nil {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.HardwareUUID == criteria.HardwareUUID {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// SubjectEqualTo filter
	if criteria.SubjectEqualTo != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.Subject == criteria.SubjectEqualTo {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// SubjectContains filter
	if criteria.SubjectContains != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if strings.Contains(tc.Subject, criteria.SubjectContains) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// IssuerEqualTo filter
	if criteria.IssuerEqualTo != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if strings.ToLower(tc.Issuer) == strings.ToLower(criteria.IssuerEqualTo) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// IssuerContains filter
	if criteria.IssuerContains != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if strings.Contains(strings.ToLower(tc.Issuer), strings.ToLower(criteria.IssuerContains)) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// ValidOn
	if !criteria.ValidOn.IsZero() {
		var tcFiltered []*hvs.TagCertificate

		for _, tc := range tcc {
			if tc.NotBefore.Before(criteria.ValidOn) && tc.NotAfter.After(criteria.ValidOn) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// ValidBefore
	if !criteria.ValidAfter.IsZero() {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.NotBefore.After(criteria.ValidAfter) && tc.NotAfter.After(criteria.ValidAfter) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// ValidAfter
	if !criteria.ValidBefore.IsZero() {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.NotBefore.Before(criteria.ValidAfter) && tc.NotAfter.Before(criteria.ValidAfter) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	return tcc, nil
}

// NewFakeTagCertificateStore loads dummy data into MockTagCertificateStore
func NewFakeTagCertificateStore() *MockTagCertificateStore {
	store := &MockTagCertificateStore{}

	store.TagCertificateStore = make(map[uuid.UUID]*hvs.TagCertificate)

	// unmarshal the tagCert models
	var tc1, tc2, tc3, tc4, tc5, tc6, tc7 hvs.TagCertificate
	json.Unmarshal([]byte(TagCert1), &tc1)
	json.Unmarshal([]byte(TagCert2), &tc2)
	json.Unmarshal([]byte(TagCert3), &tc3)
	json.Unmarshal([]byte(TagCert4), &tc4)
	json.Unmarshal([]byte(TagCert5), &tc5)
	json.Unmarshal([]byte(TagCert6), &tc6)
	json.Unmarshal([]byte(TagCert7), &tc7)

	// add to store
	store.Create(&tc1)
	store.Create(&tc2)
	store.Create(&tc3)
	store.Create(&tc4)
	store.Create(&tc5)
	store.Create(&tc6)
	store.Create(&tc7)

	return store
}
