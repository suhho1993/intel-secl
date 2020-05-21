/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

const (
	goodSignedPlatformFlavor string = `{
            "flavor": {
                "meta": {
                    "id": "13276738-d81b-470d-824b-72adae9c55dc",
                    "description": {
                        "flavor_part": "PLATFORM",
                        "source": "m23ru6.fm.intel.com",
                        "label": "INTEL_IntelCorporation_SE5C620.86B.00.01.0014.070920180847_TXT_TPM_03-18-2020_17-28-08",
                        "bios_name": "Intel Corporation",
                        "bios_version": "SE5C620.86B.00.01.0014.070920180847",
                        "tpm_version": "2.0",
                        "tboot_installed": "true"
                    },
                    "vendor": "INTEL"
                },
                "bios": {
                    "bios_name": "Intel Corporation",
                    "bios_version": "SE5C620.86B.00.01.0014.070920180847"
                },
                "hardware": {
                    "processor_info": "54 06 05 00 FF FB EB BF",
                    "feature": {
                        "tpm": {
                            "enabled": true,
                            "version": "2.0",
                            "pcr_banks": [
                                "SHA1",
                                "SHA256"
                            ]
                        },
                        "txt": {
                            "enabled": true
                        }
                    }
                },
                "pcrs": {
                    "SHA1": {
                        "pcr_0": {
                            "value": "3f95ecbb0bb8e66e54d3f9e4dbae8fe57fed96f0"
                        },
                        "pcr_17": {
                            "value": "b1908af38c1ead39b275ee1e77031cb119803e3f",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "19f7c22f6c92d9555d792466b2097443444ebd26",
                                    "label": "HASH_START",
                                    "info": {
                                        "ComponentName": "HASH_START",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "3cf4a5c90911c21f6ea71f4ca84425f8e65a2be7",
                                    "label": "BIOSAC_REG_DATA",
                                    "info": {
                                        "ComponentName": "BIOSAC_REG_DATA",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "3c585604e87f855973731fea83e21fab9392d2fc",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                                    "label": "LCP_DETAILS_HASH",
                                    "info": {
                                        "ComponentName": "LCP_DETAILS_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                                    "label": "STM_HASH",
                                    "info": {
                                        "ComponentName": "STM_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "ff86d5446b2cc2e7e3319048715c00aabb7dcc4e",
                                    "label": "MLE_HASH",
                                    "info": {
                                        "ComponentName": "MLE_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        },
                        "pcr_18": {
                            "value": "86da61107994a14c0d154fd87ca509f82377aa30",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "a395b723712b3711a89c2bb5295386c0db85fe44",
                                    "label": "SINIT_PUBKEY_HASH",
                                    "info": {
                                        "ComponentName": "SINIT_PUBKEY_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "3c585604e87f855973731fea83e21fab9392d2fc",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                                    "label": "LCP_AUTHORITIES_HASH",
                                    "info": {
                                        "ComponentName": "LCP_AUTHORITIES_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    },
                    "SHA256": {
                        "pcr_0": {
                            "value": "1009d6bc1d92739e4e8e3c6819364f9149ee652804565b83bf731bdb6352b2a6"
                        },
                        "pcr_17": {
                            "value": "331b5a626d140d9beeef61dd997cc7858388ce4f8960bef17b519aa1194733a8",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "14fc51186adf98be977b9e9b65fc9ee26df0599c4f45804fcc45d0bdcf5025db",
                                    "label": "HASH_START",
                                    "info": {
                                        "ComponentName": "HASH_START",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "c61aaa86c13133a0f1e661faf82e74ba199cd79cef652097e638a756bd194428",
                                    "label": "BIOSAC_REG_DATA",
                                    "info": {
                                        "ComponentName": "BIOSAC_REG_DATA",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                                    "label": "LCP_DETAILS_HASH",
                                    "info": {
                                        "ComponentName": "LCP_DETAILS_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                                    "label": "STM_HASH",
                                    "info": {
                                        "ComponentName": "STM_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "236043f5120fce826392d2170dc84f2491367cc8d8d403ab3b83ec24ea2ca186",
                                    "label": "MLE_HASH",
                                    "info": {
                                        "ComponentName": "MLE_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        },
                        "pcr_18": {
                            "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
                                    "label": "SINIT_PUBKEY_HASH",
                                    "info": {
                                        "ComponentName": "SINIT_PUBKEY_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                                    "label": "LCP_AUTHORITIES_HASH",
                                    "info": {
                                        "ComponentName": "LCP_AUTHORITIES_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            "signature": "A6oQ/N7kxxn6u1LlO3rMnXEYkgltfu/EP8SZ4ZAsSwlLAr1lGfPjEXiHJ2ua9jDJ5hmiIw4iL7leTFnF54bxw0napG1Uii5VkeJXmI8ltyautkE9oNJB0Zrp9F1Io1NrozCNh3pGlLNZvd+LmVgl75AkIQ64OessoHiVogdAcDNuUZpABpbDBeG6CIZWBSuLUFXQjhljddAwwwmF3+/jKa3YO4FbnwHsxZyEdTij/WUs2n8W2mrFaxb7ldPlL3mB8YFJjubvtdGW0xjgosh24NyA1lG5yLZ/PPTm8d3c4qwOJcGypbUGFZYGtjWZ2YVPm80ts7bIXtwv0tCOUUVOb7Q2qT7ONYA/WjPykxpOzXoebVRPMUlEbigw8/jnaa/H8AaEdxoqgYUF4cjujcCmqANnlKEnqgs7mQZ02JmPNbXKH2VzK9Z90zaZ/Dt3gLFoF9pIRWm/QkVOnj1q73DoYpKrBWziOPZ/w67xKq70pmxZIatJt/MQvCy2T86tt/fb"
        }
`
	goodSignedOSFlavor string = `{
            "flavor": {
                "meta": {
                    "id": "0a0c6379-1370-4b04-bd62-61d55195056f",
                    "description": {
                        "flavor_part": "OS",
                        "source": "m23ru6.fm.intel.com",
                        "label": "INTEL_RedHatEnterprise_8.1_Virsh_4.5.0_03-18-2020_17-28-08",
                        "os_name": "RedHatEnterprise",
                        "os_version": "8.1",
                        "vmm_name": "Virsh",
                        "vmm_version": "4.5.0",
                        "tpm_version": "2.0",
                        "tboot_installed": "true"
                    },
                    "vendor": "INTEL"
                },
                "bios": {
                    "bios_name": "Intel Corporation",
                    "bios_version": "SE5C620.86B.00.01.0014.070920180847"
                },
                "pcrs": {
                    "SHA1": {
                        "pcr_17": {
                            "value": "b1908af38c1ead39b275ee1e77031cb119803e3f",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "4259eb5fdb6d447f845d65b7a349772c0bc24d9c",
                                    "label": "vmlinuz",
                                    "info": {
                                        "ComponentName": "vmlinuz",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    },
                    "SHA256": {
                        "pcr_17": {
                            "value": "331b5a626d140d9beeef61dd997cc7858388ce4f8960bef17b519aa1194733a8",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "aa1a5a227e3446af8e197081e91b5f4a791015e5a741d5b40a57a08374ad3ba2",
                                    "label": "vmlinuz",
                                    "info": {
                                        "ComponentName": "vmlinuz",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            "signature": "e99IEUQv3YtHZTncjxz68jOEU8wShT8Ti7s9l4BQ4b/o6e42ZQOqcpoacxg0MwXwMqPgu9SAZ9UkBfq0+k/UjSwa7jVDFBtFBtwAFVWIEJrLi7Gru6XNco0Bdunvxu7F68wTwlIOZxZQSKh1ePPGOKoPT+iX/aaLt5wyxB6mugsiBN3si3yUuGe9+x3+ifp5g//xzApSXDVyaPY193Ri/9y/heGkm0VCv7ntOqdxspjrCS0zGlcAjdTHKAYkcP7T+gdOhfvJ3AiPWzgzmhvmJ8jku6HjCSlQr2FJIPEgvSJQ7FJg5tJolO8+sTmucG9d6N4eX0JisMCpztZ+bEicJ0+jgVcTqeLofJlw4hD+hNousDg0FySDCm6yOzztXY6kcCE4o6MW1Lx0z93Z3VJgXHFeL5HyoXoVXmgKSxqSDDqz3LmO6uDpsb4WA564FQzBjgaDTUCmGxye6dtEzhjfZI0VKOSzuA0JLEcOj3qTPgzO7kCa3ovebnxHmi+wvZUo"
        }
`
	goodSignedHostUniqueFlavor string = `{
            "flavor": {
                "meta": {
                    "id": "382a1f92-90a7-4538-99b9-0dba89a63994",
                    "description": {
                        "flavor_part": "HOST_UNIQUE",
                        "source": "m23ru6.fm.intel.com",
                        "label": "INTEL_803F6068-06DA-E811-906E-00163566263E_03-18-2020_17-28-08",
                        "bios_name": "Intel Corporation",
                        "bios_version": "SE5C620.86B.00.01.0014.070920180847",
                        "os_name": "RedHatEnterprise",
                        "os_version": "8.1",
                        "tpm_version": "2.0",
                        "hardware_uuid": "803F6068-06DA-E811-906E-00163566263E",
                        "tboot_installed": "true"
                    },
                    "vendor": "INTEL"
                },
                "pcrs": {
                    "SHA1": {
                        "pcr_17": {
                            "value": "b1908af38c1ead39b275ee1e77031cb119803e3f",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "9069ca78e7450a285173431b3e52c5c25299e473",
                                    "label": "LCP_CONTROL_HASH",
                                    "info": {
                                        "ComponentName": "LCP_CONTROL_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "33ce67be138b41d007510f229374bf1fa0e37fe7",
                                    "label": "initrd",
                                    "info": {
                                        "ComponentName": "initrd",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        },
                        "pcr_18": {
                            "value": "86da61107994a14c0d154fd87ca509f82377aa30",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "9069ca78e7450a285173431b3e52c5c25299e473",
                                    "label": "LCP_CONTROL_HASH",
                                    "info": {
                                        "ComponentName": "LCP_CONTROL_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    },
                    "SHA256": {
                        "pcr_17": {
                            "value": "331b5a626d140d9beeef61dd997cc7858388ce4f8960bef17b519aa1194733a8",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
                                    "label": "LCP_CONTROL_HASH",
                                    "info": {
                                        "ComponentName": "LCP_CONTROL_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "6643aedfa66e0d1f17c9364e31024cb503a6f7f6f3823b929889d656b833ef0e",
                                    "label": "initrd",
                                    "info": {
                                        "ComponentName": "initrd",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        },
                        "pcr_18": {
                            "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
                                    "label": "LCP_CONTROL_HASH",
                                    "info": {
                                        "ComponentName": "LCP_CONTROL_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            "signature": "n0b2mEa7y0QkVZzLt2+nhutVHPjf0zUdlln7G6nXrwflnSJjdBne+l7dpAci9zTyOewGTFtSBI7K2Mdr6f5QqHwCxec5WBIkdhUI08PhvQNmhgdQYDn9EZ2+cau/2hNnge+PZiSaY44dt5DKQyEUcyXxFWgzTtQeKErHxa1J66EIBksQvbVVcKtr1ZG31uhdqakIRrSFPJDeTaIqPWE29hmz+u6oBdk8/kHcT9UV/M144gXdAqP+mmuDlt5gSRk+wIrFcug2uPD7BJhZORu0e69ggH+TrToA9vgxKLuUEBQttm4iW1ebJJPjI2NuyeA1r1b9sFR/7xyReMDwQ40sjrNgxiyQ3f037tn/GchjJPIB4PbATfeqSeucyEoBxUlvNwmER2DO7ZpZ4dp40pvnNwsCoPw4VzAi64L19c484LWS8pHjpRE4HDxmbRtm5Ta5FdggEGz0eK5Qxlnjjv6jVTSuU3bxrtY4E8GFYZC+fJkGdnW7HkG1lo7KEgoiVuCa"
        }`
	goodSignedSoftwareFlavor string = `{
            "flavor": {
                "meta": {
                    "schema": {
                        "uri": "lib:wml:measurements:1.0"
                    },
                    "id": "c206e9c4-f394-42e5-a6aa-f28467eada3f",
                    "description": {
                        "flavor_part": "SOFTWARE",
                        "label": "ISecL_Default_Workload_Flavor_v1.0",
                        "digest_algorithm": "SHA384"
                    }
                },
                "software": {
                    "measurements": {
                        "opt-workload-agent-bin": {
                            "type": "directoryMeasurementType",
                            "value": "e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a",
                            "Path": "/opt/workload-agent/bin",
                            "Include": ".*",
                            "Exclude": ""
                        },
                        "opt-workload-agent-bin-wlagent": {
                            "type": "fileMeasurementType",
                            "value": "62adb091ca53d6907624fc564c686d614d10bb49396dad946dc9f0bec0fb14941a61dc375cf6fb314416305ea63a09c0",
                            "Path": "/opt/workload-agent/bin/wlagent"
                        }
                    },
                    "cumulative_hash": "4e8b4ac979106494f2707d7ce8ac11520144dce5459866ba5e0edc274875676e04c5e441699d76311d45aff1f8fd1e59"
                }
            },
            "signature": "kCb0j179THrSiIhglLzmSed84C4lvjSVBE4hdEThZ/6BheuUTvAB7Je4gGNRfnESgr4m8d/PPFIGQdY62AJl251oT6k6KaESPQCjPRq0EL9xfZBhksLA+42RcmEgIyIYZvtmx/9lWCZOmKZkT/0pYEW7VTgmUgFG33ah/JWL+peFfu4G1uaE4ZiOImPT3A6bybUKIglaNAZq75mGkRhSR63Gy81v4CRugrI+Oye6GeMh+A9PUJLb2sprVXqQPQc2ru1OqpkpARbi0Cj+12E6m29ZVPTL8IDlSkQbYlXL+eNaleISaHyKQ78mP0DotrPsBQNx3pSyRAAqJdlzRiP8mCjxWWOzcK9jcyakeYtAiqGEW6wG7OdBEcZlC6LWQd7OyKPu/dN14KK5q19+/haqhvsAs3dEJr4KKWhEzv23KksOMJTBQFXf1eRyY+SPL0UK9Bonpa6JyHlqaQ4wDQoJ0N6+CqQ9wLNnIBCNEtGHrbU9dWQnOo79qLKTOGCCEFsw"
        }`
	goodSignedAssetTagFlavor string = `{
            "flavor": {
                "meta": {
                    "id": "a04e4818-450c-479c-bf8a-0510f9660c1d",
                    "description": {
                        "flavor_part": "ASSET_TAG",
                        "label": "INTEL_803F6068-06DA-E811-906E-00163566263E_03-18-2020_17-28-06",
                        "hardware_uuid": "803F6068-06DA-E811-906E-00163566263E"
                    },
                    "vendor": "INTEL"
                },
                "external": {
                    "asset_tag": {
                        "tag_certificate": {
                            "encoded": "MIIChTCB7gIBATAfoR2kGzAZMRcwFQYBaQQQgD9gaAba6BGQbgAWNWYmPqAiMCCkHjAcMRowGAYDVQQDDBFhc3NldC10YWctc2VydmljZTANBgkqhkiG9w0BAQwFAAIGAXDwMKncMCIYDzIwMjAwMzE5MDAyODA1WhgPMjAyMTAzMTkwMDI4MDVaMGkwIAYFVQSGFQIxFzAVDAVTVEFURTAMDApDQUxJRk9STklBMBcGBVUEhhUCMQ4wDAwDVFBNMAUMAzIuMDAsBgVVBIYVAjEjMCEMCEhPU1ROQU1FMBUME20yM3J1Ni5mbS5pbnRlbC5jb20wDQYJKoZIhvcNAQEMBQADggGBAHKyvzsiRGUAECqqnT4KWuE6uF+chxJS+hkAUSth1MFu75HhNhMo3hOGyl1cfwzaL0d1kCMqNz0FlhH+XwT1maXR4BFkg9G/cdT4BgBhpcfiSSUuj0pUV0rH1NR1KD+DXdF0kenrOakg6hi350KX+9Y7qrfyF2YGUAKt4xrWZWpHDpHwW+Tvs68ZbcApvt4KBAsK3b+TV9DhePEF9u7NSHRnLZ/DR5BrrOIzDV0pGMOOHHYJGWmAVKOfpoGmipx1lTiDBCfxgEA4U0rIBu6mQjY1vMQu2vQi0aIaUtoUh+DfqgstaKjUA2KLymZ5OY+dl2weB+ZHpeJYnriBJmncOwENchNzGt26CGYE/cxXJR8axv4vaqggruMY3DJAv8rQWsJLTUA0nLk/90vIHfXWA7KSjJUKbSRfJvBu7tNAjrT0w4MWEGv8P0AmHDsoPEP77kAwqfdIo+72SZig8rDAlwLFxmcM4h7L5PjumwPJQG3g1aEitFAkaHBu2lsjZC652w==",
                            "issuer": "CN=asset-tag-service",
                            "serial_number": 1584577685980,
                            "subject": "803f6068-06da-e811-906e-00163566263e",
                            "not_before": "2020-03-18T17:28:05-0700",
                            "not_after": "2021-03-18T17:28:05-0700",
                            "attribute": [
                                {
                                    "attr_type": {
                                        "id": "2.5.4.789.2"
                                    },
                                    "attribute_values": [
                                        {
                                            "objects": {}
                                        }
                                    ]
                                },
                                {
                                    "attr_type": {
                                        "id": "2.5.4.789.2"
                                    },
                                    "attribute_values": [
                                        {
                                            "objects": {}
                                        }
                                    ]
                                },
                                {
                                    "attr_type": {
                                        "id": "2.5.4.789.2"
                                    },
                                    "attribute_values": [
                                        {
                                            "objects": {}
                                        }
                                    ]
                                }
                            ],
                            "fingerprint_sha384": "rSHW/ijNPDapZkZ2FBsJXSWszHNa1RK3e2wdPJpBxTyoG2o9JJAJ4CbGF4bfTq/R"
                        }
                    }
                }
            },
            "signature": "kmiFgoWF5CZ6EDg/iz6NM1vzApYSdlmRblEZ9r76FHjhuYjqqyJTYEkxf1igFjEFIsJ3CmHVw1aPeUrncMnu+gvMfsJwfknOdhbDhqTyKtQBVNoMvrVGXV9kqkZvQ6OScev9nOcIQ/ahOUTV9TaRWbeulWMfheP32+4UZxUywWA3zpzvnjIKi7M0feWUZy5lV/ocOvaWYK8sYntsSi5ICEsLO63oKmT5RECxOPi/Pos9kmWkuzBzllytCvmDXpyswsCt5h1fmX1ytdC4vY37rcRozD/rSxw5RDH3pUR6h2GPVdrUDQ6VI7qOw2S73tZaTRJSMpZW9EVflTIbfUJC+Ft+y4rQ7cFQJDKOAppHYEv0AnB6Iy98n3M40ZPCB9qDYpNswq7ufBdaX2EADoYBc6QzsvcIEHNPyEw5QgkAjsj6ckGuhRg31KBPV0vw8Xjvmu+CnD+I1yKq9AVGdBqZZ66dUALP1Y/MJfP9vPPrRwiEx3IZcTKLftCiJVqIviEF"
        }`
)

func TestNewSignedFlavorFromJSONPlatform(t *testing.T) {
	type args struct {
		ipflavorjson string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Unmarshal Signed Platform flavor",
			args: args{
				ipflavorjson: goodSignedPlatformFlavor,
			},
		},
		{
			name: "Unmarshal Signed OS flavor",
			args: args{
				ipflavorjson: goodSignedOSFlavor,
			},
		},
		{
			name: "Unmarshal Signed Host Unique flavor",
			args: args{
				ipflavorjson: goodSignedHostUniqueFlavor,
			},
		},
		{
			name: "Unmarshal Signed Software flavor",
			args: args{
				ipflavorjson: goodSignedSoftwareFlavor,
			},
		},
		{
			name: "Unmarshal Signed Asset Tag flavor",
			args: args{
				ipflavorjson: goodSignedAssetTagFlavor,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unmarshal the flavor JSON
			got1, _ := NewSignedFlavorFromJSON(tt.args.ipflavorjson)
			if got1 == nil {
				t.Errorf("SignedFlavor creation failed: %v", got1)
			}

			// Marshal flavor back to string
			strsf, err := json.Marshal(got1)
			if err != nil {
				t.Errorf("Error marshaling SignedFlavor to JSON: %s", err.Error())
			}

			// Perform unmarshal on the newly fetched string
			got2, _ := NewSignedFlavorFromJSON(tt.args.ipflavorjson)
			if got1 == nil {
				t.Errorf("SignedFlavor creation failed: %v", got1)
			}

			assert.True(t, reflect.DeepEqual(got1, got2), "2-way model check failed")

			t.Logf("Before Unmarshal: %s\nAfter Marshal: %v\nAfter Marshal:%s", tt.args.ipflavorjson, got1, strsf)
		})
	}
}
