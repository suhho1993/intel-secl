/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * kmipclient.h
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#ifndef KMIPCLIENT_H_
#define KMIPCLIENT_H_

int kmipw_init(const char *address, const char *port, const char *certificate, const char *key, const char *ca);
const char* kmipw_create(int alg_id, int alg_length);
int kmipw_destroy(const char *id);
int kmipw_get(const char *id, char *kbs_key);

#endif /* KMIPCLIENT_H_ */
