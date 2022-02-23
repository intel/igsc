/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2022 Intel Corporation
 */

#ifndef __IGSC_OPROM_PARSER_H__
#define  __IGSC_OPROM_PARSER_H__

int image_oprom_alloc_handle(struct igsc_oprom_image **img,
                             const uint8_t *buffer, uint32_t buffer_len);
void image_oprom_free_handle(struct igsc_oprom_image *img);

int image_oprom_parse(struct igsc_oprom_image *img);

int image_oprom_get_version(struct igsc_oprom_image *img,
                            enum igsc_oprom_type type,
                            struct igsc_oprom_version *version);
enum igsc_oprom_type image_oprom_get_type(struct igsc_oprom_image *img);

uint32_t image_oprom_count_devices(struct igsc_oprom_image *img);

int image_oprom_get_device(struct igsc_oprom_image *img, uint32_t num,
                           struct oprom_subsystem_device_id *device);
int image_oprom_get_next(struct igsc_oprom_image *img,
                         struct igsc_oprom_device_info *device);

void image_oprom_iterator_reset(struct igsc_oprom_image *img);

int image_oprom_get_buffer(struct igsc_oprom_image *img,
                           enum igsc_oprom_type type,
                           const uint8_t **buffer,
                           size_t *buffer_len);

uint32_t image_oprom_count_devices_4ids(struct igsc_oprom_image *img,
                                        enum igsc_oprom_type type);
void image_oprom_iterator_reset_4ids(struct igsc_oprom_image *img,
                                     enum igsc_oprom_type type);
int image_oprom_get_device_4ids(struct igsc_oprom_image *img, uint32_t pos,
                                enum igsc_oprom_type type,
                                struct oprom_subsystem_device_4ids *device);
int image_oprom_get_next_4ids(struct igsc_oprom_image *img,
                              enum igsc_oprom_type type,
                              struct igsc_oprom_device_info_4ids *device);

#endif /* !__IGSC_OPROM_PARSER_H__ */
