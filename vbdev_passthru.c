/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is a simple example of a virtual block device module that passes IO
 * down to a bdev (or bdevs) that its configured to attach to.
 */

#include "vbdev_passthru.h"
#include "spdk/env.h"
#include "spdk/conf.h"
#include "spdk/endian.h"
#include "spdk/bdev.h"
#include "spdk/thread.h"
#include "spdk/stdinc.h"
#include "spdk/bdev.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/bdev_module.h"
#include <stdio.h>
#include <string.h>
#include "spdk/stdinc.h"

static int vbdev_passthru_init(void);
static int vbdev_passthru_get_ctx_size(void);
static void vbdev_passthru_examine(struct spdk_bdev *bdev);
static void vbdev_passthru_finish(void);
static int vbdev_passthru_config_json(struct spdk_json_write_ctx *w);

static struct spdk_bdev_module passthru_if = {
	.name = "passthru",
	.module_init = vbdev_passthru_init,
	.get_ctx_size = vbdev_passthru_get_ctx_size,
	.examine_config = vbdev_passthru_examine,
	.module_fini = vbdev_passthru_finish,
	.config_json = vbdev_passthru_config_json};

#define CHUNK_SIZE 64
#define TOTAL_LEN_LEN 8

SPDK_BDEV_MODULE_REGISTER(passthru, &passthru_if)
/* configuration struct for the Time Based RAID algorithm */
struct time_based_raid_configuration
{
	int partitions_number;		   // the number of partitions that we create in the bdev storgate
	int selected_partition_number; // chosen partiton in the time based raid algoirthm
	int calculate_honeypot_sha256; // start to calculate the honeypot sha256 result
	uint64_t honeypot_start_calculation_address;
};

/*struct instance */
struct time_based_raid_configuration time_based_raid_configuration_inst = {3, 2, 0}; // Global declaration of structure time based raid configuration
																					 //
/* List of pt_bdev names and their base bdevs via configuration file.
 * Used so we can parse the conf once at init and use this list in examine().
 */
struct bdev_names
{
	char *vbdev_name;
	char *bdev_name;
	TAILQ_ENTRY(bdev_names)
	link;
};
static TAILQ_HEAD(, bdev_names) g_bdev_names = TAILQ_HEAD_INITIALIZER(g_bdev_names);

/* List of virtual bdevs and associated info for each. */
struct vbdev_passthru
{
	struct spdk_bdev *base_bdev;	  /* the thing we're attaching to */
	struct spdk_bdev_desc *base_desc; /* its descriptor we get from open */
	struct spdk_bdev pt_bdev;		  /* the PT virtual bdev */
	TAILQ_ENTRY(vbdev_passthru)
	link;
};
static TAILQ_HEAD(, vbdev_passthru) g_pt_nodes = TAILQ_HEAD_INITIALIZER(g_pt_nodes);

/* The pt vbdev channel struct. It is allocated and freed on my behalf by the io channel code.
 * If this vbdev needed to implement a poller or a queue for IO, this is where those things
 * would be defined. This passthru bdev doesn't actually need to allocate a channel, it could
 * simply pass back the channel of the bdev underneath it but for example purposes we will
 * present its own to the upper layers.
 */
struct pt_io_channel
{
	struct spdk_io_channel *base_ch; /* IO channel of base device */
	char *buff;
};

struct pt_io_channel pt_io_channel_inst;

/* Just for fun, this pt_bdev module doesn't need it but this is essentially a per IO
 * context that we get handed by the bdev layer.tun
 */
struct passthru_bdev_io
{
	uint8_t test;

	/* bdev related */
	struct spdk_io_channel *ch;

	/* for bdev_io_wait */
	struct spdk_bdev_io_wait_entry bdev_io_wait;
};

struct canary_file_struct
{
	long int canary_file_size;
	char hash_string[65];
};

struct canary_file_struct canary_file_struct_inst;
/*
 * ABOUT bool: this file does not use bool in order to be as pre-C99 compatible as possible.
 */

/*
 * Comments from pseudo-code at https://en.wikipedia.org/wiki/SHA-2 are reproduced here.
 * When useful for clarification, portions of the pseudo-code are reproduced here too.
 */

/*
 * Initialize array of round constants:
 * (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
 */
static const uint32_t k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct buffer_state
{
	const uint8_t *p;
	size_t len;
	size_t total_len;
	int single_one_delivered; /* bool */
	int total_len_delivered;  /* bool */
};

static inline uint32_t right_rot(uint32_t value, unsigned int count)
{
	/*
	 * Defined behaviour in standard C for all count where 0 < count < 32,
	 * which is what we need here.
	 */
	return value >> count | value << (32 - count);
}

static void
init_buf_state(struct buffer_state *state, const void *input, size_t len)
{
	state->p = (uint8_t const *)input;
	state->len = len;
	state->total_len = len;
	state->single_one_delivered = 0;
	state->total_len_delivered = 0;
}

/* Return value: bool */

static void
hash_to_string(char string[65], const uint8_t hash[32])
{
	size_t i;
	for (i = 0; i < 32; i++)
	{
		string += sprintf(string, "%02x", hash[i]);
	}
}

static void
vbdev_passthru_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io);

/* Callback for unregistering the IO device. */
static void
_device_unregister_cb(void *io_device)
{
	struct vbdev_passthru *pt_node = io_device;

	/* Done with this pt_node. */
	free(pt_node->pt_bdev.name);
	free(pt_node);
}

/* Called after we've unregistered following a hot remove callback.
 * Our finish entry point will be called next.
 */
static int
vbdev_passthru_destruct(void *ctx)
{
	struct vbdev_passthru *pt_node = (struct vbdev_passthru *)ctx;

	/* It is important to follow this exact sequence of steps for destroying
	 * a vbdev...
	 */

	TAILQ_REMOVE(&g_pt_nodes, pt_node, link);

	/* Unclaim the underlying bdev. */
	spdk_bdev_module_release_bdev(pt_node->base_bdev);

	/* Close the underlying bdev. */
	spdk_bdev_close(pt_node->base_desc);

	/* Unregister the io_device. */
	spdk_io_device_unregister(pt_node, _device_unregister_cb);

	return 0;
}

/* Completion callback for IO that were issued from this bdev. The original bdev_io
 * is passed in as an arg so we'll complete that one with the appropriate status
 * and then free the one that this module issued.
 */
static void
_pt_complete_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	int status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;
	struct passthru_bdev_io *io_ctx = (struct passthru_bdev_io *)orig_io->driver_ctx;

	/* We setup this value in the submission routine, just showing here that it is
	 * passed back to us.
	 */
	if (io_ctx->test != 0x5a)
	{
		SPDK_ERRLOG("Error, original IO device_ctx is wrong! 0x%x\n",
					io_ctx->test);
	}

	/* Complete the original IO and then free the one that we created here
	 * as a result of issuing an IO via submit_reqeust.
	 */
	spdk_bdev_io_complete(orig_io, status);
	spdk_bdev_free_io(bdev_io);
}

static void
vbdev_passthru_resubmit_io(void *arg)
{
	struct spdk_bdev_io *bdev_io = (struct spdk_bdev_io *)arg;
	struct passthru_bdev_io *io_ctx = (struct passthru_bdev_io *)bdev_io->driver_ctx;

	vbdev_passthru_submit_request(io_ctx->ch, bdev_io);
}

static void
vbdev_passthru_queue_io(struct spdk_bdev_io *bdev_io)
{
	struct passthru_bdev_io *io_ctx = (struct passthru_bdev_io *)bdev_io->driver_ctx;
	int rc;

	io_ctx->bdev_io_wait.bdev = bdev_io->bdev;
	io_ctx->bdev_io_wait.cb_fn = vbdev_passthru_resubmit_io;
	io_ctx->bdev_io_wait.cb_arg = bdev_io;

	rc = spdk_bdev_queue_io_wait(bdev_io->bdev, io_ctx->ch, &io_ctx->bdev_io_wait);
	if (rc != 0)
	{
		SPDK_ERRLOG("Queue io failed in vbdev_passthru_queue_io, rc=%d.\n", rc);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
	}
}

/* Callback for getting a buf from the bdev pool in the event that the caller passed
 * in NULL, we need to own the buffer so it doesn't get freed by another vbdev module
 * beneath us before we're done with it. That won't happen in this example but it could
 * if this example were used as a template for something more complex.
 */
static void
pt_read_get_buf_cb(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io, bool success)
{
	struct vbdev_passthru *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_passthru,
													  pt_bdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct passthru_bdev_io *io_ctx = (struct passthru_bdev_io *)bdev_io->driver_ctx;
	int rc;

	if (!success)
	{
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	if (bdev_io->u.bdev.md_buf == NULL)
	{
		rc = spdk_bdev_readv_blocks(pt_node->base_desc, pt_ch->base_ch, bdev_io->u.bdev.iovs,
									bdev_io->u.bdev.iovcnt, bdev_io->u.bdev.offset_blocks,
									bdev_io->u.bdev.num_blocks, _pt_complete_io,
									bdev_io);
	}
	else
	{
		rc = spdk_bdev_readv_blocks_with_md(pt_node->base_desc, pt_ch->base_ch,
											bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
											bdev_io->u.bdev.md_buf,
											bdev_io->u.bdev.offset_blocks,
											bdev_io->u.bdev.num_blocks,
											_pt_complete_io, bdev_io);
	}

	if (rc != 0)
	{
		if (rc == -ENOMEM)
		{
			SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
			io_ctx->ch = ch;
			vbdev_passthru_queue_io(bdev_io);
		}
		else
		{
			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}

static void
simple_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct sdpk_bdev *bdev = cb_arg;
	
	if (!success)
	{
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	if (pt_io_channel_inst.buff == NULL)
	{
		SPDK_NOTICELOG("Empty buff\n");
	}
	else
	{

		spdk_bdev_free_io(bdev_io);
		SPDK_NOTICELOG("Read Completed\n");
	}
	
}
static void
simple_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct sdpk_bdev *bdev = cb_arg;

	if (!success)
	{
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	spdk_bdev_free_io(bdev_io);
	spdk_dma_free(pt_io_channel_inst.buff);
	SPDK_NOTICELOG("Write Completed\n");
}

/* Called when someone above submits IO to this pt vbdev. We're simply passing it on here
 * via SPDK IO calls which in turn allocate another bdev IO and call our cpl callback provided
 * below along with the original bdiv_io so that we can complete it once this IO completes.
 */
static void
vbdev_passthru_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct vbdev_passthru *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_passthru, pt_bdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct passthru_bdev_io *io_ctx = (struct passthru_bdev_io *)bdev_io->driver_ctx;
	int rc = 0;
	// int i =0;
	// uint64_t  gpt_table_final_address =35;

	/* Setup a per IO context value; we don't do anything with it in the vbdev other
	 * than confirm we get the same thing back in the completion callback just to
	 * demonstrate.
	 */
	io_ctx->test = 0x5a;
	// Start of Time Based RAID Code
	if (strcmp(pt_node->pt_bdev.name, "honeypot") != 0)
	{
		bdev_io->u.bdev.offset_blocks = bdev_io->u.bdev.offset_blocks + time_based_raid_configuration_inst.selected_partition_number * pt_node->pt_bdev.blockcnt;

		pt_node->pt_bdev.blockcnt = pt_node->pt_bdev.blockcnt * time_based_raid_configuration_inst.partitions_number;
		bdev_io->bdev->blockcnt = bdev_io->bdev->blockcnt * time_based_raid_configuration_inst.partitions_number;
		// bdev_io->u.bdev.offset_blocks =bdev_io->u.bdev.offset_blocks*time_based_raid_configuration_inst.partitions_number;
	}

	// if the user configured read honeypot

	// end of Time Based RAID code
	switch (bdev_io->type)
	{
	case SPDK_BDEV_IO_TYPE_READ:
		spdk_bdev_io_get_buf(bdev_io, pt_read_get_buf_cb,
							 bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
		if (bdev_io->u.bdev.md_buf == NULL)
		{
			rc = spdk_bdev_writev_blocks(pt_node->base_desc, pt_ch->base_ch, bdev_io->u.bdev.iovs,
										 bdev_io->u.bdev.iovcnt, bdev_io->u.bdev.offset_blocks,
										 bdev_io->u.bdev.num_blocks, _pt_complete_io,
										 bdev_io);
		}
		else
		{
			rc = spdk_bdev_writev_blocks_with_md(pt_node->base_desc, pt_ch->base_ch,
												 bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
												 bdev_io->u.bdev.md_buf,
												 bdev_io->u.bdev.offset_blocks,
												 bdev_io->u.bdev.num_blocks,
												 _pt_complete_io, bdev_io);
		}
		break;
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		rc = spdk_bdev_write_zeroes_blocks(pt_node->base_desc, pt_ch->base_ch,
										   bdev_io->u.bdev.offset_blocks,
										   bdev_io->u.bdev.num_blocks,
										   _pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_UNMAP:
		rc = spdk_bdev_unmap_blocks(pt_node->base_desc, pt_ch->base_ch,
									bdev_io->u.bdev.offset_blocks,
									bdev_io->u.bdev.num_blocks,
									_pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_FLUSH:
		rc = spdk_bdev_flush_blocks(pt_node->base_desc, pt_ch->base_ch,
									bdev_io->u.bdev.offset_blocks,
									bdev_io->u.bdev.num_blocks,
									_pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_RESET:
		rc = spdk_bdev_reset(pt_node->base_desc, pt_ch->base_ch,
							 _pt_complete_io, bdev_io);
		break;
	default:
		SPDK_ERRLOG("passthru: unknown I/O type %d\n", bdev_io->type);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	if (rc != 0)
	{
		if (rc == -ENOMEM)
		{
			SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
			io_ctx->ch = ch;
			vbdev_passthru_queue_io(bdev_io);
		}
		else
		{
			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
	if (strcmp(pt_node->pt_bdev.name, "honeypot") != 0)
	{
		pt_node->pt_bdev.blockcnt = pt_node->pt_bdev.blockcnt / time_based_raid_configuration_inst.partitions_number;
		bdev_io->bdev->blockcnt = bdev_io->bdev->blockcnt / time_based_raid_configuration_inst.partitions_number;
	}
}

/* Called when someone above submits IO to this pt vbdev. We're simply passing it on here
 * via SPDK IO calls which in turn allocate another bdev IO and call our cpl callback provided
 * below along with the original bdiv_io so that we can complete it once this IO completes.
 */

static bool
vbdev_passthru_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	struct vbdev_passthru *pt_node = (struct vbdev_passthru *)ctx;

	return spdk_bdev_io_type_supported(pt_node->base_bdev, io_type);
}

/* We supplied this as an entry point for upper layers who want to communicate to this
 * bdev.  This is how they get a channel. We are passed the same context we provided when
 * we created our PT vbdev in examine() which, for this bdev, is the address of one of
 * our context nodes. From here we'll ask the SPDK channel code to fill out our channel
 * struct and we'll keep it in our PT node.
 */
static struct spdk_io_channel *
vbdev_passthru_get_io_channel(void *ctx)
{
	struct vbdev_passthru *pt_node = (struct vbdev_passthru *)ctx;
	struct spdk_io_channel *pt_ch = NULL;

	/* The IO channel code will allocate a channel for us which consists of
	 * the SPDK channel structure plus the size of our pt_io_channel struct
	 * that we passed in when we registered our IO device. It will then call
	 * our channel create callback to populate any elements that we need to
	 * update.
	 */
	pt_ch = spdk_get_io_channel(pt_node);

	return pt_ch;
}

/* This is the output for get_bdevs() for this vbdev */
static int
vbdev_passthru_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct vbdev_passthru *pt_node = (struct vbdev_passthru *)ctx;

	spdk_json_write_name(w, "passthru");
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "name", spdk_bdev_get_name(&pt_node->pt_bdev));
	spdk_json_write_named_string(w, "base_bdev_name", spdk_bdev_get_name(pt_node->base_bdev));
	spdk_json_write_object_end(w);

	return 0;
}

/* This is used to generate JSON that can configure this module to its current state. */
static int
vbdev_passthru_config_json(struct spdk_json_write_ctx *w)
{
	struct vbdev_passthru *pt_node;

	TAILQ_FOREACH(pt_node, &g_pt_nodes, link)
	{
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "method", "bdev_passthru_create");
		spdk_json_write_named_object_begin(w, "params");
		spdk_json_write_named_string(w, "base_bdev_name", spdk_bdev_get_name(pt_node->base_bdev));
		spdk_json_write_named_string(w, "name", spdk_bdev_get_name(&pt_node->pt_bdev));
		spdk_json_write_object_end(w);
		spdk_json_write_object_end(w);
	}
	return 0;
}

/* We provide this callback for the SPDK channel code to create a channel using
 * the channel struct we provided in our module get_io_channel() entry point. Here
 * we get and save off an underlying base channel of the device below us so that
 * we can communicate with the base bdev on a per channel basis.  If we needed
 * our own poller for this vbdev, we'd register it here.
 */
static int
pt_bdev_ch_create_cb(void *io_device, void *ctx_buf)
{
	struct pt_io_channel *pt_ch = ctx_buf;
	struct vbdev_passthru *pt_node = io_device;

	pt_ch->base_ch = spdk_bdev_get_io_channel(pt_node->base_desc);

	return 0;
}

/* We provide this callback for the SPDK channel code to destroy a channel
 * created with our create callback. We just need to undo anything we did
 * when we created. If this bdev used its own poller, we'd unregsiter it here.
 */
static void
pt_bdev_ch_destroy_cb(void *io_device, void *ctx_buf)
{
	struct pt_io_channel *pt_ch = ctx_buf;

	spdk_put_io_channel(pt_ch->base_ch);
}

/* Create the passthru association from the bdev and vbdev name and insert
 * on the global list. */
static int
vbdev_passthru_insert_name(const char *bdev_name, const char *vbdev_name)
{
	struct bdev_names *name;
	TAILQ_FOREACH(name, &g_bdev_names, link)
	{
		if (strcmp(vbdev_name, name->vbdev_name) == 0)
		{
			SPDK_ERRLOG("passthru bdev %s already exists\n", vbdev_name);
			return -EEXIST;
		}
	}

	name = calloc(1, sizeof(struct bdev_names));
	if (!name)
	{
		SPDK_ERRLOG("could not allocate bdev_names\n");
		return -ENOMEM;
	}

	name->bdev_name = strdup(bdev_name);
	if (!name->bdev_name)
	{
		SPDK_ERRLOG("could not allocate name->bdev_name\n");
		free(name);
		return -ENOMEM;
	}

	name->vbdev_name = strdup(vbdev_name);
	if (!name->vbdev_name)
	{
		SPDK_ERRLOG("could not allocate name->vbdev_name\n");
		free(name->bdev_name);
		free(name);
		return -ENOMEM;
	}

	TAILQ_INSERT_TAIL(&g_bdev_names, name, link);

	return 0;
}

/*This function gets parameters from JSON-RPC api and writes it to time based_raid_configuration struct . */ // mode - 0 backup mode
static int
vbdev_configure_time_based_raid(const char *partitions_number, const char *selected_partition_number, const char *calculate_honeypot_sha256, const char *honeypot_start_calculation_address)
{
	// assign values from RPC-JSON to

	time_based_raid_configuration_inst.partitions_number = atoi(partitions_number);
	time_based_raid_configuration_inst.selected_partition_number = atoi(selected_partition_number);
	time_based_raid_configuration_inst.calculate_honeypot_sha256 = atoi(calculate_honeypot_sha256);
	time_based_raid_configuration_inst.honeypot_start_calculation_address = atol(honeypot_start_calculation_address);
	if (atoi(calculate_honeypot_sha256) == 1)
	{
		read_canary();
	}

	SPDK_NOTICELOG("calculate_honeypot value: %s\n", calculate_honeypot_sha256);

	return 0;
}

/* On init, just perform bdev module specific initialization. */
static int
vbdev_passthru_init(void)
{
	return 0;
}

/* Called when the entire module is being torn down. */
static void
vbdev_passthru_finish(void)
{
	struct bdev_names *name;

	while ((name = TAILQ_FIRST(&g_bdev_names)))
	{
		TAILQ_REMOVE(&g_bdev_names, name, link);
		free(name->bdev_name);
		free(name->vbdev_name);
		free(name);
	}
}

/* During init we'll be asked how much memory we'd like passed to us
 * in bev_io structures as context. Here's where we specify how
 * much context we want per IO.
 */
static int
vbdev_passthru_get_ctx_size(void)
{
	return sizeof(struct passthru_bdev_io);
}

/* Where vbdev_passthru_config_json() is used to generate per module JSON config data, this
 * function is called to output any per bdev specific methods. For the PT module, there are
 * none.
 */
static void
vbdev_passthru_write_config_json(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	/* No config per bdev needed */
}

/* When we register our bdev this is how we specify our entry points. */
static const struct spdk_bdev_fn_table vbdev_passthru_fn_table = {
	.destruct = vbdev_passthru_destruct,
	.submit_request = vbdev_passthru_submit_request,
	.io_type_supported = vbdev_passthru_io_type_supported,
	.get_io_channel = vbdev_passthru_get_io_channel,
	.dump_info_json = vbdev_passthru_dump_info_json,
	.write_config_json = vbdev_passthru_write_config_json,
};

/* Called when the underlying base bdev goes away. */
static void
vbdev_passthru_base_bdev_hotremove_cb(void *ctx)
{
	struct vbdev_passthru *pt_node, *tmp;
	struct spdk_bdev *bdev_find = ctx;

	TAILQ_FOREACH_SAFE(pt_node, &g_pt_nodes, link, tmp)
	{
		if (bdev_find == pt_node->base_bdev)
		{
			spdk_bdev_unregister(&pt_node->pt_bdev, NULL, NULL);
		}
	}
}

/* Create and register the passthru vbdev if we find it in our list of bdev names.
 * This can be called either by the examine path or RPC method.
 */
static int
vbdev_passthru_register(struct spdk_bdev *bdev)
{
	struct bdev_names *name;
	struct vbdev_passthru *pt_node;
	int rc = 0;

	/* Check our list of names from config versus this bdev and if
	 * there's a match, create the pt_node & bdev accordingly.
	 */
	TAILQ_FOREACH(name, &g_bdev_names, link)
	{
		if (strcmp(name->bdev_name, bdev->name) != 0)
		{
			continue;
		}

		SPDK_NOTICELOG("Match on %s\n", bdev->name);
		pt_node = calloc(1, sizeof(struct vbdev_passthru));
		if (!pt_node)
		{
			rc = -ENOMEM;
			SPDK_ERRLOG("could not allocate pt_node\n");
			break;
		}

		/* The base bdev that we're attaching to. */
		pt_node->base_bdev = bdev;
		pt_node->pt_bdev.name = strdup(name->vbdev_name);
		if (!pt_node->pt_bdev.name)
		{
			rc = -ENOMEM;
			SPDK_ERRLOG("could not allocate pt_bdev name\n");
			free(pt_node);
			break;
		}
		pt_node->pt_bdev.product_name = "passthru";

		/* Copy some properties from the underlying base bdev. */
		pt_node->pt_bdev.write_cache = bdev->write_cache;
		pt_node->pt_bdev.required_alignment = bdev->required_alignment;
		pt_node->pt_bdev.optimal_io_boundary = bdev->optimal_io_boundary;
		pt_node->pt_bdev.blocklen = bdev->blocklen;
		pt_node->pt_bdev.blockcnt = bdev->blockcnt;

		/* Our purpose is to manipluate the number of of blocks that can be accessed.
		   The host OS will see block_cnt/time_based_raid_configuration_inst.partitions_number */
		// this operation will not performed on a honeytype bdev

		pt_node->pt_bdev.md_interleave = bdev->md_interleave;
		pt_node->pt_bdev.md_len = bdev->md_len;
		pt_node->pt_bdev.dif_type = bdev->dif_type;
		pt_node->pt_bdev.dif_is_head_of_md = bdev->dif_is_head_of_md;
		pt_node->pt_bdev.dif_check_flags = bdev->dif_check_flags;

		/* This is the context that is passed to us when the bdev
		 * layer calls in so we'll save our pt_bdev node here.
		 */
		pt_node->pt_bdev.ctxt = pt_node;
		pt_node->pt_bdev.fn_table = &vbdev_passthru_fn_table;
		pt_node->pt_bdev.module = &passthru_if;
		TAILQ_INSERT_TAIL(&g_pt_nodes, pt_node, link);

		spdk_io_device_register(pt_node, pt_bdev_ch_create_cb, pt_bdev_ch_destroy_cb,
								sizeof(struct pt_io_channel),
								name->vbdev_name);
		SPDK_NOTICELOG("io_device created at: 0x%p\n", pt_node);

		rc = spdk_bdev_open(bdev, true, vbdev_passthru_base_bdev_hotremove_cb,
							bdev, &pt_node->base_desc);
		if (rc)
		{
			SPDK_ERRLOG("could not open bdev %s\n", spdk_bdev_get_name(bdev));
			TAILQ_REMOVE(&g_pt_nodes, pt_node, link);
			spdk_io_device_unregister(pt_node, NULL);
			free(pt_node->pt_bdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("bdev opened\n");

		rc = spdk_bdev_module_claim_bdev(bdev, pt_node->base_desc, pt_node->pt_bdev.module);
		if (rc)
		{
			SPDK_ERRLOG("could not claim bdev %s\n", spdk_bdev_get_name(bdev));
			spdk_bdev_close(pt_node->base_desc);
			TAILQ_REMOVE(&g_pt_nodes, pt_node, link);
			spdk_io_device_unregister(pt_node, NULL);
			free(pt_node->pt_bdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("bdev claimed\n");

		rc = spdk_bdev_register(&pt_node->pt_bdev);
		if (rc)
		{
			SPDK_ERRLOG("could not register pt_bdev\n");
			spdk_bdev_module_release_bdev(&pt_node->pt_bdev);
			spdk_bdev_close(pt_node->base_desc);
			TAILQ_REMOVE(&g_pt_nodes, pt_node, link);
			spdk_io_device_unregister(pt_node, NULL);
			free(pt_node->pt_bdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("ext_pt_bdev registered\n");
		SPDK_NOTICELOG("created ext_pt_bdev for: %s\n", name->vbdev_name);
	}

	return rc;
}

/* Create the passthru disk from the given bdev and vbdev name. */
int create_passthru_disk(const char *bdev_name, const char *vbdev_name)
{
	struct spdk_bdev *bdev = NULL;
	bdev = spdk_bdev_get_by_name(bdev_name);
	SPDK_NOTICELOG("%d ---NVME----------num_of_blocks", bdev->blockcnt);
	SPDK_NOTICELOG("%s ---NVME------name", bdev->name);
	int rc = 0;

	/* Insert the bdev into our global name list even if it doesn't exist yet,
	 * it may show up soon...
	 */
	rc = vbdev_passthru_insert_name(bdev_name, vbdev_name);
	if (rc)
	{
		return rc;
	}

	bdev = spdk_bdev_get_by_name(bdev_name);
	if (!bdev)
	{
		/* This is not an error, we tracked the name above and it still
		 * may show up later.
		 */
		SPDK_NOTICELOG("vbdev creation deferred pending base bdev arrival\n");
		return 0;
	}

	return vbdev_passthru_register(bdev);
}

void delete_passthru_disk(struct spdk_bdev *bdev, spdk_bdev_unregister_cb cb_fn, void *cb_arg)
{
	struct bdev_names *name;

	if (!bdev || bdev->module != &passthru_if)
	{
		cb_fn(cb_arg, -ENODEV);
		return;
	}

	bdev->blockcnt = bdev->blockcnt * time_based_raid_configuration_inst.partitions_number;

	/* Remove the association (vbdev, bdev) from g_bdev_names. This is required so that the
	 * vbdev does not get re-created if the same bdev is constructed at some other time,
	 * unless the underlying bdev was hot-removed.
	 */
	TAILQ_FOREACH(name, &g_bdev_names, link)
	{
		if (strcmp(name->vbdev_name, bdev->name) == 0)
		{
			TAILQ_REMOVE(&g_bdev_names, name, link);
			free(name->bdev_name);
			free(name->vbdev_name);
			free(name);
			break;
		}
	}

	/* Additional cleanup happens in the destruct callback. */
	spdk_bdev_unregister(bdev, cb_fn, cb_arg);
}

/* Because we specified this function in our pt bdev function table when we
 * registered our pt bdev, we'll get this call anytime a new bdev shows up.
 * Here we need to decide if we care about it and if so what to do. We
 * parsed the config file at init so we check the new bdev against the list
 * we built up at that time and if the user configured us to attach to this
 * bdev, here's where we do it.
 */
static void
vbdev_passthru_examine(struct spdk_bdev *bdev)
{
	vbdev_passthru_register(bdev);

	spdk_bdev_module_examine_done(&passthru_if);
}

// int copy_passthru_disk(struct spdk_bdev *bdev_read, struct spdk_bdev *bdev_write)
// {
// 	SPDK_NOTICELOG("%d -------------num_of_blocks", bdev_read->blockcnt);
// 	SPDK_NOTICELOG("%s -------------name", bdev_read->name);
// 	int rc = 0;
// 	struct spdk_bdev_desc *bdev_desc_read;
// 	struct spdk_io_channel *bdev_io_channel_read;

// 	struct spdk_bdev_desc *bdev_desc_write;
// 	struct spdk_io_channel *bdev_io_channel_write;
// 	struct vbdev_passthru *pt_node_read = SPDK_CONTAINEROF(bdev_read, struct vbdev_passthru, pt_bdev);
// 	struct vbdev_passthru *pt_node_write = SPDK_CONTAINEROF(bdev_write, struct vbdev_passthru, pt_bdev);
// 	if (bdev_read == NULL)
// 	{
// 		SPDK_ERRLOG("Could not find the first bdev \n");
// 		return;
// 	}
// 	SPDK_NOTICELOG("Opening the bdev honeypot \n");
// 	SPDK_NOTICELOG("Opening io channel\n");
// 	/* Open I/O channel */
// 	bdev_io_channel_read = spdk_bdev_get_io_channel(pt_node_read->base_desc);
// 	if (bdev_io_channel_read == NULL)
// 	{
// 		SPDK_ERRLOG("Could not create bdev I/O channel!!\n");
// 		spdk_bdev_close(pt_node_read->base_desc);
// 		return;
// 	}
// 	uint32_t blk_size, buf_align;
// 	uint64_t num_of_blocks = spdk_bdev_get_num_blocks(bdev_read); // 80 //not fixed value
// 	SPDK_NOTICELOG("\n numofblocks %d\n", num_of_blocks);
// 	blk_size = spdk_bdev_get_block_size(bdev_read);
// 	SPDK_NOTICELOG("\n SIZE OF BLOCKS %d\n", blk_size); // blocks could be only 512 or 4096 bytes
// 	buf_align = spdk_bdev_get_buf_align(bdev_read);
// 	SPDK_NOTICELOG("\n BUF_ALIGN %d\n", buf_align);										   // system parameter for the addresses in buffer and bdev
// 	pt_io_channel_inst.buff = spdk_dma_zmalloc(blk_size * num_of_blocks, buf_align, NULL); // 100000 ask Oleg, probably too much
// 	if (!pt_io_channel_inst.buff)
// 	{
// 		SPDK_ERRLOG("Failed to allocate buffer\n");
// 		spdk_put_io_channel(bdev_io_channel_read);
// 		spdk_bdev_close(pt_node_read->base_desc);
// 		return;
// 	}

// 	SPDK_NOTICELOG("Reading io\n");
// 	// SPDK_NOTICELOG("%d\n", 100000 * blk_size);
// 	// SPDK_NOTICELOG("%d\n", buf_align);
// 	// uint64_t offset = 0; // in mallocs = 0 if we are copying totally, clarify
// 	rc = spdk_bdev_read(pt_node_read->base_desc, bdev_io_channel_read,
// 						pt_io_channel_inst.buff, 0, num_of_blocks * blk_size, simple_read_complete, bdev_read); // reading
// 	if (rc == -ENOMEM)
// 	{
// 		SPDK_NOTICELOG("Queueing io\n");
// 		SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
// 		vbdev_passthru_queue_io(bdev_io_channel_read);
// 	}
// 	else if (rc)
// 	{
// 		SPDK_ERRLOG("%s error while reading from bdev: %d\n", spdk_strerror(-rc), rc);
// 		spdk_put_io_channel(bdev_io_channel_read);
// 		spdk_bdev_close(pt_node_read->base_desc);
// 	}

// 	/////////////////////////////////////////////////////////////////

// 	// writing

// 	if (bdev_write == NULL)
// 	{
// 		SPDK_ERRLOG("Could not find the first bdev \n");
// 		return;
// 	}
// 	SPDK_NOTICELOG("Opening the second bdev \n");
// 	SPDK_NOTICELOG("Opening io channel\n");
// 	/* Open I/O channel */
// 	bdev_io_channel_write = spdk_bdev_get_io_channel(pt_node_write->base_desc);
// 	if (bdev_io_channel_write == NULL)
// 	{
// 		SPDK_ERRLOG("Could not create bdev I/O channel!!\n");
// 		spdk_bdev_close(pt_node_write->base_desc);
// 		return;
// 	}
// 	SPDK_NOTICELOG("Writing through io\n");
// 	// uint64_t offset = 0;
// 	rc = spdk_bdev_write(pt_node_write->base_desc, bdev_io_channel_write,
// 						 pt_io_channel_inst.buff, 0, num_of_blocks * blk_size, simple_write_complete, bdev_write); // reading
// 	SPDK_NOTICELOG("before log %d \n", rc);
// 	if (rc == -ENOMEM)
// 	{
// 		SPDK_NOTICELOG("log1");
// 		SPDK_NOTICELOG("Queueing io\n");
// 		SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
// 		vbdev_passthru_queue_io(bdev_io_channel_write);
// 	}
// 	else if (rc)
// 	{
// 		SPDK_NOTICELOG("log2");
// 		SPDK_ERRLOG("%s error while writing from bdev: %d\n", spdk_strerror(-rc), rc);
// 		spdk_put_io_channel(bdev_io_channel_write);
// 		spdk_bdev_close(pt_node_write->base_desc);
// 	}

// 	return 1;
// }

/////////////////////////////////////////////////////////////////

int copy_passthru_disk(struct spdk_bdev *bdev_read, struct spdk_bdev *bdev_write)
{

	int rc = 0;

	//bdev opening
	struct spdk_bdev_desc *bdev_desc_read;
	struct spdk_io_channel *bdev_io_channel_read;
	struct spdk_bdev_desc *bdev_desc_write;
	struct spdk_io_channel *bdev_io_channel_write;
	struct vbdev_passthru *pt_node_read = SPDK_CONTAINEROF(bdev_read, struct vbdev_passthru, pt_bdev);
	struct vbdev_passthru *pt_node_write = SPDK_CONTAINEROF(bdev_write, struct vbdev_passthru, pt_bdev);
	SPDK_NOTICELOG("Opening the first bdev \n");
	if (bdev_read == NULL)
	{
		SPDK_ERRLOG("Could not find the first bdev \n");
		return;
	}
	SPDK_NOTICELOG("Opening the second bdev \n");
	if (bdev_write == NULL)
	{
		SPDK_ERRLOG("Could not find the second bdev \n");
		return;
	}

	//Configurating channels for read and write;

	SPDK_NOTICELOG("Opening the read io channel\n");
	bdev_io_channel_read = spdk_bdev_get_io_channel(pt_node_read->base_desc);
	if (bdev_io_channel_read == NULL)
	{
		SPDK_ERRLOG("Could not create bdev I/O channel!!\n");
		spdk_bdev_close(pt_node_read->base_desc);
		return;
	}
	SPDK_NOTICELOG("Opening the write io channel\n");
	bdev_io_channel_write = spdk_bdev_get_io_channel(pt_node_write->base_desc);
	if (bdev_io_channel_write == NULL)
	{
		SPDK_ERRLOG("Could not create bdev I/O channel!!\n");
		spdk_bdev_close(pt_node_write->base_desc);
		return;
	}
	uint64_t blk_size, buf_align, blocks_readed_by_step; //blocks parameters
	uint64_t num_of_blocks = spdk_bdev_get_num_blocks(bdev_read); 
	blk_size = spdk_bdev_get_block_size(bdev_read);
	buf_align = spdk_bdev_get_buf_align(bdev_read);
	
	blocks_readed_by_step= 100000; //bdev blocks scanned by a step
	uint64_t blocks_in_buffer;

	for (uint64_t blocks_scanned = 0; blocks_scanned < num_of_blocks; blocks_scanned = blocks_scanned + blocks_readed_by_step)
	{

		SPDK_NOTICELOG("Blocks was scanned: %d", blocks_scanned);
		// maintaining rest amount of the blocks 
		
		if (blocks_scanned + blocks_readed_by_step > num_of_blocks)
		{
			SPDK_NOTICELOG("The number of blocks in a bdev is %d, the copied amount by the step is %d \n", (num_of_blocks), blocks_readed_by_step);
			SPDK_NOTICELOG("The remainder is %d \n", (num_of_blocks % blocks_readed_by_step));

			blocks_in_buffer = (num_of_blocks % blocks_readed_by_step);
			// this block is used for the last iteration of a loop.
			// we reduce the last buffer's size to get blocks from bdev
		}
		else{
			blocks_in_buffer = blocks_readed_by_step;
		}
		
		
		pt_io_channel_inst.buff = spdk_dma_zmalloc(blk_size * blocks_in_buffer, buf_align, NULL); // malloc for blocks_in_buffer to read and write
		if (!pt_io_channel_inst.buff)
		{
			SPDK_ERRLOG("Failed to allocate buffer\n");
			spdk_put_io_channel(bdev_io_channel_read);
			spdk_bdev_close(pt_node_read->base_desc);
			return;
		}


		SPDK_NOTICELOG("Reading io\n");

		rc = spdk_bdev_read_blocks(pt_node_read->base_desc, bdev_io_channel_read,
								   pt_io_channel_inst.buff, blocks_scanned, blocks_in_buffer, simple_read_complete, bdev_read);  
		// reading blocks from bdev to the malloc pt_io_channel_inst.buff with the offset of "blocks_scanned"

		if (rc == -ENOMEM)
		{
			SPDK_NOTICELOG("Queueing io\n");
			SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
			vbdev_passthru_queue_io(bdev_io_channel_read);
		}
		else if (rc)
		{
			SPDK_ERRLOG("%s error while reading from bdev: %d\n", spdk_strerror(-rc), rc);
			spdk_put_io_channel(bdev_io_channel_read);
			spdk_bdev_close(pt_node_read->base_desc);
			SPDK_ERRLOG("%d %d \n", blocks_scanned, blocks_in_buffer);
		}



		SPDK_NOTICELOG("Writing through io\n");
		rc = spdk_bdev_write_blocks(pt_node_write->base_desc, bdev_io_channel_write,
									pt_io_channel_inst.buff, blocks_scanned, blocks_in_buffer, simple_write_complete, bdev_write); // reading
		// writing blocks to bdev from the malloc pt_io_channel_inst.buff with the offset of "blocks_scanned"
		if (rc == -ENOMEM)
		{
			
			SPDK_NOTICELOG("Queueing io\n");
			SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
			vbdev_passthru_queue_io(bdev_io_channel_write);
		}
		else if (rc)
		{
			SPDK_ERRLOG("%s error while writing from bdev: %d\n", spdk_strerror(-rc), rc);
			spdk_put_io_channel(bdev_io_channel_write);
			spdk_bdev_close(pt_node_write->base_desc);
			//		}
			spdk_free(pt_io_channel_inst.buff);
		}


		spdk_dma_free(pt_io_channel_inst.buff); //free the buffer
	}
	SPDK_NOTICELOG("The copy of bdevs was totally completed.\n");
	SPDK_NOTICELOG("%d blocks was copied with the size of %d bytes per each", num_of_blocks, blk_size );

	return 1;
}

	// static void
	// read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
	// {
	// 	// struct vbdev_passthru *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_passthru,
	// 	//				 pt_bdev);
	// 	// struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	// 	// struct passthru_bdev_io *io_ctx = (struct passthru_bdev_io *)bdev_io->driver_ctx;
	// 	struct sdpk_bdev *bdev = cb_arg;

	// 	int rc;
	// 	// SPDK_NOTICELOG("Start calculate sha256 \n");
	// 	// if (!success) {
	// 	// 	spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
	// 	// 	return;
	// 	// }

	// 	// if (pt_io_channel_inst.buff == NULL) {
	// 	// 		SPDK_NOTICELOG("Sha256 calculation failed \n");
	// 	// } else {

	// 	// uint8_t hash[32];
	// 	// char hash_string[65];
	// 	// uint32_t blk_size = spdk_bdev_get_block_size(bdev);
	// 	// SPDK_NOTICELOG("Read successful calculting sha256 result :\n");
	// 	//     SPDK_NOTICELOG("Start calculate sha256 \n");
	// 	//     SPDK_NOTICELOG("%d \n",sizeof(pt_io_channel_inst.buff));
	// 	// calc_sha_256(hash, pt_io_channel_inst.buff, (100000*blk_size));
	// 	// hash_to_string(hash_string, hash);
	// 	// SPDK_NOTICELOG("result %s:\n",hash_string);
	// 	//         char buffer [700];

	// 	// rc = snprintf(buffer,sizeof(buffer), "%s" ,hash_string);

	// 	// creating file pointer to work with files
	// 	// 	FILE *fptr;

	// 	// // opening file in writing mode
	// 	// 	fptr = fopen("/home/ubuntu/spdk/build/bin/sha256_result.txt", "w");

	// 	// // exiting program
	// 	// 	if (fptr == NULL) {
	// 	// 	SPDK_NOTICELOG("Failed to open config file, please retry");
	// 	// 	//spdk_json_write_string(w, "error to write configuration file");
	// 	// 	//spdk_jsonrpc_end_result(request, w);

	// 	// 	}

	// 	// fprintf(fptr, "%s",hash_string);
	// 	// 	fclose(fptr);

	// 	spdk_dma_free(pt_io_channel_inst.buff);
	// 	spdk_bdev_free_io(bdev_io);

	// 	if (rc != 0)
	// 	{
	// 		if (rc == -ENOMEM)
	// 		{
	// 			SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
	// 			//	io_ctx->ch = ch;
	// 			//	vbdev_passthru_queue_io(bdev_io);
	// 		}
	// 		else
	// 		{
	// 			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
	// 			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
	// 		}
	// 	}
	// }

	// int copy_passthru_disk(struct spdk_bdev *bdev_read, struct spdk_bdev *bdev_write)
	// {
	// 	struct spdk_bdev *bdev = NULL;
	// 	struct spdk_bdev_desc *bdev_desc;
	// 	struct spdk_io_channel *bdev_io_channel;
	// 	int rc = 0;
	// 	bdev = bdev_read;
	// 	struct vbdev_passthru *pt_node = SPDK_CONTAINEROF(bdev, struct vbdev_passthru, pt_bdev);

	// 	if (bdev == NULL)
	// 	{
	// 		SPDK_ERRLOG("Could not find the read_bdev \n");
	// 		return;
	// 	}

	// 	SPDK_NOTICELOG("Opening the read bdev \n");
	// 	// rc = spdk_bdev_open(bdev, true, NULL, NULL, &bdev_desc);
	// 	// if (rc) {
	// 	//		SPDK_ERRLOG("Could not open bdev: honeypot \n");

	// 	//			return;
	// 	//	}

	// 	SPDK_NOTICELOG("Opening io channel\n");
	// 	/* Open I/O channel */
	// 	bdev_io_channel = spdk_bdev_get_io_channel(pt_node->base_desc);
	// 	if (bdev_io_channel == NULL)
	// 	{
	// 		SPDK_ERRLOG("Could not create bdev I/O channel!!\n");
	// 		spdk_bdev_close(pt_node->base_desc);
	// 		return;
	// 	}

	// 	char *buff;
	// 	uint32_t blk_size, buf_align;
	// 	uint32_t num_of_blocks;

	// 	blk_size = spdk_bdev_get_block_size(bdev);
	// 	buf_align = spdk_bdev_get_buf_align(bdev);
	// 	num_of_blocks = spdk_bdev_get_num_blocks(bdev);
	// 	// pt_io_channel_inst.buff = spdk_dma_zmalloc(blk_size, buf_align, NULL);
	// 	// pt_io_channel_inst.buff = spdk_dma_zmalloc(2000*blk_size-20*blk_size, buf_align, NULL);

	// 	pt_io_channel_inst.buff = spdk_dma_zmalloc(num_of_blocks * blk_size, buf_align, NULL);

	// 	if (!pt_io_channel_inst.buff)
	// 	{
	// 		SPDK_ERRLOG("Failed to allocate buffer\n");
	// 		spdk_put_io_channel(bdev_io_channel);
	// 		spdk_bdev_close(pt_node->base_desc);
	// 		return;
	// 	}

	// 	uint32_t length = spdk_bdev_get_block_size(bdev);

	// 	SPDK_NOTICELOG("Reading io\n");
	// 	SPDK_NOTICELOG("%d\n", num_of_blocks * blk_size);

	// 	SPDK_NOTICELOG("%d\n", buf_align);
	// 	rc = spdk_bdev_read(pt_node->base_desc, bdev_io_channel,
	// 						pt_io_channel_inst.buff, 0, num_of_blocks * blk_size, read_complete, bdev);

	// 	if (rc == -ENOMEM)
	// 	{
	// 		SPDK_NOTICELOG("Queueing io\n");
	// 		SPDK_ERRLOG("No memory, start to queue io for passthru.\n");
	// 		vbdev_passthru_queue_io(bdev_io_channel);
	// 	}
	// 	else if (rc)
	// 	{
	// 		SPDK_ERRLOG("%s error while reading from bdev: %d\n", spdk_strerror(-rc), rc);
	// 		spdk_put_io_channel(bdev_io_channel);
	// 		spdk_bdev_close(pt_node->base_desc);
	// 	}
	// }