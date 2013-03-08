/* Copyright (C) 2013 talisein <agpotter@gmail.com>                        *
 *                                                                         *
 * This program is free software: you can redistribute it and/or modify    *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation, either version 3 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful,         *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.   */

#include <weechat-plugin.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <gcrypt.h>
#include <stdbool.h>

#define LOCAL   __attribute__ ((visibility ("hidden")))
#define EXTERN  __attribute__ ((visibility ("default")))
#define XFER_STATUS_DONE 3
#define CKSUM_PREFIX "cksum: "

EXTERN char weechat_plugin_name[]        = "cksum";
EXTERN char weechat_plugin_api_version[] = WEECHAT_PLUGIN_API_VERSION;
EXTERN char weechat_plugin_author[]      = "talisein";
EXTERN char weechat_plugin_description[] = "Performs checksum validation after DCC file xfer";
EXTERN char weechat_plugin_version[]     = "0.9.0";
EXTERN char weechat_plugin_license[]     = "GPL3";

typedef struct {
	struct t_hashtable *xfers;
	struct t_hook      *hook_print;
	struct t_hook      *hook_xfer_ended;
	regex_t            *re_tx_complete;
	regex_t            *re_md5;
	regex_t            *re_nick;
	regex_t            *re_crc32;
	char               *ebuf;
	size_t              elen;
	unsigned char      *buf;
	size_t              len;
} cksum_globals_t;

typedef struct {
	cksum_globals_t *globals;
	char            *md5;
	char            *crc32;
	char            *filename;
	off_t            size;
	ssize_t          total_read;
	unsigned int     ref_cnt;
	struct t_hook   *hook_fd;
	gcry_md_hd_t    *gcry;
} cksum_ctx_t;

typedef struct {
	char *filename;
	char *crc32;
	struct t_hook *timer;
} cksum_xfer_t;

struct t_weechat_plugin *weechat_plugin    = NULL;
cksum_globals_t         *cksum_global_data = NULL;

LOCAL cksum_xfer_t* 
cksum_xfer_new(const char* filename, const char* crc32)
{
	cksum_xfer_t *xfer = (cksum_xfer_t*) malloc(sizeof(cksum_xfer_t));
	if (xfer) {
		xfer->filename = strdup (filename);
		xfer->crc32    = strdup (crc32);
		xfer->timer    = NULL;
		if (!xfer->filename || !xfer->crc32) {
			if (xfer->filename) free (xfer->filename);
			if (xfer->crc32)    free (xfer->crc32);
			free (xfer);
			xfer = NULL;
		}
	}

	return xfer;
}

LOCAL void
cksum_xfer_free(cksum_xfer_t *xfer)
{
	if (xfer) {
		if (xfer->filename) free (xfer->filename);
		if (xfer->crc32)    free (xfer->crc32);
		if (xfer->timer) {
			weechat_unhook(xfer->timer);
			xfer->timer = NULL;
		}
		free (xfer);
	}
}

LOCAL void 
cksum_xfers_add(cksum_xfer_t *xfer)
{
	if (xfer) {
		struct t_hashtable *xfers = cksum_global_data->xfers;
		char *key = strdup (xfer->filename);
		if (key)
			weechat_hashtable_set(xfers, key, xfer);
	}
}

LOCAL void
cksum_xfers_remove(cksum_xfer_t *xfer)
{
	if (xfer) {
		struct t_hashtable *xfers = cksum_global_data->xfers;
		weechat_hashtable_remove(xfers, (void*) xfer->filename);
		cksum_xfer_free(xfer);
	}
}

LOCAL cksum_xfer_t*
cksum_xfers_find(const char* filename)
{
	if (filename) {
		struct t_hashtable *xfers = cksum_global_data->xfers;
		cksum_xfer_t *xfer = (cksum_xfer_t*) weechat_hashtable_get(xfers, (void*) filename);
		return xfer;
	}

	return NULL;
}

LOCAL bool
cksum_xfers_has_xfer(const cksum_xfer_t* xfer)
{
	struct t_hashtable *xfers = cksum_global_data->xfers;
	int ret = weechat_hashtable_has_key(xfers, xfer->filename);
	if (ret == 1)
		return true;
	else
		return false;
}

LOCAL void
cksum_xfers_remove_all_cb(void              *data      __attribute__((unused)),
                         struct t_hashtable *hashtable __attribute__((unused)),
                         const void         *key       __attribute__((unused)),
                         const void         *value)
{
	cksum_xfer_t *xfer = (cksum_xfer_t*) value;
	cksum_xfer_free(xfer);
}

LOCAL void
cksum_xfers_remove_all(void)
{
	struct t_hashtable *xfers = cksum_global_data->xfers;
	weechat_hashtable_map(xfers, &cksum_xfers_remove_all_cb, NULL);
	weechat_hashtable_remove_all(xfers);
}

LOCAL inline int
is_not_hex_char(char c)
{
	if ( (   c >= '0' && c <= '9' )
	     || (c >= 'A' && c <= 'Z' )
	     || (c >= 'a' && c <= 'z' ) )
		return 0;
	else
		return 1;
}

LOCAL char*
get_crc32(regex_t *re, const char *str)
{
	if (!str || !re) return NULL;

	regmatch_t   crc32_match;
	int          crc32_found = regexec(re, str, 1, &crc32_match, 0);
	unsigned int nbytes      = gcry_md_get_algo_dlen(GCRY_MD_CRC32);
	char        *ret         = NULL;

	if (crc32_found != REG_NOMATCH) {
		int   hoffset = is_not_hex_char(str[crc32_match.rm_so]);
		ret           = weechat_strndup(str + crc32_match.rm_so + hoffset,
		                                nbytes*2);
	}

	return ret;
}

LOCAL cksum_ctx_t*
cksum_ctx_new (cksum_globals_t *globals, char* md5, const char* filename)
{
	cksum_ctx_t *ctx = malloc(sizeof(cksum_ctx_t));

	if (ctx) {
		ctx->globals    = globals;
		ctx->md5        = (md5)? strdup (md5) : NULL;
		ctx->filename   = strdup (filename);
		ctx->crc32      = get_crc32 (globals->re_crc32, ctx->filename);
		ctx->ref_cnt    = 1;
		ctx->size       = 0;
		ctx->total_read = 0;
		ctx->hook_fd    = NULL;
		ctx->gcry       = NULL;
		if ( (md5 && !ctx->md5) || !ctx->filename) {
			if (ctx->md5)      free (ctx->md5);
			if (ctx->crc32)    free (ctx->md5);
			if (ctx->filename) free (ctx->md5);
			free (ctx);
			return NULL;
		}
		return ctx;
	} else {
		return NULL;
	}
}

LOCAL void
cksum_ctx_ref(cksum_ctx_t *ctx)
{
	++ctx->ref_cnt;
}

LOCAL void
cksum_ctx_unref(cksum_ctx_t *ctx)
{
	--ctx->ref_cnt;
	if (ctx->ref_cnt == 0) {
		if (ctx->hook_fd) weechat_unhook(ctx->hook_fd);
		if (ctx->gcry) {
			gcry_md_close(*(ctx->gcry));
			free(ctx->gcry);
		}

		if (ctx->filename) free (ctx->filename);
		if (ctx->md5)      free (ctx->md5);
		if (ctx->crc32)    free (ctx->crc32);
		free(ctx);
	}
}

LOCAL void
print_regcomp_error(int code, const regex_t* preg, struct t_weechat_plugin *weechat_plugin)
{
	char* buf = NULL;
	size_t len = 0;

	len = regerror(code, preg, buf, len);
	buf = malloc(len);
	if (buf) {
		regerror(code, preg, buf, len);
		weechat_printf(NULL, "%s%sError compiling regex: %s",
		               weechat_prefix("error"), CKSUM_PREFIX, buf);
		free(buf);
	}
}

LOCAL bool
cksum_global_init(void)
{
	cksum_global_data = malloc(sizeof(cksum_globals_t));
	if (!cksum_global_data) return false;
	cksum_global_data->xfers    = weechat_hashtable_new(128,
	                                                    WEECHAT_HASHTABLE_STRING,
	                                                    WEECHAT_HASHTABLE_POINTER,
	                                                    NULL, NULL);
	cksum_global_data->hook_print      = NULL;
	cksum_global_data->hook_xfer_ended = NULL;
	cksum_global_data->re_tx_complete  = malloc(sizeof(regex_t));
	cksum_global_data->re_md5          = malloc(sizeof(regex_t));
	cksum_global_data->re_nick         = malloc(sizeof(regex_t));
	cksum_global_data->re_crc32        = malloc(sizeof(regex_t));
	cksum_global_data->len             = 1024*1024;
	cksum_global_data->buf             = malloc(cksum_global_data->len);
	cksum_global_data->elen            = 128;
	cksum_global_data->ebuf            = malloc(cksum_global_data->elen);

	if ( cksum_global_data->xfers
	     && cksum_global_data->re_tx_complete 
	     && cksum_global_data->re_md5 
	     && cksum_global_data->re_nick 
	     && cksum_global_data->re_crc32
	     && cksum_global_data->ebuf
	     && cksum_global_data->buf) {
		int code = regcomp(cksum_global_data->re_tx_complete,
		                   "Transfer Completed", REG_ICASE | REG_EXTENDED | REG_NOSUB);
		if (code != 0) {
			print_regcomp_error(code, cksum_global_data->re_tx_complete, weechat_plugin);
			goto malloc_err;
		}
		code = regcomp(cksum_global_data->re_md5,
		               "[0-9A-F]{32}", REG_ICASE | REG_EXTENDED);
		if (code != 0) {
			print_regcomp_error(code, cksum_global_data->re_md5, weechat_plugin);
			goto cksum_err;
		}
		code = regcomp(cksum_global_data->re_nick,
		               "^[^ ]+", REG_EXTENDED);
		if (code != 0) {
			print_regcomp_error(code, cksum_global_data->re_nick, weechat_plugin);
			goto rn_err;
		}
		code = regcomp(cksum_global_data->re_crc32,
		               "([^0-9A-Z]|^)[0-9A-F]{8}([^0-9A-Z]|$)", REG_ICASE | REG_EXTENDED);
		if (code != 0) {
			print_regcomp_error(code, cksum_global_data->re_crc32, weechat_plugin);
			goto crc32_err;
		}
		
		return true;
	} else {
		goto malloc_err;
	}

 crc32_err:
	regfree(cksum_global_data->re_nick);
 rn_err:
	regfree(cksum_global_data->re_md5);
 cksum_err:
	regfree(cksum_global_data->re_tx_complete);
 malloc_err:

	if (cksum_global_data->xfers)          weechat_hashtable_free(cksum_global_data->xfers);
	if (cksum_global_data->re_tx_complete) free(cksum_global_data->re_tx_complete);
	if (cksum_global_data->re_md5)         free(cksum_global_data->re_md5);
	if (cksum_global_data->re_nick)        free(cksum_global_data->re_nick);
	if (cksum_global_data->re_crc32)       free(cksum_global_data->re_crc32);
	if (cksum_global_data->ebuf)           free(cksum_global_data->ebuf);
	if (cksum_global_data->buf)            free(cksum_global_data->buf);
	free (cksum_global_data);
	cksum_global_data = NULL;
	return false;
}

LOCAL char*
get_checksum(gcry_md_hd_t *gcry, int algo)
{
	unsigned int   nbytes   = gcry_md_get_algo_dlen(algo);
	unsigned char *bin_hash = gcry_md_read(*gcry, algo);
	char          *hash     = malloc(nbytes*2 + 1);
	unsigned int   i;

	if (hash && bin_hash) {
		hash[nbytes] = '\0';
		for(i = 0; i < nbytes; ++i)
			sprintf(hash + i*2, "%02x", bin_hash[i]);		
	}

	return hash;
}

LOCAL bool
compare_checksums(char *cksum, char *l, char *r)
{
	bool ret = false;
	if (l && r && cksum) {
		if (weechat_strcasecmp(l, r) == 0) {
			weechat_printf(NULL, "%s%s%s verified%s: %s",
			               CKSUM_PREFIX, weechat_color("green"),
			               cksum, weechat_color("chat"), l);
			ret = true;
		} else {
			weechat_printf(NULL, "%s%s%s%s checksum mismatch!%s %s != %s", 
			               weechat_prefix("error"), CKSUM_PREFIX,
			               weechat_color("red"), cksum,
			               weechat_color("chat"), l, r);
		}
	}

	return ret;
}

LOCAL int
cksum_fd_callback(void *cbdata, int fd)
{
	cksum_ctx_t     *ctx     = (cksum_ctx_t*) cbdata;
	ssize_t        blen    = ctx->globals->len;
	unsigned char *buf     = ctx->globals->buf;
	size_t         elen    = ctx->globals->elen;
	char          *ebuf    = ctx->globals->ebuf;
	ssize_t        to_read = ctx->size - ctx->total_read;
	ssize_t        sread   = 0;
	gcry_md_hd_t  *gcry    = ctx->gcry;
	int            ret     = WEECHAT_RC_OK;

	/* Read from fd */
	if (to_read >= blen)
		sread = read(fd, buf, blen);
	else
		sread = read(fd, buf, to_read);
	if (sread < 0) {
		if (errno == EINTR) return WEECHAT_RC_OK;
		int merrno = errno;
		weechat_printf(NULL, "%s%sError reading file: %s",
		               weechat_prefix("error"), CKSUM_PREFIX,
		               strerror_r(merrno, ebuf, elen));
		ret = WEECHAT_RC_ERROR;
		goto cleanup;
	}

	/* Handle read bytes */
	if (sread > 0) {
		gcry_md_write(*gcry, buf, sread);
		ctx->total_read += sread;

		/* Done reading */
		if (ctx->total_read >= ctx->size) {
			/* Compare md5sum */
			char *hash = get_checksum (gcry, GCRY_MD_MD5);
			if (hash) {
				compare_checksums ("md5sum", hash, ctx->md5);
				free (hash);
			}

			/* Compare crc32 */
			hash = get_checksum (gcry, GCRY_MD_CRC32);
			if (hash) {
				compare_checksums ("CRC32", hash, ctx->crc32);
				free (hash);
			}

			/* Done reading, unhook and close fd */
			goto cleanup;
		}
	}

	return ret;

 cleanup:
	weechat_unhook(ctx->hook_fd);
	ctx->hook_fd = NULL;
	cksum_ctx_unref(ctx);
	while (close(fd) < 0) {
		if (errno == EINTR) continue;
		int merrno = errno;
		weechat_printf(NULL, "%s%sFailed to close fd: %s",
		               weechat_prefix("error"), CKSUM_PREFIX,
		               strerror_r(merrno, ebuf, elen));
		ret = WEECHAT_RC_ERROR;
	}
	return ret;
}

LOCAL bool
setup_self_hash(cksum_ctx_t *ctx)
{
	struct stat  mstat;
	char        *ebuf = ctx->globals->ebuf;
	const size_t elen = ctx->globals->elen;
	int          fd   = -1;

	/* Open fd */
	while (fd == -1) {
		fd = open(ctx->filename, O_RDONLY);
		if (fd == -1) {
			if (errno == EINTR) continue;
			int merrno = errno;
			weechat_printf(NULL, "%s%sError opening file '%s': %s",
			               weechat_prefix("error"), CKSUM_PREFIX,
			               ctx->filename,
			               strerror_r(merrno, ebuf, elen));
			return false;
		}
	}

	/* Get file size */
	int sret = fstat(fd, &mstat);
	if (sret == -1) {
		int merrno = errno;
		weechat_printf(NULL, "%s%sError stating file '%s': %s",
		               weechat_prefix("error"), CKSUM_PREFIX,
		               ctx->filename,
		               strerror_r(merrno, ebuf, elen));
		goto err;
	}
	ctx->size = mstat.st_size;

	/* Set up gcrypt md5 hashing */
	ctx->gcry = malloc(sizeof(gcry_md_hd_t));
	if (!ctx->gcry) goto err;
	gcry_error_t gerr = gcry_md_open(ctx->gcry, GCRY_MD_MD5, 0);
	if (gerr) {
		weechat_printf(NULL, "%s%sError using gcrypt: %s/%s",
		               weechat_prefix("error"), CKSUM_PREFIX,
		               gcry_strsource (gerr), gcry_strerror (gerr));
		goto err_gcry;
	}

	/* Set up gcrypt crc32 hashing */
	gerr = gcry_md_enable(*(ctx->gcry), GCRY_MD_CRC32);
	if (gerr) {
		weechat_printf(NULL, "%s%sError using gcrypt: %s/%s",
		               weechat_prefix("error"), CKSUM_PREFIX,
		               gcry_strsource (gerr), gcry_strerror (gerr));
	}

	/* Hook fd */
	struct t_hook *hook = weechat_hook_fd(fd, 1, 0, 0, &cksum_fd_callback, ctx);
	ctx->hook_fd = hook;
	if (hook == NULL) {
		weechat_printf(NULL, "%s%sError hooking fd",
		               weechat_prefix("error"), CKSUM_PREFIX);
		goto err_gcry;
	}

	return true;

 err_gcry:
	free(ctx->gcry);
	ctx->gcry = NULL;
 err:
	while (close(fd) == -1) {
		if (errno == EINTR) continue;
		int merrno = errno;
		weechat_printf(NULL, "%s%sFailed to close fd: %s", 
		               weechat_prefix("error"), CKSUM_PREFIX,
		               strerror_r(merrno, ebuf, elen));
		break;
	}

	cksum_ctx_unref(ctx);
	return false;
}

LOCAL bool
on_cksum_recv(const char* nick, char* md5, cksum_globals_t *globals)
{
	/* Get list of xfers */
	struct t_infolist *infolist;
	bool ret = false;
	infolist = weechat_infolist_get("xfer", NULL, NULL);
	if (!infolist) {
		weechat_printf(NULL, "%s%sUnable to get xfer infolist for md5sum",
		               weechat_prefix("error"), CKSUM_PREFIX);
		return ret;
	}

	while ( weechat_infolist_next(infolist) ) {
		/* Match xfer to remote_nick */
		const char* remote_nick = weechat_infolist_string(infolist, "remote_nick");
		const int status = weechat_infolist_integer(infolist, "status");
		if ( status == XFER_STATUS_DONE && strcmp(remote_nick, nick) == 0) {
			/* Create cksum_ctx and start hashing */
			const char* fn = weechat_infolist_string(infolist, "local_filename");
			cksum_ctx_t *ctx = cksum_ctx_new(globals, md5, fn);
			if (ctx) {
				ret = setup_self_hash(ctx);

				/* Prevent CRC32 timer from starting second hash */
				cksum_xfer_t *xfer = cksum_xfers_find(fn);
				if (xfer) {
					cksum_xfers_remove(xfer);
				}
			} else {
				weechat_printf(NULL, "%s%sUnable to create context (on_cksum_recv)",
				               weechat_prefix("error"), CKSUM_PREFIX);
			}

			break;
		}
	}

	weechat_infolist_free(infolist);
	return ret;
}

LOCAL int
cksum_cb_process_message(void                 *cbdata,
                         struct t_gui_buffer  *buffer     __attribute__((unused)),
                         time_t                date       __attribute__((unused)),
                         int                   tags_count __attribute__((unused)),
                         const char          **tags       __attribute__((unused)),
                         int                   displayed  __attribute__((unused)),
                         int                   highlight  __attribute__((unused)),
                         const char           *prefix     __attribute__((unused)),
                         const char           *message) {
	cksum_globals_t *globals = (cksum_globals_t*) cbdata;
	if (!globals) return WEECHAT_RC_ERROR;
	if (!message) return WEECHAT_RC_OK;

	/* Determine if this message is interesting */
	if (regexec(globals->re_tx_complete, message, 1, NULL, 0) != REG_NOMATCH) {
		regmatch_t cksum_match;
		regmatch_t nick_match;
		int cksum_found  = regexec(globals->re_md5,  message, 1, &cksum_match, 0);
		int nick_found   = regexec(globals->re_nick, message, 1, &nick_match,  0);

		/* Copy remote_nick and md5sum out of message */
		if (cksum_found != REG_NOMATCH && nick_found != REG_NOMATCH) {
			char* nick = NULL;
			char* md5  = NULL;
			nick = weechat_strndup(message + nick_match.rm_so,
			                     nick_match.rm_eo - nick_match.rm_so);
			md5 = weechat_strndup(message + cksum_match.rm_so,
			                      32);
			if (!md5 || !nick) {
				if (nick) free (nick);
				if (md5) free (md5);
				return WEECHAT_RC_ERROR;
			}

			bool ret = on_cksum_recv(nick, md5, globals);
			free(md5);
			free(nick);
			if (!ret) return WEECHAT_RC_ERROR;
		}
	}

	return WEECHAT_RC_OK;
}

LOCAL int
cksum_cb_timer(void* cbdata, int remaining_calls __attribute__((unused)) )
{
	cksum_globals_t *globals = cksum_global_data;
	cksum_xfer_t    *xfer    = (cksum_xfer_t*)cbdata;
	cksum_ctx_t     *ctx     = cksum_ctx_new(globals, NULL, xfer->filename);
	if (ctx) {
		setup_self_hash(ctx);
		cksum_xfers_remove(xfer);
	} else {
		weechat_printf(NULL, "%s%sUnable to create context (cb_timer)",
		               weechat_prefix("error"), CKSUM_PREFIX);
	}

	return WEECHAT_RC_OK;
}

LOCAL int
cksum_cb_xfer_ended(void* cbdata,
                    const char *signal    __attribute__((unused)),
                    const char *type_data __attribute__((unused)),
                    void *signal_data)
{
	/* Weechat as of 4.0 does not give a complete infolist in this    *
	 * signal. So we have to get the whole list of xfers and find the *
	 * right one that has the information we need (local_filename).   */
	cksum_globals_t   *globals      = (cksum_globals_t*) cbdata;
	struct t_infolist *sig_infolist = (struct t_infolist*) signal_data;
	struct t_infolist *infolist     = weechat_infolist_get("xfer", NULL, NULL);

	if (!infolist)                            return WEECHAT_RC_ERROR;
	if (!sig_infolist)                        return WEECHAT_RC_ERROR;
	if (!weechat_infolist_next(sig_infolist)) return WEECHAT_RC_ERROR;

	const char *sig_filename = weechat_infolist_string(sig_infolist, "filename");
	char *crc32 = get_crc32(globals->re_crc32, sig_filename);
	if (crc32) {
		while (weechat_infolist_next(infolist)) {
			const char *filename = weechat_infolist_string(infolist, "filename");
			int status = weechat_infolist_integer(infolist, "status");
			if (status == XFER_STATUS_DONE && strcmp(filename, sig_filename) == 0) {
				/* Match found, create new cksum_xfer and hash in 5 seconds */
				const char *fn = weechat_infolist_string(infolist, "local_filename");
				if (fn) {
					cksum_xfer_t *xfer = cksum_xfer_new(fn, crc32);
					if (xfer) {
						struct t_hook *hook = weechat_hook_timer(5000, 0, 1,
						                                         &cksum_cb_timer,
						                                         xfer);
						if (hook) {
							xfer->timer = hook;
							cksum_xfers_add(xfer);
						} else {
							cksum_xfer_free(xfer);
						}
					}
				}
				break;
			}
		}

		free (crc32);
	}

	weechat_infolist_free (infolist);

	return WEECHAT_RC_OK;
}

EXTERN int
weechat_plugin_init (struct t_weechat_plugin *plugin,
                     int                      argc   __attribute__((unused)),
                     char                    *argv[] __attribute__((unused)))
{
	weechat_plugin = plugin;
	if (!cksum_global_init()) return WEECHAT_RC_ERROR;

	cksum_globals_t *globals    = cksum_global_data;
	struct t_hook   *print_hook = weechat_hook_print(NULL, NULL, NULL,
	                                                 1, &cksum_cb_process_message,
	                                                 globals);
	if (print_hook == NULL) goto err;
	struct t_hook   *xfer_hook  = weechat_hook_signal("xfer_ended",
	                                                  &cksum_cb_xfer_ended,
	                                                  globals);
	if (xfer_hook == NULL) {
		weechat_unhook(print_hook);
		goto err;
	}

	globals->hook_print      = print_hook;
	globals->hook_xfer_ended = xfer_hook;

	return WEECHAT_RC_OK;

 err:
	weechat_plugin_end(plugin);
	return WEECHAT_RC_OK;
}

EXTERN int
weechat_plugin_end (struct t_weechat_plugin *weechat_plugin)
{
	cksum_globals_t *globals = cksum_global_data;

	if (globals) {
		cksum_xfers_remove_all();
		weechat_hashtable_free (cksum_global_data->xfers);
		if (globals->hook_print) weechat_unhook(globals->hook_print);
		if (globals->hook_xfer_ended) weechat_unhook(globals->hook_xfer_ended);
		regfree (globals->re_crc32);
		regfree (globals->re_nick);
		regfree (globals->re_md5);
		regfree (globals->re_tx_complete);
		free (globals->re_crc32);
		free (globals->re_nick);
		free (globals->re_md5);
		free (globals->re_tx_complete);
		free (globals->buf);
		free (globals->ebuf);
		free (globals);
		cksum_global_data = NULL;
	}

	return WEECHAT_RC_OK;
}
