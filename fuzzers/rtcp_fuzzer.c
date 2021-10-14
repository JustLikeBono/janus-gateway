#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <glib.h>
#include "../debug.h"
#include "../rtcp.h"
#include "../rtp.h"

int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;

int RAND_bytes(uint8_t *key, int len) {
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

	if (size > 1472) return 0;

	if (size <= 0) return 0;

	if (!janus_is_rtcp((char *)data, size)) return 0;

	if (size < 8) return 0;

	uint8_t cdata0[size], cdata1[size], cdata2[size], cdata3[size], cdata4[size], cdata5[size];
	uint8_t *cdata[6] = { cdata0, cdata1, cdata2, cdata3, cdata4, cdata5 };
	int idx, newlen;
	for (idx=0; idx < 6; idx++)
		memcpy(cdata[idx], data, size);

	idx = 0;

	janus_rtcp_context ctx0, ctx1;
	memset(&ctx0, 0, sizeof(janus_rtcp_context));
	memset(&ctx1, 0, sizeof(janus_rtcp_context));


	janus_rtcp_has_bye((char *)data, size);
	janus_rtcp_has_fir((char *)data, size);
	janus_rtcp_has_pli((char *)data, size);
	janus_rtcp_get_receiver_ssrc((char *)data, size);
	janus_rtcp_get_remb((char *)data, size);
	janus_rtcp_get_sender_ssrc((char *)data, size);

	janus_rtcp_cap_remb((char *)cdata[idx++], size, 256000);
	janus_rtcp_swap_report_blocks((char *)cdata[idx++], size, 2);
	janus_rtcp_fix_report_data((char *)cdata[idx++], size, 2000, 1000, 2, 2, 2, TRUE);
	janus_rtcp_fix_ssrc(&ctx0, (char *)cdata[idx++], size, 1, 2, 2);
	janus_rtcp_parse(&ctx1, (char *)cdata[idx++], size);
	janus_rtcp_remove_nacks((char *)cdata[idx++], size);

	char *output_data = janus_rtcp_filter((char *)data, size, &newlen);
	GSList *list = janus_rtcp_get_nacks((char *)data, size);


	g_free(output_data);
	if (list) g_slist_free(list);
	return 0;
}
