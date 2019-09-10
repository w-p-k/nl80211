
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/nl80211.h>
#include <netpacket/packet.h>
#include <linux/errqueue.h>

typedef signed char int8_t;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

//
#ifndef BIT
#define BIT(x) (1U << (x))
#endif

#if 0
enum nl80211_protocol_features {
	NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP = 1 << 0,
};
#endif

#define HOSTAPD_MODE_FLAG_HT_INFO_KNOWN BIT(0)
#define HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN BIT(1)

//
#define VHT_CHANWIDTH_USE_HT	0
#define VHT_CHANWIDTH_80MHZ	1
#define VHT_CHANWIDTH_160MHZ	2
#define VHT_CHANWIDTH_80P80MHZ	3

//
#define HOSTAPD_CHAN_DISABLED			0x00000001
#define HOSTAPD_CHAN_NO_IR			0x00000002
#define HOSTAPD_CHAN_RADAR			0x00000008
#define HOSTAPD_CHAN_HT40PLUS			0x00000010
#define HOSTAPD_CHAN_HT40MINUS			0x00000020
#define HOSTAPD_CHAN_HT40			0x00000040
#define HOSTAPD_CHAN_SURVEY_LIST_INITIALIZED	0x00000080


#define HOSTAPD_CHAN_DFS_UNKNOWN		0x00000000
#define HOSTAPD_CHAN_DFS_USABLE			0x00000100
#define HOSTAPD_CHAN_DFS_UNAVAILABLE		0x00000200
#define HOSTAPD_CHAN_DFS_AVAILABLE		0x00000300
#define HOSTAPD_CHAN_DFS_MASK			0x00000300

#define HOSTAPD_CHAN_VHT_10_70			0x00000800
#define HOSTAPD_CHAN_VHT_30_50			0x00001000
#define HOSTAPD_CHAN_VHT_50_30			0x00002000
#define HOSTAPD_CHAN_VHT_70_10			0x00004000

#define HOSTAPD_CHAN_INDOOR_ONLY		0x00010000
#define HOSTAPD_CHAN_GO_CONCURRENT		0x00020000

#define HOSTAPD_CHAN_VHT_10_150			0x00100000
#define HOSTAPD_CHAN_VHT_30_130			0x00200000
#define HOSTAPD_CHAN_VHT_50_110			0x00400000
#define HOSTAPD_CHAN_VHT_70_90			0x00800000
#define HOSTAPD_CHAN_VHT_90_70			0x01000000
#define HOSTAPD_CHAN_VHT_110_50			0x02000000
#define HOSTAPD_CHAN_VHT_130_30			0x04000000
#define HOSTAPD_CHAN_VHT_150_10			0x08000000

//
enum hostapd_chan_width_attr {
	HOSTAPD_CHAN_WIDTH_10 = BIT(0),
	HOSTAPD_CHAN_WIDTH_20 = BIT(1),
	HOSTAPD_CHAN_WIDTH_40P = BIT(2),
	HOSTAPD_CHAN_WIDTH_40M = BIT(3),
	HOSTAPD_CHAN_WIDTH_80 = BIT(4),
	HOSTAPD_CHAN_WIDTH_160 = BIT(5),
};

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
enum nlmsgerr_attrs {
	NLMSGERR_ATTR_UNUSED,
	NLMSGERR_ATTR_MSG,
	NLMSGERR_ATTR_OFFS,
	NLMSGERR_ATTR_COOKIE,

	__NLMSGERR_ATTR_MAX,
	NLMSGERR_ATTR_MAX = __NLMSGERR_ATTR_MAX -1
};
#endif

#ifndef NLM_F_CAPPED
#define NLM_F_CAPPED 0x100
#endif

#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

struct nl80211_global {
	struct nl_cb *nl_cb;
	struct nl_sock *nl;
	int nl80211_id;
};

//
enum hostapd_hw_mode {
	HOSTAPD_MODE_IEEE80211B,
	HOSTAPD_MODE_IEEE80211G,
	HOSTAPD_MODE_IEEE80211A,
	HOSTAPD_MODE_IEEE80211AD,
	HOSTAPD_MODE_IEEE80211ANY,
	NUM_HOSTAPD_MODES,
};

struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};

struct hostapd_channel_data {
	short chan;
	int freq;
	int flag;
	u32 allowed_bw;
	u8 max_tx_power;
	struct dl_list survey_list;
	s8 min_nf;
	long double interference_factor;
	unsigned int dfs_cac_ms;
};

#define HE_MAX_NUM_SS		8
#define HE_MAX_PHY_CAPAB_SIZE	3

struct he_ppe_threshold {
	u32 numss_m1;
	u32 ru_count;
	u32 ppet16_ppet8_ru3_ru0[HE_MAX_NUM_SS];
};	


struct he_capabilities {
	u8 he_supported;
	u32 phy_cap[HE_MAX_PHY_CAPAB_SIZE];
	u32 mac_cap;
	u32 mcs;
	struct he_ppe_threshold ppet;
};

struct hostapd_hw_modes {
	enum hostapd_hw_mode mode;
	int num_channels;
	struct hostapd_channel_data *channels;
	int num_rates;
	int *rates;
	u16 ht_capab;
	u8 mcs_set[16];
	u8 a_mpdu_params;
	u32 vht_capab;
	u8 vht_mcs_set[8];
	unsigned int flags;
	struct he_capabilities he_capab;
};

	
	

struct phy_info_arg {
	u16 *num_modes;
	struct hostapd_hw_modes *modes;
	int last_mode, last_chan_idx;
	int failed;
	u8 dfs_domain;
};

//
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
	int len = nlh->nlmsg_len;
	struct nlattr *attrs;
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	int *ret = arg;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

	*ret = err->error;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_SKIP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	if (len <= ack_len)
		return NL_STOP;

	attrs = (void *)((unsigned char *)nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG]) {
		len = strnlen((char *)nla_data(tb[NLMSGERR_ATTR_MSG]),
			      nla_len(tb[NLMSGERR_ATTR_MSG]));
		printf("nl80211: kernel reports %*s", len, (char *)nla_data(tb[NLMSGERR_ATTR_MSG]));
	}

	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static void nl80211_nlmsg_clear(struct nl_msg *msg)
{
	if (msg) {
		struct nlmsghdr *hdr = nlmsg_hdr(msg);
		void *data = nlmsg_data(hdr);

		int len = hdr->nlmsg_len - NLMSG_HDRLEN;

		memset(data, 0, len);
	}
}

static int send_and_recv(struct nl80211_global *global, struct nl_sock *nl_handle,
			 struct nl_msg *msg, int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM, opt;

	if (!msg)
		return -ENOMEM;

	cb = nl_cb_clone(global->nl_cb);
	if (!cb)
		goto out;
	
	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	opt = 1;
	setsockopt(nl_socket_get_fd(nl_handle), SOL_NETLINK, NETLINK_EXT_ACK,
		   &opt, sizeof(opt));

	/* try to set NETLINK_CAP_ACK to 1, ignoring errors */
	opt = 1;
	setsockopt(nl_socket_get_fd(nl_handle), SOL_NETLINK, NETLINK_CAP_ACK,
		   &opt, sizeof(opt));

	err = nl_send_auto_complete(nl_handle, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0) {
		int res = nl_recvmsgs(nl_handle, cb);
		if (res < 0) {
			printf("nl80211: %s->nl_recvmsgs failed: %d",
			       __func__, res);
		}
	}
out:
	nl_cb_put(cb);
	if (!valid_handler && valid_data == (void *) - 1)
		nl80211_nlmsg_clear(msg);
	nlmsg_free(msg);
	return err;
}

int send_and_recv_msgs(struct nl80211_global *global, struct nl_msg *msg,
		       int (*valid_handler)(struct nl_msg *, void *),
		       void *valid_data)
{
	return send_and_recv(global, global->nl, msg, valid_handler, valid_data);
}

void *nl80211_cmd(int drv_id, struct nl_msg *msg, int flags, uint8_t cmd)
{
    return genlmsg_put(msg, 0, 0, drv_id, 0, flags, cmd, 0);
}

struct nl_msg *nl80211_cmd_msg(struct nl80211_global *global, int flags, uint8_t cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	if (!nl80211_cmd(global->nl80211_id, msg, flags, cmd)) {
		nlmsg_free(msg);
		return NULL;
	}

	return msg;
}

static int protocol_feature_handler(struct nl_msg *msg, void *arg)
{
	u32 *feat = arg;
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_PROTOCOL_FEATURES])
		*feat = nla_get_u32(tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]);

	return NL_SKIP;
}

static u32 get_nl80211_protocol_features(struct nl80211_global *global)
{
	u32 feat = 0;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return 0;

	if (!nl80211_cmd(global->nl80211_id, msg, 0, NL80211_CMD_GET_PROTOCOL_FEATURES)) {
		nlmsg_free(msg);
		return 0;
	}

	if (send_and_recv_msgs(global, msg, protocol_feature_handler, &feat) == 0)
		return feat;

	return 0;
}



static inline void *os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t)0)/size)
		return NULL;
	return realloc(ptr, nmemb * size);
}

static void phy_info_ht_capa(struct hostapd_hw_modes *mode, struct nlattr *capa,
			struct nlattr *ampdu_factor,
			struct nlattr *ampdu_density,
			struct nlattr *mcs_set)
{
	if (capa)
		mode->ht_capab = nla_get_u16(capa);

	if (ampdu_factor)
		mode->a_mpdu_params |= nla_get_u8(ampdu_factor) & 0x03;

	if (ampdu_density)
		mode->a_mpdu_params |= nla_get_u8(ampdu_density) << 2;

	if (mcs_set && nla_len(mcs_set) >= 16) {
		u8 *mcs;
		mcs = nla_data(mcs_set);
		memcpy(mode->mcs_set, mcs, 16);
	}
}

static void phy_info_vht_capa(struct hostapd_hw_modes *mode,
			struct nlattr *capa,
			struct nlattr *mcs_set)
{
	if (capa)
		mode->vht_capab = nla_get_u32(capa);

	if (mcs_set && nla_len(mcs_set) >= 8) {
		u8 *mcs;
		mcs = nla_data(mcs_set);
		memcpy(mode->vht_mcs_set, mcs, 8);
	}
}

enum hostapd_hw_mode ieee80211_freq_to_channel_ext(unsigned int freq,
				int sec_channel, int vht,
				u8 *op_class, u8 *channel)
{
	u8 vht_opclass;

	if (sec_channel > 1 || sec_channel < -1)
		return NUM_HOSTAPD_MODES;

	if (freq >= 2412 && freq <= 2472) {
		if ((freq - 2407) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht)
			return NUM_HOSTAPD_MODES;

		if (sec_channel == 1)
			*op_class = 83;
		else if (sec_channel == -1)
			*op_class = 84;
		else
			*op_class = 81;

		*channel = (freq - 2407)/5;

		return HOSTAPD_MODE_IEEE80211G;
	}

	if (freq == 2484) {
		if (sec_channel || vht)
			return NUM_HOSTAPD_MODES;
		*op_class = 82;
		*channel = 14;

		return HOSTAPD_MODE_IEEE80211B;
	}

	if (freq >= 4900 && freq < 5000) {
		if ((freq - 4000) % 5)
			return NUM_HOSTAPD_MODES;
		*channel = (freq - 4000)/5;
		*op_class = 0;
		return HOSTAPD_MODE_IEEE80211A;
	}

	switch (vht) {
	case VHT_CHANWIDTH_80MHZ:
		vht_opclass = 128;
		break;
	case VHT_CHANWIDTH_160MHZ:
		vht_opclass = 129;
		break;
	case VHT_CHANWIDTH_80P80MHZ:
		vht_opclass = 130;
		break;
	default:
		vht_opclass = 0;
		break;
	}

	if (freq >= 5180 && freq <= 5240) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 116;
		else if (sec_channel == -1)
			*op_class = 117;
		else
			*op_class = 115;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq >= 5260 && freq <= 5320) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 119;
		else if (sec_channel == -1)
			*op_class = 120;
		else
			*op_class = 118;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq >= 5745 && freq <= 5845) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 126;
		else if (sec_channel == -1)
			*op_class = 127;
		else if (freq <= 5805)
			*op_class = 124;
		else
			*op_class = 125;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq >= 5000 && freq <= 5700) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;

		if (vht_opclass)
			*op_class = vht_opclass;
		else if (sec_channel == 1)
			*op_class = 122;
		else if (sec_channel == -1)
			*op_class = 123;
		else
			*op_class = 121;

		*channel = (freq - 5000) / 5;

		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq >= 5000 && freq < 5900) {
		if ((freq - 5000) % 5)
			return NUM_HOSTAPD_MODES;
		*channel = (freq - 5000)/5;
		*op_class = 0;
		return HOSTAPD_MODE_IEEE80211A;
	}

	if (freq >= 56160 + 2160 * 1 && freq <= 561600 + 2160 *4) {
		if (sec_channel || vht)
			return NUM_HOSTAPD_MODES;

		*channel = (freq - 56160) / 2160;
		*op_class = 180;
		return HOSTAPD_MODE_IEEE80211AD;
	}

	return NUM_HOSTAPD_MODES;
}


enum hostapd_hw_mode ieee80211_freq_to_chan(int freq, u8 *channel)
{
	u8 op_class;

	return ieee80211_freq_to_channel_ext(freq, 0, VHT_CHANWIDTH_USE_HT,
				&op_class, channel);
}

static void phy_info_freq(struct hostapd_hw_modes *mode,
			struct hostapd_channel_data *chan,
			struct nlattr *tb_freq[])
{
	u8 channel;
	chan->freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
	chan->flag = 0;
	chan->allowed_bw = ~0;
	chan->dfs_cac_ms = 0;
	if (ieee80211_freq_to_chan(chan->freq, &channel) != NUM_HOSTAPD_MODES)
		chan->chan = channel;

	if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
		chan->flag |= HOSTAPD_CHAN_DISABLED;
	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR])
		chan->flag |= HOSTAPD_CHAN_NO_IR;
	if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
		chan->flag |= HOSTAPD_CHAN_RADAR;
	if (tb_freq[NL80211_FREQUENCY_ATTR_INDOOR_ONLY])
		chan->flag |= HOSTAPD_CHAN_INDOOR_ONLY;
	if (tb_freq[NL80211_FREQUENCY_ATTR_GO_CONCURRENT])
		chan->flag |= HOSTAPD_CHAN_GO_CONCURRENT;

	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_10MHZ])
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_10;
	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_20MHZ])
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_20;
	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS])
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40P;
	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS])
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40M;
	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_80MHZ])
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_80;
	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_160MHZ])
		chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_160;

	if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]) {
		enum nl80211_dfs_state state =
			nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);

		switch (state) {
		case NL80211_DFS_USABLE:
			chan->flag |= HOSTAPD_CHAN_DFS_USABLE;
			break;
		case NL80211_DFS_AVAILABLE:
			chan->flag |= HOSTAPD_CHAN_DFS_AVAILABLE;
			break;
		case NL80211_DFS_UNAVAILABLE:
			chan->flag |= HOSTAPD_CHAN_DFS_UNAVAILABLE;
			break;
		}
	}

	if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]) {
		chan->dfs_cac_ms = nla_get_u32(
			tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]);
	}
}

static int phy_info_freqs(struct phy_info_arg *phy_info, 
		struct hostapd_hw_modes *mode, struct nlattr *tb)
{
	static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = {.type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IR] = {.type = NLA_FLAG},
		[NL80211_FREQUENCY_ATTR_RADAR] = {.type = NLA_FLAG},
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = {.type = NLA_U32},
		[NL80211_FREQUENCY_ATTR_DFS_STATE] = {.type = NLA_U32},
		[NL80211_FREQUENCY_ATTR_NO_10MHZ] = {.type = NLA_FLAG},
		[NL80211_FREQUENCY_ATTR_NO_20MHZ] = {.type = NLA_FLAG},
		[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS] = {.type = NLA_FLAG},
		[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS] = {.type = NLA_FLAG},
		[NL80211_FREQUENCY_ATTR_NO_80MHZ] = {.type = NLA_FLAG},
		[NL80211_FREQUENCY_ATTR_NO_160MHZ] = {.type = NLA_FLAG},
	};
	int new_channels = 0;
	struct hostapd_channel_data *channel;
	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	struct nlattr *nl_freq;
	int rem_freq, idx;

	if (tb == NULL)
		return NL_OK;

	nla_for_each_nested(nl_freq, tb, rem_freq) {
		nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			nla_data(nl_freq), nla_len(nl_freq), freq_policy);
		if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
			continue;
		new_channels++;
	}

	channel = os_realloc_array(mode->channels,
				mode->num_channels + new_channels,
				sizeof(struct hostapd_channel_data));
	if (!channel)
		return NL_STOP;

	mode->channels = channel;
	mode->num_channels += new_channels;

	idx = phy_info->last_chan_idx;

	nla_for_each_nested(nl_freq, tb, rem_freq) {
		nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			nla_data(nl_freq), nla_len(nl_freq), freq_policy);
		if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
			continue;
		phy_info_freq(mode, &mode->channels[idx], tb_freq);
		idx++;
	}
	phy_info->last_chan_idx = idx;

	return NL_OK;
}

static int phy_info_rates(struct hostapd_hw_modes *mode, struct nlattr *tb)
{
	static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = {.type = NLA_U32},
		[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = {.type = NLA_FLAG },
	};
	struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
	struct nlattr *nl_rate;
	int rem_rate, idx;

	if (tb == NULL)
		return NL_OK;

	nla_for_each_nested(nl_rate, tb, rem_rate) {
		nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX,
		nla_data(nl_rate), nla_len(nl_rate),
		rate_policy);
		if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
			continue;
		mode->num_rates++;
	}

	mode->rates = malloc(mode->num_rates * sizeof(int));
	if (!mode->rates)
		return NL_STOP;
	memset(mode->rates, 0, mode->num_rates * sizeof(int));

	idx = 0;

	nla_for_each_nested(nl_rate, tb, rem_rate) {
		nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX,
			nla_data(nl_rate), nla_len(nl_rate),
			rate_policy);
		if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
			continue;
		mode->rates[idx] = nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]);
		idx++;
	}

	return NL_OK;
}

static int phy_info_band(struct phy_info_arg *phy_info, struct nlattr *nl_band)
{
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct hostapd_hw_modes *mode;
	int ret;

	if (phy_info->last_mode != nl_band->nla_type) {
		mode = os_realloc_array(phy_info->modes, *phy_info->num_modes + 1, sizeof(*mode));
		if (!mode) {
			phy_info->failed = 1;
			return NL_STOP;
		}
		phy_info->modes = mode;

		mode = &phy_info->modes[*(phy_info->num_modes)];
		memset(mode, 0, sizeof(*mode));
		mode->mode = NUM_HOSTAPD_MODES;
		mode->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN | 
			      HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN;

		mode->vht_mcs_set[0] = 0xff;
		mode->vht_mcs_set[1] = 0xff;
		mode->vht_mcs_set[4] = 0xff;
		mode->vht_mcs_set[5] = 0xff;

		*(phy_info->num_modes) += 1;
		phy_info->last_mode = nl_band->nla_type;
		phy_info->last_chan_idx = 0;
	} else
		mode = &phy_info->modes[*(phy_info->num_modes) - 1];

	nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band),
		  nla_len(nl_band), NULL);

	phy_info_ht_capa(mode, tb_band[NL80211_BAND_ATTR_HT_CAPA],
		tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR],
		tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY],
		tb_band[NL80211_BAND_ATTR_HT_MCS_SET]);
	phy_info_vht_capa(mode, tb_band[NL80211_BAND_ATTR_VHT_CAPA],
		tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);
	ret = phy_info_freqs(phy_info, mode, tb_band[NL80211_BAND_ATTR_FREQS]);
	if (ret == NL_OK)
		ret = phy_info_rates(mode, tb_band[NL80211_BAND_ATTR_RATES]);
	if (ret != NL_OK) {
		phy_info->failed = 1;
		return ret;
	}

	return NL_OK;
}

	

 

static int phy_info_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct phy_info_arg *phy_info = arg;
	struct nlattr *nl_band;
	int rem_band;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
		return NL_SKIP;

	nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band)
	{
		int res = phy_info_band(phy_info, nl_band);
		if (res != NL_OK)
			return res;
	}

	return NL_SKIP;
}

int do_wiphy(struct nl80211_global *global)
{
	u32 feat;
	int nl_flags = 0;
	struct nl_msg *msg;
	int ret;
	u16 num_modes = 0;
	struct phy_info_arg result = {
		.num_modes = &num_modes,
		.modes = NULL,
		.last_mode = -1,
		.failed = 0,
		.dfs_domain = 0,
	};
	int i;
	

	feat = get_nl80211_protocol_features(global);
	printf("feat=0x%x\n", feat);
	if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
		nl_flags = NLM_F_DUMP;

	if (!(msg = nl80211_cmd_msg(global, nl_flags, NL80211_CMD_GET_WIPHY)) ||
	    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP)) {
		nlmsg_free(msg);
		return -1;
	}

	if ((ret = send_and_recv_msgs(global, msg, phy_info_handler, &result)) != 0) {
		printf("%s: failed: ret=%d\n", __func__, ret);
	} else {
		printf("%s: success, num_modes=%d, result.failed=%d\n", __func__, num_modes, result.failed);
		for (i=0; i<num_modes; i++) {
			printf("mode[%d]=%d\n", i, result.modes[i].mode);
			printf("num_channels=%d\n", result.modes[i].num_channels);
			printf("channel freq=%d\n", result.modes[i].channels[0].freq);
		}
	}

	return ret;
}

static struct nl_sock *nl_create_handle(struct nl_cb *cb, const char *dbg)
{
	struct nl_sock *socket;

	socket = nl_socket_alloc();
	if (socket == NULL) {
		printf("nl80211: Failed to allocate netlink callbacks (%s)\n", dbg);
		return NULL;
	}

	if (genl_connect(socket)) {
		printf("nl80211: Failed to connect to generic netlin (%s)\n", dbg);
		nl_socket_free(socket);
		return NULL;
	}
	return socket;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static int init_nl_global(struct nl80211_global *global)
{
    	// Use interface wlan0 for scanning
    	int if_index = if_nametoindex("wlan1");

	global->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (global->nl_cb == NULL) {
		printf("nl80211: Failed to allocate netlink callbacks\n");
		return -1;
	}

	global->nl = nl_create_handle(global->nl_cb, "nl");
	if (global->nl == NULL)
		goto err;

	global->nl80211_id = genl_ctrl_resolve(global->nl, "nl80211");
	if (global->nl80211_id < 0) {
		printf("nl80211: 'nl80211' generic netlink not found\n");
		goto err;
	}

	nl_cb_set(global->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	//nl_cb_set(global->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_global_event, global);
	return 0;

err:
	if (global->nl)
		nl_socket_free(global->nl);
	nl_cb_put(global->nl_cb);
	global->nl_cb = NULL;
	return -1;
}


int main()
{
	struct nl80211_global global_drv;
	int err;

	err = init_nl_global(&global_drv);
	if (err != 0) {
		printf("init_nl_global failed, err=%d\n", err);
		return -1;
	}

    	err = do_wiphy(&global_drv);
    	if ( err != 0) {
		printf("do_connect() failed with %d. \n", err);
		return err;
    	}

    	return 0;
}


