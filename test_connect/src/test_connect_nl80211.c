
#include <stdio.h>
#include <errno.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>


struct trigger_results {
    int done;
    int aborted;
};


static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
    // Callback for errors.
    printf("error_handler() called.\n");
    int *ret = arg;
    *ret = err->error;
    return NL_STOP;
}


static int finish_handler(struct nl_msg *msg, void *arg) {
    // Callback for NL_CB_FINISH.
    int *ret = arg;
    *ret = 0;
    return NL_SKIP;
}


static int ack_handler(struct nl_msg *msg, void *arg) {
    // Callback for NL_CB_ACK.
    int *ret = arg;
    *ret = 0;
    return NL_STOP;
}


static int no_seq_check(struct nl_msg *msg, void *arg) {
    // Callback for NL_CB_SEQ_CHECK.
    return NL_OK;
}


void mac_addr_n2a(char *mac_addr, unsigned char *arg) {
    // From http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c.
    int i, l;

    l = 0;
    for (i = 0; i < 6; i++) {
        if (i == 0) {
            sprintf(mac_addr+l, "%02x", arg[i]);
            l += 2;
        } else {
            sprintf(mac_addr+l, ":%02x", arg[i]);
            l += 3;
        }
    }
}


void print_ssid(unsigned char *ie, int ielen) {
    uint8_t len;
    uint8_t *data;
    int i;

    while (ielen >= 2 && ielen >= ie[1]) {
        if (ie[0] == 0 && ie[1] >= 0 && ie[1] <= 32) {
            len = ie[1];
            data = ie + 2;
            for (i = 0; i < len; i++) {
                if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\') printf("%c", data[i]);
                else if (data[i] == ' ' && (i != 0 && i != len -1)) printf(" ");
                else printf("\\x%.2x", data[i]);
            }
            break;
        }
        ielen -= ie[1] + 2;
        ie += ie[1] + 2;
    }
}


static int callback_trigger(struct nl_msg *msg, void *arg) {
    // Called by the kernel when the scan is done or has been aborted.
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct trigger_results *results = arg;

    //printf("Got something.\n");
    //printf("%d\n", arg);
    //nl_msg_dump(msg, stdout);

    if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
        printf("Got NL80211_CMD_SCAN_ABORTED.\n");
        results->done = 1;
        results->aborted = 1;
    } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
        printf("Got NL80211_CMD_NEW_SCAN_RESULTS.\n");
        results->done = 1;
        results->aborted = 0;
    }  // else probably an uninteresting multicast message.

    return NL_SKIP;
}


static int callback_dump(struct nl_msg *msg, void *arg) {
    // Called by the kernel with a dump of the successful scan's data. Called for each SSID.
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    char mac_addr[20];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_TSF] = { .type = NLA_U64 },
        [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_BSS_BSSID] = { },
        [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
        [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { },
        [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
        [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
        [NL80211_BSS_STATUS] = { .type = NLA_U32 },
        [NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES] = { },
    };

    // Parse and error check.
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[NL80211_ATTR_BSS]) {
        printf("bss info missing!\n");
        return NL_SKIP;
    }
    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy)) {
        printf("failed to parse nested attributes!\n");
        return NL_SKIP;
    }
    if (!bss[NL80211_BSS_BSSID]) return NL_SKIP;
    if (!bss[NL80211_BSS_INFORMATION_ELEMENTS]) return NL_SKIP;

    // Start printing.
    mac_addr_n2a(mac_addr, nla_data(bss[NL80211_BSS_BSSID]));
    printf("%s, ", mac_addr);
    printf("%d MHz, ", nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
    print_ssid(nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]), nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));
    printf("\n");

    return NL_SKIP;
}

int do_connect(struct nl_sock *socket, int if_index, int driver_id) {
    // Starts the scan and waits for it to finish. Does not return until the scan is done or has been aborted.
    struct trigger_results results = { .done = 0, .aborted = 0 };
    struct nl_msg *msg;
    struct nl_msg *ssids_to_scan;
    int err;
    int ret;

    // Allocate the messages and callback handler.
    msg = nlmsg_alloc();
    if (!msg) {
        printf("ERROR: Failed to allocate netlink message for msg.\n");
        return -ENOMEM;
    }

    // Setup the messages and callback handler.
    genlmsg_put(msg, 0, 0, driver_id, 0, (NLM_F_REQUEST | NLM_F_ACK), NL80211_CMD_CONNECT, 0);  // Setup which command to run.
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);  // Add message attribute, which interface to use.
    nla_put(msg, NL80211_ATTR_SSID, strlen("Validator_Test"), "Validator_Test");
    
    err = 1;
    ret = nl_send_auto_complete(socket, msg);  // Send the message.
    printf("NL80211_CMD_CONNECT sent %d bytes to the kernel.\n", ret);
    printf("Waiting for connection to complete...\n");
    ret = nl_recvmsgs_default(socket);  // First wait for ack_handler(). This helps with basic errors.
    if (ret < 0) {
        printf("ERROR: nl_recvmsgs() returned %d (%s).\n", ret, nl_geterror(-ret));
    }
    printf("connection is done.\n");

    // Cleanup.
    nlmsg_free(msg);
    return ret;
}


int main()
{
    // Use interface wlan0 for scanning
    int if_index = if_nametoindex("wlan0");

    // Open socket to kernel
    struct nl_sock *socket = nl_socket_alloc();
    genl_connect(socket);
    int driver_id = genl_ctrl_resolve(socket, "nl80211");

    // Issue NL80211_CMD_TRIGGER_SCAN to the kernel and wait for it to finish
    int err = do_connect(socket, if_index, driver_id);
    if ( err != 0) {
	printf("do_connect() failed with %d. \n", err);
	return err;
    }

    return 0;
}


