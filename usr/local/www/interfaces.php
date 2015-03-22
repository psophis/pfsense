<?php
/* $Id$ */
/*
	interfaces.php
	Copyright (C) 2013-2015 Electric Sheep Fencing, LP
	Copyright (C) 2004-2008 Scott Ullrich
	Copyright (C) 2006 Daniel S. Haischt.
	Copyright (C) 2008-2010 Ermal Luçi
	All rights reserved.

	originally part of m0n0wall (http://m0n0.ch/wall)
	Copyright (C) 2003-2004 Manuel Kasper <mk@neon1.net>.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	1. Redistributions of source code must retain the above copyright notice,
	   this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
	AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
	AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
	OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/
/*
	pfSense_BUILDER_BINARIES:	/usr/sbin/arp
	pfSense_MODULE:	interfaces
*/

##|+PRIV
##|*IDENT=page-interfaces
##|*NAME=Interfaces: WAN page
##|*DESCR=Allow access to the 'Interfaces' page.
##|*MATCH=interfaces.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("ipsec.inc");
require_once("functions.inc");
require_once("captiveportal.inc");
require_once("filter.inc");
require_once("shaper.inc");
require_once("rrd.inc");
require_once("vpn.inc");
require_once("xmlparse_attr.inc");

$referer = (isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '/interfaces.php');

// Get configured interface list
$ifdescrs = get_configured_interface_with_descr(false, true);

$if = "wan";
if ($_REQUEST['if']) {
	$if = $_REQUEST['if'];
}

if (empty($ifdescrs[$if])) {
	header("Location: interfaces.php");
	exit;
}

define("CRON_MONTHLY_PATTERN", "0 0 1 * *");
define("CRON_WEEKLY_PATTERN", "0 0 * * 0");
define("CRON_DAILY_PATTERN", "0 0 * * *");
define("CRON_HOURLY_PATTERN", "0 * * * *");

if (!is_array($pconfig)) {
	$pconfig = array();
}

$config['ppps'] = array();
if (!is_array($config['ppps'])) {
}
if (!is_array($config['ppps']['ppp'])) {
	$config['ppps']['ppp'] = array();
}
$a_ppps = &$config['ppps']['ppp'];

function remove_bad_chars($string)
{
	return preg_replace('/[^a-z_0-9]/i','',$string);
}

if (!is_array($config['gateways']['gateway_item'])) {
	$config['gateways']['gateway_item'] = array();
}
$a_gateways = &$config['gateways']['gateway_item'];

$wancfg = &$config['interfaces'][$if];
$old_wancfg = $wancfg;
$old_wancfg['realif'] = get_real_interface($if);
$old_ppps = $a_ppps;
// Populate page descr if it does not exist.
if ($if == "wan" && !$wancfg['descr']) {
	$wancfg['descr'] = "WAN";
} else if ($if == "lan" && !$wancfg['descr']) {
	$wancfg['descr'] = "LAN";
}

/* NOTE: The code here is used to set the $pppid for the curious */
foreach ($a_ppps as $pppid => $ppp) {
	if ($wancfg['if'] == $ppp['if']) {
		break;
	}
}

$type_disabled = (substr($wancfg['if'], 0, 3) == 'gre') ? 'disabled' : '';

if ($wancfg['if'] == $a_ppps[$pppid]['if']) {
	$pconfig['pppid'] = $pppid;
	$pconfig['ptpid'] = $a_ppps[$pppid]['ptpid'];
	$pconfig['port'] = $a_ppps[$pppid]['ports'];
	if ($a_ppps[$pppid]['type'] == "ppp") {
		$pconfig['username'] = $a_ppps[$pppid]['username'];
		$pconfig['password'] = base64_decode($a_ppps[$pppid]['password']);

		$pconfig['phone'] = $a_ppps[$pppid]['phone'];
		$pconfig['apn'] = $a_ppps[$pppid]['apn'];
	} else if ($a_ppps[$pppid]['type'] == "pppoe") {
		$pconfig['pppoe_username'] = $a_ppps[$pppid]['username'];
		$pconfig['pppoe_password'] = base64_decode($a_ppps[$pppid]['password']);
		$pconfig['provider'] = $a_ppps[$pppid]['provider'];
		$pconfig['pppoe_dialondemand'] = isset($a_ppps[$pppid]['ondemand']);
		$pconfig['pppoe_idletimeout'] = $a_ppps[$pppid]['idletimeout'];

		/* ================================================ */
		/* = force a connection reset at a specific time? = */
		/* ================================================ */

		if (isset($a_ppps[$pppid]['pppoe-reset-type'])) {
			$pconfig['pppoe-reset-type'] = $a_ppps[$pppid]['pppoe-reset-type'];
			$itemhash = getMPDCRONSettings($a_ppps[$pppid]['if']);
			if ($itemhash)
				$cronitem = $itemhash['ITEM'];
			if (isset($cronitem)) {
				$resetTime = "{$cronitem['minute']} {$cronitem['hour']} {$cronitem['mday']} {$cronitem['month']} {$cronitem['wday']}";
			} else {
				$resetTime = NULL;
			}
			//log_error("ResetTime:".$resetTime);
			if ($a_ppps[$pppid]['pppoe-reset-type'] == "custom") {
				if ($cronitem) {
					$pconfig['pppoe_pr_custom'] = true;
					$pconfig['pppoe_resetminute'] = $cronitem['minute'];
					$pconfig['pppoe_resethour'] = $cronitem['hour'];
					if ($cronitem['mday'] <> "*" && $cronitem['month'] <> "*")
						$pconfig['pppoe_resetdate'] = "{$cronitem['month']}/{$cronitem['mday']}/" . date("Y");
				}
			} else if ($a_ppps[$pppid]['pppoe-reset-type'] == "preset") {
				$pconfig['pppoe_pr_preset'] = true;
				switch ($resetTime) {
					case CRON_MONTHLY_PATTERN:
						$pconfig['pppoe_monthly'] = true;
						break;
					case CRON_WEEKLY_PATTERN:
						$pconfig['pppoe_weekly'] = true;
						break;
					case CRON_DAILY_PATTERN:
						$pconfig['pppoe_daily'] = true;
						break;
					case CRON_HOURLY_PATTERN:
						$pconfig['pppoe_hourly'] = true;
						break;
				}
			}
		}// End force pppoe reset at specific time
	// End if type == pppoe
	} else if ($a_ppps[$pppid]['type'] == "pptp" || $a_ppps[$pppid]['type'] == "l2tp"){
		$pconfig['pptp_username'] = $a_ppps[$pppid]['username'];
		$pconfig['pptp_password'] = base64_decode($a_ppps[$pppid]['password']);
		$pconfig['pptp_local'] = explode(",",$a_ppps[$pppid]['localip']);
		$pconfig['pptp_subnet'] = explode(",",$a_ppps[$pppid]['subnet']);
		$pconfig['pptp_remote'] = explode(",",$a_ppps[$pppid]['gateway']);
		$pconfig['pptp_dialondemand'] = isset($a_ppps[$pppid]['ondemand']);
		$pconfig['pptp_idletimeout'] = $a_ppps[$pppid]['timeout'];
	}
} else {
	$pconfig['ptpid'] = interfaces_ptpid_next();
	$pppid = count($a_ppps);
}
$pconfig['dhcphostname'] = $wancfg['dhcphostname'];
$pconfig['alias-address'] = $wancfg['alias-address'];
$pconfig['alias-subnet'] = $wancfg['alias-subnet'];
$pconfig['dhcprejectfrom'] = $wancfg['dhcprejectfrom'];

$pconfig['adv_dhcp_pt_timeout'] = $wancfg['adv_dhcp_pt_timeout'];
$pconfig['adv_dhcp_pt_retry'] = $wancfg['adv_dhcp_pt_retry'];
$pconfig['adv_dhcp_pt_select_timeout'] = $wancfg['adv_dhcp_pt_select_timeout'];
$pconfig['adv_dhcp_pt_reboot'] = $wancfg['adv_dhcp_pt_reboot'];
$pconfig['adv_dhcp_pt_backoff_cutoff'] = $wancfg['adv_dhcp_pt_backoff_cutoff'];
$pconfig['adv_dhcp_pt_initial_interval'] = $wancfg['adv_dhcp_pt_initial_interval'];

$pconfig['adv_dhcp_pt_values'] = $wancfg['adv_dhcp_pt_values'];

$pconfig['adv_dhcp_send_options'] = $wancfg['adv_dhcp_send_options'];
$pconfig['adv_dhcp_request_options'] = $wancfg['adv_dhcp_request_options'];
$pconfig['adv_dhcp_required_options'] = $wancfg['adv_dhcp_required_options'];
$pconfig['adv_dhcp_option_modifiers'] = $wancfg['adv_dhcp_option_modifiers'];

$pconfig['adv_dhcp_config_advanced'] = $wancfg['adv_dhcp_config_advanced'];
$pconfig['adv_dhcp_config_file_override'] = $wancfg['adv_dhcp_config_file_override'];
$pconfig['adv_dhcp_config_file_override_path'] = $wancfg['adv_dhcp_config_file_override_path'];

$pconfig['adv_dhcp6_interface_statement_send_options'] = $wancfg['adv_dhcp6_interface_statement_send_options'];
$pconfig['adv_dhcp6_interface_statement_request_options'] = $wancfg['adv_dhcp6_interface_statement_request_options'];
$pconfig['adv_dhcp6_interface_statement_information_only_enable'] = $wancfg['adv_dhcp6_interface_statement_information_only_enable'];
$pconfig['adv_dhcp6_interface_statement_script'] = $wancfg['adv_dhcp6_interface_statement_script'];

$pconfig['adv_dhcp6_id_assoc_statement_address_enable'] = $wancfg['adv_dhcp6_id_assoc_statement_address_enable'];
$pconfig['adv_dhcp6_id_assoc_statement_address'] = $wancfg['adv_dhcp6_id_assoc_statement_address'];
$pconfig['adv_dhcp6_id_assoc_statement_address_id'] = $wancfg['adv_dhcp6_id_assoc_statement_address_id'];
$pconfig['adv_dhcp6_id_assoc_statement_address_pltime'] = $wancfg['adv_dhcp6_id_assoc_statement_address_pltime'];
$pconfig['adv_dhcp6_id_assoc_statement_address_vltime'] = $wancfg['adv_dhcp6_id_assoc_statement_address_vltime'];

$pconfig['adv_dhcp6_id_assoc_statement_prefix_enable'] = $wancfg['adv_dhcp6_id_assoc_statement_prefix_enable'];
$pconfig['adv_dhcp6_id_assoc_statement_prefix'] = $wancfg['adv_dhcp6_id_assoc_statement_prefix'];
$pconfig['adv_dhcp6_id_assoc_statement_prefix_id'] = $wancfg['adv_dhcp6_id_assoc_statement_prefix_id'];
$pconfig['adv_dhcp6_id_assoc_statement_prefix_pltime'] = $wancfg['adv_dhcp6_id_assoc_statement_prefix_pltime'];
$pconfig['adv_dhcp6_id_assoc_statement_prefix_vltime'] = $wancfg['adv_dhcp6_id_assoc_statement_prefix_vltime'];

$pconfig['adv_dhcp6_prefix_interface_statement_sla_id'] = $wancfg['adv_dhcp6_prefix_interface_statement_sla_id'];
$pconfig['adv_dhcp6_prefix_interface_statement_sla_len'] = $wancfg['adv_dhcp6_prefix_interface_statement_sla_len'];

$pconfig['adv_dhcp6_authentication_statement_authname'] = $wancfg['adv_dhcp6_authentication_statement_authname'];
$pconfig['adv_dhcp6_authentication_statement_protocol'] = $wancfg['adv_dhcp6_authentication_statement_protocol'];
$pconfig['adv_dhcp6_authentication_statement_algorithm'] = $wancfg['adv_dhcp6_authentication_statement_algorithm'];
$pconfig['adv_dhcp6_authentication_statement_rdm'] = $wancfg['adv_dhcp6_authentication_statement_rdm'];

$pconfig['adv_dhcp6_key_info_statement_keyname'] = $wancfg['adv_dhcp6_key_info_statement_keyname'];
$pconfig['adv_dhcp6_key_info_statement_realm'] = $wancfg['adv_dhcp6_key_info_statement_realm'];
$pconfig['adv_dhcp6_key_info_statement_keyid'] = $wancfg['adv_dhcp6_key_info_statement_keyid'];
$pconfig['adv_dhcp6_key_info_statement_secret'] = $wancfg['adv_dhcp6_key_info_statement_secret'];
$pconfig['adv_dhcp6_key_info_statement_expire'] = $wancfg['adv_dhcp6_key_info_statement_expire'];

$pconfig['adv_dhcp6_config_advanced'] = $wancfg['adv_dhcp6_config_advanced'];
$pconfig['adv_dhcp6_config_file_override'] = $wancfg['adv_dhcp6_config_file_override'];
$pconfig['adv_dhcp6_config_file_override_path'] = $wancfg['adv_dhcp6_config_file_override_path'];

$pconfig['dhcp_plus'] = isset($wancfg['dhcp_plus']);
$pconfig['descr'] = remove_bad_chars($wancfg['descr']);
$pconfig['enable'] = isset($wancfg['enable']);

if (is_array($config['aliases']['alias'])) {
	foreach($config['aliases']['alias'] as $alias) {
		if($alias['name'] == $wancfg['descr']) {
			$input_errors[] = sprintf(gettext("Sorry, an alias with the name %s already exists."),$wancfg['descr']);
		}
	}
}

switch($wancfg['ipaddr']) {
	case "dhcp":
		$pconfig['type'] = "dhcp";
		break;
	case "pppoe":
	case "pptp":
	case "l2tp":
	case "ppp":
		$pconfig['type'] = $wancfg['ipaddr'];
		break;
	default:
		if(is_ipaddrv4($wancfg['ipaddr'])) {
			$pconfig['type'] = "staticv4";
			$pconfig['ipaddr'] = $wancfg['ipaddr'];
			$pconfig['subnet'] = $wancfg['subnet'];
			$pconfig['gateway'] = $wancfg['gateway'];
		} else
			$pconfig['type'] = "none";
		break;
}

switch($wancfg['ipaddrv6']) {
	case "slaac":
		$pconfig['type6'] = "slaac";
		break;
	case "dhcp6":
		$pconfig['dhcp6-duid'] = $wancfg['dhcp6-duid'];
		if(!isset($wancfg['dhcp6-ia-pd-len']))
			$wancfg['dhcp6-ia-pd-len'] = "none";
		$pconfig['dhcp6-ia-pd-len'] = $wancfg['dhcp6-ia-pd-len'];
		$pconfig['dhcp6-ia-pd-send-hint'] = isset($wancfg['dhcp6-ia-pd-send-hint']);
		$pconfig['type6'] = "dhcp6";
		$pconfig['dhcp6prefixonly'] = isset($wancfg['dhcp6prefixonly']);
		$pconfig['dhcp6usev4iface'] = isset($wancfg['dhcp6usev4iface']);
		break;
	case "6to4":
		$pconfig['type6'] = "6to4";
		break;
	case "track6":
		$pconfig['type6'] = "track6";
		$pconfig['track6-interface'] = $wancfg['track6-interface'];
		if ($wancfg['track6-prefix-id'] == "")
			$pconfig['track6-prefix-id'] = 0;
		else
			$pconfig['track6-prefix-id'] = $wancfg['track6-prefix-id'];
		$pconfig['track6-prefix-id--hex'] = sprintf("%x", $pconfig['track6-prefix-id']);
		break;
	case "6rd":
		$pconfig['prefix-6rd'] = $wancfg['prefix-6rd'];
		if($wancfg['prefix-6rd-v4plen'] == "")
			$wancfg['prefix-6rd-v4plen'] = "0";
		$pconfig['prefix-6rd-v4plen'] = $wancfg['prefix-6rd-v4plen'];
		$pconfig['type6'] = "6rd";
		$pconfig['gateway-6rd'] = $wancfg['gateway-6rd'];
		break;
	default:
		if(is_ipaddrv6($wancfg['ipaddrv6'])) {
			$pconfig['type6'] = "staticv6";
			$pconfig['ipaddrv6'] = $wancfg['ipaddrv6'];
			$pconfig['subnetv6'] = $wancfg['subnetv6'];
			$pconfig['gatewayv6'] = $wancfg['gatewayv6'];
		} else
			$pconfig['type6'] = "none";
		break;
}

// print_r($pconfig);

$pconfig['blockpriv'] = isset($wancfg['blockpriv']);
$pconfig['blockbogons'] = isset($wancfg['blockbogons']);
$pconfig['spoofmac'] = $wancfg['spoofmac'];
$pconfig['mtu'] = $wancfg['mtu'];
$pconfig['mss'] = $wancfg['mss'];

/* Wireless interface? */
if (isset($wancfg['wireless'])) {
	/* Sync first to be sure it displays the actual settings that will be used */
	interface_sync_wireless_clones($wancfg, false);
	/* Get wireless modes */
	$wlanif = get_real_interface($if);
	if (!does_interface_exist($wlanif))
		interface_wireless_clone($wlanif, $wancfg);
	$wlanbaseif = interface_get_wireless_base($wancfg['if']);
	preg_match("/^(.*?)([0-9]*)$/", $wlanbaseif, $wlanbaseif_split);
	$wl_modes = get_wireless_modes($if);
	$wl_chaninfo = get_wireless_channel_info($if);
	$wl_sysctl_prefix = 'dev.' . $wlanbaseif_split[1] . '.' . $wlanbaseif_split[2];
	$wl_sysctl = get_sysctl(array("{$wl_sysctl_prefix}.diversity", "{$wl_sysctl_prefix}.txantenna", "{$wl_sysctl_prefix}.rxantenna",
		"{$wl_sysctl_prefix}.slottime", "{$wl_sysctl_prefix}.acktimeout", "{$wl_sysctl_prefix}.ctstimeout"));
	$wl_regdomain_xml_attr = array();
	$wl_regdomain_xml = parse_xml_regdomain($wl_regdomain_xml_attr);
	$wl_regdomains = &$wl_regdomain_xml['regulatory-domains']['rd'];
	$wl_regdomains_attr = &$wl_regdomain_xml_attr['regulatory-domains']['rd'];
	$wl_countries = &$wl_regdomain_xml['country-codes']['country'];
	$wl_countries_attr = &$wl_regdomain_xml_attr['country-codes']['country'];
	$pconfig['persistcommonwireless'] = isset($config['wireless']['interfaces'][$wlanbaseif]);
	$pconfig['standard'] = $wancfg['wireless']['standard'];
	$pconfig['mode'] = $wancfg['wireless']['mode'];
	$pconfig['protmode'] = $wancfg['wireless']['protmode'];
	$pconfig['ssid'] = $wancfg['wireless']['ssid'];
	$pconfig['channel'] = $wancfg['wireless']['channel'];
	$pconfig['txpower'] = $wancfg['wireless']['txpower'];
	$pconfig['diversity'] = $wancfg['wireless']['diversity'];
	$pconfig['txantenna'] = $wancfg['wireless']['txantenna'];
	$pconfig['rxantenna'] = $wancfg['wireless']['rxantenna'];
	$pconfig['distance'] = $wancfg['wireless']['distance'];
	$pconfig['regdomain'] = $wancfg['wireless']['regdomain'];
	$pconfig['regcountry'] = $wancfg['wireless']['regcountry'];
	$pconfig['reglocation'] = $wancfg['wireless']['reglocation'];
	$pconfig['wme_enable'] = isset($wancfg['wireless']['wme']['enable']);
	if (isset($wancfg['wireless']['puren']['enable'])) {
		$pconfig['puremode'] = '11n';
	} else if (isset($wancfg['wireless']['pureg']['enable'])) {
		$pconfig['puremode'] = '11g';
	} else {
		$pconfig['puremode'] = 'any';
	}
	$pconfig['apbridge_enable'] = isset($wancfg['wireless']['apbridge']['enable']);
	$pconfig['authmode'] = $wancfg['wireless']['authmode'];
	$pconfig['hidessid_enable'] = isset($wancfg['wireless']['hidessid']['enable']);
	$pconfig['auth_server_addr'] = $wancfg['wireless']['auth_server_addr'];
	$pconfig['auth_server_port'] = $wancfg['wireless']['auth_server_port'];
	$pconfig['auth_server_shared_secret'] = $wancfg['wireless']['auth_server_shared_secret'];
	$pconfig['auth_server_addr2'] = $wancfg['wireless']['auth_server_addr2'];
	$pconfig['auth_server_port2'] = $wancfg['wireless']['auth_server_port2'];
	$pconfig['auth_server_shared_secret2'] = $wancfg['wireless']['auth_server_shared_secret2'];
	if (is_array($wancfg['wireless']['wpa'])) {
		$pconfig['debug_mode'] = $wancfg['wireless']['wpa']['debug_mode'];
		$pconfig['macaddr_acl'] = $wancfg['wireless']['wpa']['macaddr_acl'];
		$pconfig['mac_acl_enable'] = isset($wancfg['wireless']['wpa']['mac_acl_enable']);
		$pconfig['auth_algs'] = $wancfg['wireless']['wpa']['auth_algs'];
		$pconfig['wpa_mode'] = $wancfg['wireless']['wpa']['wpa_mode'];
		$pconfig['wpa_key_mgmt'] = $wancfg['wireless']['wpa']['wpa_key_mgmt'];
		$pconfig['wpa_pairwise'] = $wancfg['wireless']['wpa']['wpa_pairwise'];
		$pconfig['wpa_group_rekey'] = $wancfg['wireless']['wpa']['wpa_group_rekey'];
		$pconfig['wpa_gmk_rekey'] = $wancfg['wireless']['wpa']['wpa_gmk_rekey'];
		$pconfig['wpa_strict_rekey'] = isset($wancfg['wireless']['wpa']['wpa_strict_rekey']);
		$pconfig['passphrase'] = $wancfg['wireless']['wpa']['passphrase'];
		$pconfig['ieee8021x'] = isset($wancfg['wireless']['wpa']['ieee8021x']['enable']);
		$pconfig['rsn_preauth'] = isset($wancfg['wireless']['wpa']['rsn_preauth']);
		$pconfig['ext_wpa_sw'] = $wancfg['wireless']['wpa']['ext_wpa_sw'];
		$pconfig['wpa_enable'] = isset($wancfg['wireless']['wpa']['enable']);
	}
	$pconfig['wep_enable'] = isset($wancfg['wireless']['wep']['enable']);
	$pconfig['mac_acl'] = $wancfg['wireless']['mac_acl'];
	if (is_array($wancfg['wireless']['wep']) && is_array($wancfg['wireless']['wep']['key'])) {
		$i = 1;
		foreach ($wancfg['wireless']['wep']['key'] as $wepkey) {
			$pconfig['key' . $i] = $wepkey['value'];
			if (isset($wepkey['txkey'])) {
				$pconfig['txkey'] = $i;
			}
			$i++;
		}
		if (!isset($wepkey['txkey']))
			$pconfig['txkey'] = 1;
	}
}

if ($_POST['apply']) {
	unset($input_errors);
	if (!is_subsystem_dirty('interfaces')) {
		$input_errors[] = gettext("You have already applied your settings!");
	} else {
		unlink_if_exists("{$g['tmp_path']}/config.cache");
		clear_subsystem_dirty('interfaces');

		if (file_exists("{$g['tmp_path']}/.interfaces.apply")) {
			$toapplylist = unserialize(file_get_contents("{$g['tmp_path']}/.interfaces.apply"));
			foreach ($toapplylist as $ifapply => $ifcfgo) {
				if (isset($config['interfaces'][$ifapply]['enable'])) {
					interface_bring_down($ifapply, false, $ifcfgo);
					interface_configure($ifapply, true);
				} else {
					interface_bring_down($ifapply, true, $ifcfgo);
					if (isset($config['dhcpd'][$ifapply]['enable']) ||
						isset($config['dhcpdv6'][$ifapply]['enable'])) {
						services_dhcpd_configure();
					}
				}
			}
		}
		/* restart snmp so that it binds to correct address */
		services_snmpd_configure();

		/* sync filter configuration */
		setup_gateways_monitor();

		clear_subsystem_dirty('interfaces');

		filter_configure();

		enable_rrd_graphing();

		if (is_subsystem_dirty('staticroutes') && (system_routing_configure() == 0)) {
			clear_subsystem_dirty('staticroutes');
		}
	}
	@unlink("{$g['tmp_path']}/.interfaces.apply");
	header("Location: interfaces.php?if={$if}");
	exit;
} else if ($_POST && $_POST['enable'] != "yes") {
	unset($wancfg['enable']);
	if (isset($wancfg['wireless'])) {
		interface_sync_wireless_clones($wancfg, false);
	}
	write_config("Interface {$_POST['descr']}({$if}) is now disabled.");
	mark_subsystem_dirty('interfaces');
	if (file_exists("{$g['tmp_path']}/.interfaces.apply")) {
		$toapplylist = unserialize(file_get_contents("{$g['tmp_path']}/.interfaces.apply"));
	} else {
		$toapplylist = array();
	}
	$toapplylist[$if]['ifcfg'] = $wancfg;
	$toapplylist[$if]['ppps'] = $a_ppps;
	/* we need to be able remove IP aliases for IPv6 */
	file_put_contents("{$g['tmp_path']}/.interfaces.apply", serialize($toapplylist));
	header("Location: interfaces.php?if={$if}");
	exit;
} else if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	if (is_numeric("0x" . $_POST['track6-prefix-id--hex'])) {
		$pconfig['track6-prefix-id'] = intval($_POST['track6-prefix-id--hex'], 16);
	} else {
		$pconfig['track6-prefix-id'] = 0;
	}
	conf_mount_rw();

	/* filter out spaces from descriptions  */
	$_POST['descr'] = remove_bad_chars($_POST['descr']);

	/* okay first of all, cause we are just hiding the PPPoE HTML
	 * fields releated to PPPoE resets, we are going to unset $_POST
	 * vars, if the reset feature should not be used. Otherwise the
	 * data validation procedure below, may trigger a false error
	 * message.
	 */
	if (empty($_POST['pppoe-reset-type'])) {
		unset($_POST['pppoe_pr_type']);
		unset($_POST['pppoe_resethour']);
		unset($_POST['pppoe_resetminute']);
		unset($_POST['pppoe_resetdate']);
		unset($_POST['pppoe_pr_preset_val']);
	}
	/* description unique? */
	foreach ($ifdescrs as $ifent => $ifdescr) {
		if ($if != $ifent && $ifdescr == $_POST['descr']) {
			$input_errors[] = gettext("An interface with the specified description already exists.");
			break;
		}
	}
	if(is_numeric($_POST['descr'])) {
		$input_errors[] = gettext("The interface description cannot contain only numbers.");
	}
	/* input validation */
	if (isset($config['dhcpd']) && isset($config['dhcpd'][$if]['enable']) && (! preg_match("/^staticv4/", $_POST['type']))) {
		$input_errors[] = gettext("The DHCP Server is active on this interface and it can be used only with a static IP configuration. Please disable the DHCP Server service on this interface first, then change the interface configuration.");
	}
	if (isset($config['dhcpdv6']) && isset($config['dhcpdv6'][$if]['enable']) && (! preg_match("/^staticv6/", $_POST['type6']))) {
		$input_errors[] = gettext("The DHCP6 Server is active on this interface and it can be used only with a static IPv6 configuration. Please disable the DHCPv6 Server service on this interface first, then change the interface configuration.");
	}

	switch(strtolower($_POST['type'])) {
		case "staticv4":
			$reqdfields = explode(" ", "ipaddr subnet gateway");
			$reqdfieldsn = array(gettext("IPv4 address"),gettext("Subnet bit count"),gettext("Gateway"));
			do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
			break;
		case "none":
			if(is_array($config['virtualip']['vip'])) {
				foreach ($config['virtualip']['vip'] as $vip) {
					if (is_ipaddrv4($vip['subnet']) && $vip['interface'] == $if) {
						$input_errors[] = gettext("This interface is referenced by IPv4 VIPs. Please delete those before setting the interface to 'none' configuration.");
					}
				}
			}
		case "dhcp":
			if (in_array($wancfg['ipaddr'], array("ppp", "pppoe", "pptp", "l2tp"))) {
				$input_errors[] = sprintf(gettext("You have to reassign the interface to be able to configure as %s."),$_POST['type']);
			}
			break;
		case "ppp":
			$reqdfields = explode(" ", "port phone");
			$reqdfieldsn = array(gettext("Modem Port"),gettext("Phone Number"));
			do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
			break;
		case "pppoe":
			if ($_POST['pppoe_dialondemand']) {
				$reqdfields = explode(" ", "pppoe_username pppoe_password pppoe_dialondemand pppoe_idletimeout");
				$reqdfieldsn = array(gettext("PPPoE username"),gettext("PPPoE password"),gettext("Dial on demand"),gettext("Idle timeout value"));
			} else {
				$reqdfields = explode(" ", "pppoe_username pppoe_password");
				$reqdfieldsn = array(gettext("PPPoE username"),gettext("PPPoE password"));
			}
			do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
			break;
		case "pptp":
			if ($_POST['pptp_dialondemand']) {
				$reqdfields = explode(" ", "pptp_username pptp_password pptp_local pptp_subnet pptp_remote pptp_dialondemand pptp_idletimeout");
				$reqdfieldsn = array(gettext("PPTP username"),gettext("PPTP password"),gettext("PPTP local IP address"),gettext("PPTP subnet"),gettext("PPTP remote IP address"),gettext("Dial on demand"),gettext("Idle timeout value"));
			} else {
				$reqdfields = explode(" ", "pptp_username pptp_password pptp_local pptp_subnet pptp_remote");
				$reqdfieldsn = array(gettext("PPTP username"),gettext("PPTP password"),gettext("PPTP local IP address"),gettext("PPTP subnet"),gettext("PPTP remote IP address"));
			}
			do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
			break;
		case "l2tp":
			if ($_POST['pptp_dialondemand']) {
				$reqdfields = explode(" ", "pptp_username pptp_password pptp_remote pptp_dialondemand pptp_idletimeout");
				$reqdfieldsn = array(gettext("L2TP username"),gettext("L2TP password"),gettext("L2TP remote IP address"),gettext("Dial on demand"),gettext("Idle timeout value"));
			} else {
				$reqdfields = explode(" ", "pptp_username pptp_password pptp_remote");
				$reqdfieldsn = array(gettext("L2TP username"),gettext("L2TP password"),gettext("L2TP remote IP address"));
			}
			do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
			break;
	}
	switch(strtolower($_POST['type6'])) {
		case "staticv6":
			$reqdfields = explode(" ", "ipaddrv6 subnetv6 gatewayv6");
			$reqdfieldsn = array(gettext("IPv6 address"),gettext("Subnet bit count"),gettext("Gateway"));
			do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
			break;
		case "none":
			if(is_array($config['virtualip']['vip'])) {
				foreach ($config['virtualip']['vip'] as $vip) {
					if (is_ipaddrv6($vip['subnet']) && $vip['interface'] == $if) {
						$input_errors[] = gettext("This interface is referenced by IPv6 VIPs. Please delete those before setting the interface to 'none' configuration.");
					}
				}
			}
		case "dhcp6":
			if (in_array($wancfg['ipaddrv6'], array())) {
				$input_errors[] = sprintf(gettext("You have to reassign the interface to be able to configure as %s."),$_POST['type6']);
			}
			break;
		case "6rd":
			foreach ($ifdescrs as $ifent => $ifdescr) {
				if ($if != $ifent && ($config[interfaces][$ifent]['ipaddrv6'] == $_POST['type6'])) {
					if ($config[interfaces][$ifent]['prefix-6rd'] == $_POST['prefix-6rd']) {
						$input_errors[] = gettext("You can only have one interface configured in 6rd with same prefix.");
						break;
					}
				}
			}
			if (in_array($wancfg['ipaddrv6'], array())) {
				$input_errors[] = sprintf(gettext("You have to reassign the interface to be able to configure as %s."),$_POST['type6']);
			}
			break;
		case "6to4":
			foreach ($ifdescrs as $ifent => $ifdescr) {
				if ($if != $ifent && ($config[interfaces][$ifent]['ipaddrv6'] == $_POST['type6'])) {
					$input_errors[] = sprintf(gettext("You can only have one interface configured as 6to4."),$_POST['type6']);
					break;
				}
			}
			if (in_array($wancfg['ipaddrv6'], array())) {
				$input_errors[] = sprintf(gettext("You have to reassign the interface to be able to configure as %s."),$_POST['type6']);
			}
			break;
		case "track6":
			/* needs to check if $track6-prefix-id is used on another interface */
			if (in_array($wancfg['ipaddrv6'], array())) {
				$input_errors[] = sprintf(gettext("You have to reassign the interface to be able to configure as %s."),$_POST['type6']);
			}
			if ($_POST['track6-prefix-id--hex'] != "" && !is_numeric("0x" . $_POST['track6-prefix-id--hex'])) {
				$input_errors[] = gettext("You must enter a valid hexadecimal number for the IPv6 prefix ID.");
			} else {
				$track6_prefix_id = intval($_POST['track6-prefix-id--hex'], 16);
				if ($track6_prefix_id < 0 || $track6_prefix_id > $_POST['ipv6-num-prefix-ids-' . $_POST['track6-interface']]) {
					$input_errors[] = gettext("You specified an IPv6 prefix ID that is out of range. ({$_POST['track6-interface']}) - ({$_POST['ipv6-num-prefix-ids-' . $_POST['track6-interface']]}) - ({$ipv6_delegation_length})");
				} else {
					foreach ($ifdescrs as $ifent => $ifdescr) {
						if ($if == $ifent) {
							continue;
						}
						if ($config['interfaces'][$ifent]['ipaddrv6'] == 'track6' &&
						    $config['interfaces'][$ifent]['track6-interface'] == $_POST['track6-interface'] &&
							$config['interfaces'][$ifent]['track6-prefix-id'] == $track6_prefix_id) {
							$input_errors[] = sprintf(gettext("This track6 prefix ID is already being used in %s."), $ifdescr);
						}
					}
				}
			}
			break;
	}


	/* normalize MAC addresses - lowercase and convert Windows-ized hyphenated MACs to colon delimited */
	$staticroutes = get_staticroutes(true);
	$_POST['spoofmac'] = strtolower(str_replace("-", ":", $_POST['spoofmac']));
	if ($_POST['ipaddr']) {
		if (!is_ipaddrv4($_POST['ipaddr'])) {
			$input_errors[] = gettext("A valid IPv4 address must be specified.");
		} else {
			if (is_ipaddr_configured($_POST['ipaddr'], $if, true)) {
				$input_errors[] = gettext("This IPv4 address is being used by another interface or VIP.");
			}

			/* Do not accept network or broadcast address, except if subnet is 31 or 32 */
			if ($_POST['subnet'] < 31) {
				if ($_POST['ipaddr'] == gen_subnet($_POST['ipaddr'], $_POST['subnet'])) {
					$input_errors[] = gettext("This IPv4 address is the network address and cannot be used");
				} else if ($_POST['ipaddr'] == gen_subnet_max($_POST['ipaddr'], $_POST['subnet'])) {
					$input_errors[] = gettext("This IPv4 address is the broadcast address and cannot be used");
				}
			}

			foreach ($staticroutes as $route_subnet) {
				list($network, $subnet) = explode("/", $route_subnet);
				if ($_POST['subnet'] == $subnet && $network == gen_subnet($_POST['ipaddr'], $_POST['subnet'])) {
					$input_errors[] = gettext("This IPv4 address conflicts with a Static Route.");
					break;
				}
				unset($network, $subnet);
			}
		}
	}
	if ($_POST['ipaddrv6']) {
		if (!is_ipaddrv6($_POST['ipaddrv6'])) {
			$input_errors[] = gettext("A valid IPv6 address must be specified.");
		} else {
			if (is_ipaddr_configured($_POST['ipaddrv6'], $if, true)) {
				$input_errors[] = gettext("This IPv6 address is being used by another interface or VIP.");
			}

			foreach ($staticroutes as $route_subnet) {
				list($network, $subnet) = explode("/", $route_subnet);
				if ($_POST['subnetv6'] == $subnet && $network == gen_subnetv6($_POST['ipaddrv6'], $_POST['subnetv6'])) {
					$input_errors[] = gettext("This IPv6 address conflicts with a Static Route.");
					break;
				}
				unset($network, $subnet);
			}
		}
	}
	if (($_POST['subnet'] && !is_numeric($_POST['subnet']))) {
		$input_errors[] = gettext("A valid subnet bit count must be specified.");
	}
	if (($_POST['subnetv6'] && !is_numeric($_POST['subnetv6']))) {
		$input_errors[] = gettext("A valid subnet bit count must be specified.");
	}
	if (($_POST['alias-address'] && !is_ipaddrv4($_POST['alias-address']))) {
		$input_errors[] = gettext("A valid alias IP address must be specified.");
	}
	if (($_POST['alias-subnet'] && !is_numeric($_POST['alias-subnet']))) {
		$input_errors[] = gettext("A valid alias subnet bit count must be specified.");
	}
	if ($_POST['dhcprejectfrom'] && !is_ipaddrv4($_POST['dhcprejectfrom'])) {
		$input_errors[] = gettext("A valid alias IP address must be specified to reject DHCP Leases from.");
	}
	if (($_POST['gateway'] != "none") || ($_POST['gatewayv6'] != "none")) {
		$match = false;
		foreach($a_gateways as $gateway) {
			if(in_array($_POST['gateway'], $gateway)) {
				$match = true;
			}
		}
		foreach($a_gateways as $gateway) {
			if(in_array($_POST['gatewayv6'], $gateway)) {
				$match = true;
			}
		}
		if(!$match) {
			$input_errors[] = gettext("A valid gateway must be specified.");
		}
	}
	if (($_POST['provider'] && !is_domain($_POST['provider']))) {
		$input_errors[] = gettext("The service name contains invalid characters.");
	}
	if (($_POST['pppoe_idletimeout'] != "") && !is_numericint($_POST['pppoe_idletimeout'])) {
		$input_errors[] = gettext("The idle timeout value must be an integer.");
	}
	if ($_POST['pppoe_resethour'] <> "" && !is_numericint($_POST['pppoe_resethour']) &&
		$_POST['pppoe_resethour'] >= 0 && $_POST['pppoe_resethour'] <=23) {
			$input_errors[] = gettext("A valid PPPoE reset hour must be specified (0-23).");
		}
	if ($_POST['pppoe_resetminute'] <> "" && !is_numericint($_POST['pppoe_resetminute']) &&
		$_POST['pppoe_resetminute'] >= 0 && $_POST['pppoe_resetminute'] <=59) {
			$input_errors[] = gettext("A valid PPPoE reset minute must be specified (0-59).");
		}
	if ($_POST['pppoe_resetdate'] <> "" && !is_numeric(str_replace("/", "", $_POST['pppoe_resetdate']))) {
		$input_errors[] = gettext("A valid PPPoE reset date must be specified (mm/dd/yyyy).");
	}
	if (($_POST['pptp_local'] && !is_ipaddrv4($_POST['pptp_local']))) {
		$input_errors[] = gettext("A valid PPTP local IP address must be specified.");
	}
	if (($_POST['pptp_subnet'] && !is_numeric($_POST['pptp_subnet']))) {
		$input_errors[] = gettext("A valid PPTP subnet bit count must be specified.");
	}
	if (($_POST['pptp_remote'] && !is_ipaddrv4($_POST['pptp_remote']) && !is_hostname($_POST['gateway'][$iface]))) {
		$input_errors[] = gettext("A valid PPTP remote IP address must be specified.");
	}
	if (($_POST['pptp_idletimeout'] != "") && !is_numericint($_POST['pptp_idletimeout'])) {
		$input_errors[] = gettext("The idle timeout value must be an integer.");
	}
	if (($_POST['spoofmac'] && !is_macaddr($_POST['spoofmac']))) {
		$input_errors[] = gettext("A valid MAC address must be specified.");
	}
	if ($_POST['mtu']) {
		if (!is_numericint($_POST['mtu'])) {
			$input_errors[] = "MTU must be an integer.";
		}
		if (substr($wancfg['if'], 0, 3) == 'gif') {
			$min_mtu = 1280;
			$max_mtu = 8192;
		} else {
			$min_mtu = 576;
			$max_mtu = 9000;
		}

		if ($_POST['mtu'] < $min_mtu || $_POST['mtu'] > $max_mtu) {
			$input_errors[] = sprintf(gettext("The MTU must be between %d and %d bytes."), $min_mtu, $max_mtu);
		}

		unset($min_mtu, $max_mtu);

		if (stristr($wancfg['if'], "_vlan")) {
			$realhwif_array = get_parent_interface($wancfg['if']);
			// Need code to handle MLPPP if we ever use $realhwif for MLPPP handling
			$parent_realhwif = $realhwif_array[0];
			$parent_if = convert_real_interface_to_friendly_interface_name($parent_realhwif);
			if (!empty($parent_if) && !empty($config['interfaces'][$parent_if]['mtu'])) {
				if ($_POST['mtu'] > intval($config['interfaces'][$parent_if]['mtu'])) {
					$input_errors[] = gettext("The MTU of a VLAN cannot be greater than that of its parent interface.");
				}
			}
		} else {
			foreach ($config['interfaces'] as $idx => $ifdata) {
				if (($idx == $if) || !preg_match('/_vlan[0-9]/', $ifdata['if'])) {
					continue;
				}

				$realhwif_array = get_parent_interface($ifdata['if']);
				// Need code to handle MLPPP if we ever use $realhwif for MLPPP handling
				$parent_realhwif = $realhwif_array[0];

				if ($parent_realhwif != $wancfg['if']) {
					continue;
				}

				if (isset($ifdata['mtu']) && $ifdata['mtu'] > $_POST['mtu']) {
					$input_errors[] = sprintf(gettext("Interface %s (VLAN) has MTU set to a larger value"), $ifdata['descr']);
				}
			}
		}
	}
	if ($_POST['mss'] <> '') {
		if (!is_numericint($_POST['mss']) || ($_POST['mss'] < 576 || $_POST['mss'] > 65535)) {
			$input_errors[] = gettext("The MSS must be an integer between 576 and 65535 bytes.");
		}
	}
	/* Wireless interface? */
	if (isset($wancfg['wireless'])) {
		$reqdfields = array("mode");
		$reqdfieldsn = array(gettext("Mode"));
		if ($_POST['mode'] == 'hostap') {
			$reqdfields[] = "ssid";
			$reqdfieldsn[] = gettext("SSID");
		}
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
		check_wireless_mode();
		/* loop through keys and enforce size */
		for ($i = 1; $i <= 4; $i++) {
			if ($_POST['key' . $i]) {
				/* 64 bit */
				if (strlen($_POST['key' . $i]) == 5) {
					continue;
				}
				if (strlen($_POST['key' . $i]) == 10) {
					/* hex key */
					if (stristr($_POST['key' . $i], "0x") == false) {
						$_POST['key' . $i] = "0x" . $_POST['key' . $i];
					}
					continue;
				}
				if (strlen($_POST['key' . $i]) == 12) {
					/* hex key */
					if(stristr($_POST['key' . $i], "0x") == false) {
						$_POST['key' . $i] = "0x" . $_POST['key' . $i];
					}
					continue;
				}
				/* 128 bit */
				if (strlen($_POST['key' . $i]) == 13) {
					continue;
				}
				if (strlen($_POST['key' . $i]) == 26) {
					/* hex key */
					if (stristr($_POST['key' . $i], "0x") == false) {
						$_POST['key' . $i] = "0x" . $_POST['key' . $i];
					}
					continue;
				}
				if(strlen($_POST['key' . $i]) == 28) {
					continue;
				}
				$input_errors[] =  gettext("Invalid WEP key size.   Sizes should be 40 (64) bit keys or 104 (128) bit.");
				break;
			}
		}

		if ($_POST['passphrase']) {
			$passlen = strlen($_POST['passphrase']);
			if ($passlen < 8 || $passlen > 63) {
				$input_errors[] = gettext("The length of the passphrase should be between 8 and 63 characters.");
			}
		}
	}
	if (!$input_errors) {
		if ($wancfg['ipaddr'] != $_POST['type']) {
			if (in_array($wancfg['ipaddr'], array("ppp", "pppoe", "pptp", "l2tp"))) {
				$wancfg['if'] = $a_ppps[$pppid]['ports'];
				unset($a_ppps[$pppid]);
			} else if ($wancfg['ipaddr'] == "dhcp") {
				kill_dhclient_process($wancfg['if']);
			}
			if ($wancfg['ipaddrv6'] == "dhcp6") {
				$pid = find_dhcp6c_process($wancfg['if']);
				if($pid) {
					posix_kill($pid, SIGTERM);
				}
			}
		}
		$ppp = array();
		if ($wancfg['ipaddr'] != "ppp") {
			unset($wancfg['ipaddr']);
		}
		if ($wancfg['ipaddrv6'] != "ppp") {
			unset($wancfg['ipaddrv6']);
		}
		unset($wancfg['subnet']);
		unset($wancfg['gateway']);
		unset($wancfg['subnetv6']);
		unset($wancfg['gatewayv6']);
		unset($wancfg['dhcphostname']);
		unset($wancfg['dhcprejectfrom']);
		unset($wancfg['dhcp6-duid']);
		unset($wancfg['dhcp6-ia-pd-len']);
		unset($wancfg['dhcp6-ia-pd-send-hint']);
		unset($wancfg['dhcp6prefixonly']);
		unset($wancfg['dhcp6usev4iface']);
		unset($wancfg['track6-interface']);
		unset($wancfg['track6-prefix-id']);
		unset($wancfg['prefix-6rd']);
		unset($wancfg['prefix-6rd-v4plen']);
		unset($wancfg['gateway-6rd']);

		unset($wancfg['adv_dhcp_pt_timeout']);
		unset($wancfg['adv_dhcp_pt_retry']);
		unset($wancfg['adv_dhcp_pt_select_timeout']);
		unset($wancfg['adv_dhcp_pt_reboot']);
		unset($wancfg['adv_dhcp_pt_backoff_cutoff']);
		unset($wancfg['adv_dhcp_pt_initial_interval']);

		unset($wancfg['adv_dhcp_pt_values']);

		unset($wancfg['adv_dhcp_send_options']);
		unset($wancfg['adv_dhcp_request_options']);
		unset($wancfg['adv_dhcp_required_options']);
		unset($wancfg['adv_dhcp_option_modifiers']);

		unset($wancfg['adv_dhcp_config_advanced']);
		unset($wancfg['adv_dhcp_config_file_override']);
		unset($wancfg['adv_dhcp_config_file_override_path']);

		unset($wancfg['adv_dhcp6_interface_statement_send_options']);
		unset($wancfg['adv_dhcp6_interface_statement_request_options']);
		unset($wancfg['adv_dhcp6_interface_statement_information_only_enable']);
		unset($wancfg['adv_dhcp6_interface_statement_script']);

		unset($wancfg['adv_dhcp6_id_assoc_statement_address_enable']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_address']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_address_id']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_address_pltime']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_address_vltime']);

		unset($wancfg['adv_dhcp6_id_assoc_statement_prefix_enable']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_prefix']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_prefix_id']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_prefix_pltime']);
		unset($wancfg['adv_dhcp6_id_assoc_statement_prefix_vltime']);

		unset($wancfg['adv_dhcp6_prefix_interface_statement_sla_id']);
		unset($wancfg['adv_dhcp6_prefix_interface_statement_sla_len']);

		unset($wancfg['adv_dhcp6_authentication_statement_authname']);
		unset($wancfg['adv_dhcp6_authentication_statement_protocol']);
		unset($wancfg['adv_dhcp6_authentication_statement_algorithm']);
		unset($wancfg['adv_dhcp6_authentication_statement_rdm']);

		unset($wancfg['adv_dhcp6_key_info_statement_keyname']);
		unset($wancfg['adv_dhcp6_key_info_statement_realm']);
		unset($wancfg['adv_dhcp6_key_info_statement_keyid']);
		unset($wancfg['adv_dhcp6_key_info_statement_secret']);
		unset($wancfg['adv_dhcp6_key_info_statement_expire']);

		unset($wancfg['adv_dhcp6_config_advanced']);
		unset($wancfg['adv_dhcp6_config_file_override']);
		unset($wancfg['adv_dhcp6_config_file_override_path']);

		unset($wancfg['pppoe_password']);
		unset($wancfg['pptp_username']);
		unset($wancfg['pptp_password']);
		unset($wancfg['provider']);
		unset($wancfg['ondemand']);
		unset($wancfg['timeout']);
		if (empty($wancfg['pppoe']['pppoe-reset-type'])) {
			unset($wancfg['pppoe']['pppoe-reset-type']);
		}
		unset($wancfg['local']);

		unset($wancfg['remote']);
		if (is_array($a_ppps[$pppid]) && in_array($wancfg['ipaddr'], array("ppp", "pppoe", "pptp", "l2tp"))) {
			if ($wancfg['ipaddr'] != 'ppp') {
				unset($a_ppps[$pppid]['apn']);
				unset($a_ppps[$pppid]['phone']);
				unset($a_ppps[$pppid]['provider']);
				unset($a_ppps[$pppid]['ondemand']);
			}
			if (in_array($wancfg['ipaddr'], array("pppoe", "pptp", "l2tp"))) {
				unset($a_ppps[$pppid]['localip']);
				unset($a_ppps[$pppid]['subnet']);
				unset($a_ppps[$pppid]['gateway']);
			}
			if ($wancfg['ipaddr'] != 'pppoe') {
				unset($a_ppps[$pppid]['pppoe-reset-type']);
			}
			if ($wancfg['type'] != $_POST['type']) {
				unset($a_ppps[$pppid]['idletimeout']);
			}
		}

		$wancfg['descr'] = remove_bad_chars($_POST['descr']);
		$wancfg['enable'] =  $_POST['enable']  == "yes" ? true : false;

		/* let return_gateways_array() do the magic on dynamic interfaces for us */
		switch($_POST['type']) {
			case "staticv4":
				$wancfg['ipaddr'] = $_POST['ipaddr'];
				$wancfg['subnet'] = $_POST['subnet'];
				if ($_POST['gateway'] != "none") {
					$wancfg['gateway'] = $_POST['gateway'];
				}
				break;
			case "dhcp":
				$wancfg['ipaddr'] = "dhcp";
				$wancfg['dhcphostname'] = $_POST['dhcphostname'];
				$wancfg['alias-address'] = $_POST['alias-address'];
				$wancfg['alias-subnet'] = $_POST['alias-subnet'];
				$wancfg['dhcprejectfrom'] = $_POST['dhcprejectfrom'];

				$wancfg['adv_dhcp_pt_timeout'] = $_POST['adv_dhcp_pt_timeout'];
				$wancfg['adv_dhcp_pt_retry'] = $_POST['adv_dhcp_pt_retry'];
				$wancfg['adv_dhcp_pt_select_timeout'] = $_POST['adv_dhcp_pt_select_timeout'];
				$wancfg['adv_dhcp_pt_reboot'] = $_POST['adv_dhcp_pt_reboot'];
				$wancfg['adv_dhcp_pt_backoff_cutoff'] = $_POST['adv_dhcp_pt_backoff_cutoff'];
				$wancfg['adv_dhcp_pt_initial_interval'] = $_POST['adv_dhcp_pt_initial_interval'];

				$wancfg['adv_dhcp_pt_values'] = $_POST['adv_dhcp_pt_values'];

				$wancfg['adv_dhcp_send_options'] = $_POST['adv_dhcp_send_options'];
				$wancfg['adv_dhcp_request_options'] = $_POST['adv_dhcp_request_options'];
				$wancfg['adv_dhcp_required_options'] = $_POST['adv_dhcp_required_options'];
				$wancfg['adv_dhcp_option_modifiers'] = $_POST['adv_dhcp_option_modifiers'];

				$wancfg['adv_dhcp_config_advanced'] = $_POST['adv_dhcp_config_advanced'];
				$wancfg['adv_dhcp_config_file_override'] = $_POST['adv_dhcp_config_file_override'];
				$wancfg['adv_dhcp_config_file_override_path'] = $_POST['adv_dhcp_config_file_override_path'];

				$wancfg['dhcp_plus'] = $_POST['dhcp_plus'] == "yes" ? true : false;
				if($gateway_item) {
					$a_gateways[] = $gateway_item;
				}
				break;
			case "ppp":
				$a_ppps[$pppid]['ptpid'] = $_POST['ptpid'];
				$a_ppps[$pppid]['type'] = $_POST['type'];
				$a_ppps[$pppid]['if'] = $_POST['type'].$_POST['ptpid'];
				$a_ppps[$pppid]['ports'] = $_POST['port'];
				$a_ppps[$pppid]['username'] = $_POST['username'];
				$a_ppps[$pppid]['password'] = base64_encode($_POST['password']);
				$a_ppps[$pppid]['phone'] = $_POST['phone'];
				$a_ppps[$pppid]['apn'] = $_POST['apn'];
				$wancfg['if'] = $_POST['type'] . $_POST['ptpid'];
				$wancfg['ipaddr'] = $_POST['type'];
				break;

			case "pppoe":
				$a_ppps[$pppid]['ptpid'] = $_POST['ptpid'];
				$a_ppps[$pppid]['type'] = $_POST['type'];
				$a_ppps[$pppid]['if'] = $_POST['type'].$_POST['ptpid'];
				if (isset($_POST['ppp_port'])) {
					$a_ppps[$pppid]['ports'] = $_POST['ppp_port'];
				} else {
					$a_ppps[$pppid]['ports'] = $wancfg['if'];
				}
				$a_ppps[$pppid]['username'] = $_POST['pppoe_username'];
				$a_ppps[$pppid]['password'] = base64_encode($_POST['pppoe_password']);
				if (!empty($_POST['provider'])) {
					$a_ppps[$pppid]['provider'] = $_POST['provider'];
				} else {
					$a_ppps[$pppid]['provider'] = true;
				}
				$a_ppps[$pppid]['ondemand'] = $_POST['pppoe_dialondemand'] ? true : false;
				if (!empty($_POST['pppoe_idletimeout'])) {
					$a_ppps[$pppid]['idletimeout'] = $_POST['pppoe_idletimeout'];
				} else {
					unset($a_ppps[$pppid]['idletimeout']);
				}

				if (!empty($_POST['pppoe-reset-type'])) {
					$a_ppps[$pppid]['pppoe-reset-type'] = $_POST['pppoe-reset-type'];
				} else {
					unset($a_ppps[$pppid]['pppoe-reset-type']);
				}
				$wancfg['if'] = $_POST['type'].$_POST['ptpid'];
				$wancfg['ipaddr'] = $_POST['type'];
				if($gateway_item) {
					$a_gateways[] = $gateway_item;
				}

				break;
			case "pptp":
			case "l2tp":
				$a_ppps[$pppid]['ptpid'] = $_POST['ptpid'];
				$a_ppps[$pppid]['type'] = $_POST['type'];
				$a_ppps[$pppid]['if'] = $_POST['type'].$_POST['ptpid'];
				if (isset($_POST['ppp_port'])) {
					$a_ppps[$pppid]['ports'] = $_POST['ppp_port'];
				} else {
					$a_ppps[$pppid]['ports'] = $wancfg['if'];
				}
				$a_ppps[$pppid]['username'] = $_POST['pptp_username'];
				$a_ppps[$pppid]['password'] = base64_encode($_POST['pptp_password']);
				$a_ppps[$pppid]['localip'] = $_POST['pptp_local'];
				$a_ppps[$pppid]['subnet'] = $_POST['pptp_subnet'];
				$a_ppps[$pppid]['gateway'] = $_POST['pptp_remote'];
				$a_ppps[$pppid]['ondemand'] = $_POST['pptp_dialondemand'] ? true : false;
				if (!empty($_POST['pptp_idletimeout'])) {
					$a_ppps[$pppid]['idletimeout'] = $_POST['pptp_idletimeout'];
				} else {
					unset($a_ppps[$pppid]['idletimeout']);
				}
				$wancfg['if'] = $_POST['type'].$_POST['ptpid'];
				$wancfg['ipaddr'] = $_POST['type'];
				if($gateway_item) {
					$a_gateways[] = $gateway_item;
				}
				break;
			case "none":
				break;
		}
		switch($_POST['type6']) {
			case "staticv6":
				$wancfg['ipaddrv6'] = $_POST['ipaddrv6'];
				$wancfg['subnetv6'] = $_POST['subnetv6'];
				if ($_POST['gatewayv6'] != "none") {
					$wancfg['gatewayv6'] = $_POST['gatewayv6'];
				}
				break;
			case "slaac":
				$wancfg['ipaddrv6'] = "slaac";
				break;
			case "dhcp6":
				$wancfg['ipaddrv6'] = "dhcp6";
				$wancfg['dhcp6-duid'] = $_POST['dhcp6-duid'];
				$wancfg['dhcp6-ia-pd-len'] = $_POST['dhcp6-ia-pd-len'];
				if($_POST['dhcp6-ia-pd-send-hint'] == "yes") {
					$wancfg['dhcp6-ia-pd-send-hint'] = true;
				}
				if($_POST['dhcp6prefixonly'] == "yes") {
					$wancfg['dhcp6prefixonly'] = true;
				}
				if($_POST['dhcp6usev4iface'] == "yes") {
					$wancfg['dhcp6usev4iface'] = true;
				}

				if (!empty($_POST['adv_dhcp6_interface_statement_send_options'])) {
					$wancfg['adv_dhcp6_interface_statement_send_options'] = $_POST['adv_dhcp6_interface_statement_send_options'];
				}
				if (!empty($_POST['adv_dhcp6_interface_statement_request_options'])) {
					$wancfg['adv_dhcp6_interface_statement_request_options'] = $_POST['adv_dhcp6_interface_statement_request_options'];
				}
				if (isset($_POST['adv_dhcp6_interface_statement_information_only_enable'])) {
					$wancfg['adv_dhcp6_interface_statement_information_only_enable'] = $_POST['adv_dhcp6_interface_statement_information_only_enable'];
				}
				if (!empty($_POST['adv_dhcp6_interface_statement_script'])) {
					$wancfg['adv_dhcp6_interface_statement_script'] = $_POST['adv_dhcp6_interface_statement_script'];
				}
				if (isset($_POST['adv_dhcp6_id_assoc_statement_address_enable'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_address_enable'] = $_POST['adv_dhcp6_id_assoc_statement_address_enable'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_address'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_address'] = $_POST['adv_dhcp6_id_assoc_statement_address'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_address_id'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_address_id'] = $_POST['adv_dhcp6_id_assoc_statement_address_id'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_address_pltime'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_address_pltime'] = $_POST['adv_dhcp6_id_assoc_statement_address_pltime'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_address_vltime'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_address_vltime'] = $_POST['adv_dhcp6_id_assoc_statement_address_vltime'];
				}
				if (isset($_POST['adv_dhcp6_id_assoc_statement_prefix_enable'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_prefix_enable'] = $_POST['adv_dhcp6_id_assoc_statement_prefix_enable'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_prefix'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_prefix'] = $_POST['adv_dhcp6_id_assoc_statement_prefix'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_prefix_id'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_prefix_id'] = $_POST['adv_dhcp6_id_assoc_statement_prefix_id'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_prefix_pltime'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_prefix_pltime'] = $_POST['adv_dhcp6_id_assoc_statement_prefix_pltime'];
				}
				if (!empty($_POST['adv_dhcp6_id_assoc_statement_prefix_vltime'])) {
					$wancfg['adv_dhcp6_id_assoc_statement_prefix_vltime'] = $_POST['adv_dhcp6_id_assoc_statement_prefix_vltime'];
				}
				if (!empty($_POST['adv_dhcp6_prefix_interface_statement_sla_id'])) {
					$wancfg['adv_dhcp6_prefix_interface_statement_sla_id'] = $_POST['adv_dhcp6_prefix_interface_statement_sla_id'];
				}
				if (!empty($_POST['adv_dhcp6_prefix_interface_statement_sla_len'])) {
					$wancfg['adv_dhcp6_prefix_interface_statement_sla_len'] = $_POST['adv_dhcp6_prefix_interface_statement_sla_len'];
				}
				if (!empty($_POST['adv_dhcp6_authentication_statement_authname'])) {
					$wancfg['adv_dhcp6_authentication_statement_authname'] = $_POST['adv_dhcp6_authentication_statement_authname'];
				}
				if (!empty($_POST['adv_dhcp6_authentication_statement_protocol'])) {
					$wancfg['adv_dhcp6_authentication_statement_protocol'] = $_POST['adv_dhcp6_authentication_statement_protocol'];
				}
				if (!empty($_POST['adv_dhcp6_authentication_statement_algorithm'])) {
					$wancfg['adv_dhcp6_authentication_statement_algorithm'] = $_POST['adv_dhcp6_authentication_statement_algorithm'];
				}
				if (!empty($_POST['adv_dhcp6_authentication_statement_rdm'])) {
					$wancfg['adv_dhcp6_authentication_statement_rdm'] = $_POST['adv_dhcp6_authentication_statement_rdm'];
				}
				if (!empty($_POST['adv_dhcp6_key_info_statement_keyname'])) {
					$wancfg['adv_dhcp6_key_info_statement_keyname'] = $_POST['adv_dhcp6_key_info_statement_keyname'];
				}
				if (!empty($_POST['adv_dhcp6_key_info_statement_realm'])) {
					$wancfg['adv_dhcp6_key_info_statement_realm'] = $_POST['adv_dhcp6_key_info_statement_realm'];
				}
				if (!empty($_POST['adv_dhcp6_key_info_statement_keyid'])) {
					$wancfg['adv_dhcp6_key_info_statement_keyid'] = $_POST['adv_dhcp6_key_info_statement_keyid'];
				}
				if (!empty($_POST['adv_dhcp6_key_info_statement_secret'])) {
					$wancfg['adv_dhcp6_key_info_statement_secret'] = $_POST['adv_dhcp6_key_info_statement_secret'];
				}
				if (!empty($_POST['adv_dhcp6_key_info_statement_expire'])) {
					$wancfg['adv_dhcp6_key_info_statement_expire'] = $_POST['adv_dhcp6_key_info_statement_expire'];
				}
				if (!empty($_POST['adv_dhcp6_config_advanced'])) {
					$wancfg['adv_dhcp6_config_advanced'] = $_POST['adv_dhcp6_config_advanced'];
				}
				if (!empty($_POST['adv_dhcp6_config_file_override'])) {
					$wancfg['adv_dhcp6_config_file_override'] = $_POST['adv_dhcp6_config_file_override'];
				}
				if (!empty($_POST['adv_dhcp6_config_file_override_path'])) {
					$wancfg['adv_dhcp6_config_file_override_path'] = $_POST['adv_dhcp6_config_file_override_path'];
				}

				if($gateway_item) {
					$a_gateways[] = $gateway_item;
				}
				break;
			case "6rd":
				$wancfg['ipaddrv6'] = "6rd";
				$wancfg['prefix-6rd'] = $_POST['prefix-6rd'];
				$wancfg['prefix-6rd-v4plen'] = $_POST['prefix-6rd-v4plen'];
				$wancfg['gateway-6rd'] = $_POST['gateway-6rd'];
				if($gateway_item) {
					$a_gateways[] = $gateway_item;
				}
				break;
			case "6to4":
				$wancfg['ipaddrv6'] = "6to4";
				break;
			case "track6":
				$wancfg['ipaddrv6'] = "track6";
				$wancfg['track6-interface'] = $_POST['track6-interface'];
				if ($_POST['track6-prefix-id--hex'] === "") {
					$wancfg['track6-prefix-id'] = 0;
				} else if (is_numeric("0x" . $_POST['track6-prefix-id--hex'])) {
					$wancfg['track6-prefix-id'] = intval($_POST['track6-prefix-id--hex'], 16);
				} else {
					$wancfg['track6-prefix-id'] = 0;
				}
				break;
			case "none":
				break;
		}
		handle_pppoe_reset($_POST);

		if($_POST['blockpriv'] == "yes") {
			$wancfg['blockpriv'] = true;
		} else {
			unset($wancfg['blockpriv']);
		}
		if($_POST['blockbogons'] == "yes") {
			$wancfg['blockbogons'] = true;
		} else {
			unset($wancfg['blockbogons']);
		}
		$wancfg['spoofmac'] = $_POST['spoofmac'];
		if (empty($_POST['mtu'])) {
			unset($wancfg['mtu']);
		} else {
			$wancfg['mtu'] = $_POST['mtu'];
		}
		if (empty($_POST['mss'])) {
			unset($wancfg['mss']);
		} else {
			$wancfg['mss'] = $_POST['mss'];
		}
		if (empty($_POST['mediaopt'])) {
			unset($wancfg['media']);
			unset($wancfg['mediaopt']);
		} else {
			$mediaopts = explode(' ', $_POST['mediaopt']);
			if ($mediaopts[0] != '') {
				$wancfg['media'] = $mediaopts[0];
			}
			if ($mediaopts[1] != '') {
				$wancfg['mediaopt'] = $mediaopts[1];
			} else {
				unset($wancfg['mediaopt']);
			}
		}
		if (isset($wancfg['wireless'])) {
			handle_wireless_post();
		}

		conf_mount_ro();
		write_config();

		if (file_exists("{$g['tmp_path']}/.interfaces.apply")) {
			$toapplylist = unserialize(file_get_contents("{$g['tmp_path']}/.interfaces.apply"));
		} else {
			$toapplylist = array();
		}
		$toapplylist[$if]['ifcfg'] = $old_wancfg;
		$toapplylist[$if]['ppps'] = $old_ppps;
		file_put_contents("{$g['tmp_path']}/.interfaces.apply", serialize($toapplylist));

		mark_subsystem_dirty('interfaces');

		/* regenerate cron settings/crontab file */
		configure_cron();

		header("Location: interfaces.php?if={$if}");
		exit;
	}

} // end if($_POST)

function handle_wireless_post() {
	global $_POST, $config, $g, $wancfg, $if, $wl_countries_attr, $wlanbaseif;
	if (!is_array($wancfg['wireless'])) {
		$wancfg['wireless'] = array();
	}
	$wancfg['wireless']['standard'] = $_POST['standard'];
	$wancfg['wireless']['mode'] = $_POST['mode'];
	$wancfg['wireless']['protmode'] = $_POST['protmode'];
	$wancfg['wireless']['ssid'] = $_POST['ssid'];
	$wancfg['wireless']['channel'] = $_POST['channel'];
	$wancfg['wireless']['authmode'] = $_POST['authmode'];
	$wancfg['wireless']['txpower'] = $_POST['txpower'];
	$wancfg['wireless']['distance'] = $_POST['distance'];
	$wancfg['wireless']['regdomain'] = $_POST['regdomain'];
	$wancfg['wireless']['regcountry'] = $_POST['regcountry'];
	$wancfg['wireless']['reglocation'] = $_POST['reglocation'];
	if (!empty($wancfg['wireless']['regdomain']) && !empty($wancfg['wireless']['regcountry'])) {
		foreach($wl_countries_attr as $wl_country) {
			if ($wancfg['wireless']['regcountry'] == $wl_country['ID']) {
				$wancfg['wireless']['regdomain'] = $wl_country['rd'][0]['REF'];
				break;
			}
		}
	}
	if (!is_array($wancfg['wireless']['wpa'])) {
		$wancfg['wireless']['wpa'] = array();
	}
	$wancfg['wireless']['wpa']['macaddr_acl'] = $_POST['macaddr_acl'];
	$wancfg['wireless']['wpa']['auth_algs'] = $_POST['auth_algs'];
	$wancfg['wireless']['wpa']['wpa_mode'] = $_POST['wpa_mode'];
	$wancfg['wireless']['wpa']['wpa_key_mgmt'] = $_POST['wpa_key_mgmt'];
	$wancfg['wireless']['wpa']['wpa_pairwise'] = $_POST['wpa_pairwise'];
	$wancfg['wireless']['wpa']['wpa_group_rekey'] = $_POST['wpa_group_rekey'];
	$wancfg['wireless']['wpa']['wpa_gmk_rekey'] = $_POST['wpa_gmk_rekey'];
	$wancfg['wireless']['wpa']['passphrase'] = $_POST['passphrase'];
	$wancfg['wireless']['wpa']['ext_wpa_sw'] = $_POST['ext_wpa_sw'];
	$wancfg['wireless']['auth_server_addr'] = $_POST['auth_server_addr'];
	$wancfg['wireless']['auth_server_port'] = $_POST['auth_server_port'];
	$wancfg['wireless']['auth_server_shared_secret'] = $_POST['auth_server_shared_secret'];
	$wancfg['wireless']['auth_server_addr2'] = $_POST['auth_server_addr2'];
	$wancfg['wireless']['auth_server_port2'] = $_POST['auth_server_port2'];
	$wancfg['wireless']['auth_server_shared_secret2'] = $_POST['auth_server_shared_secret2'];

	if ($_POST['persistcommonwireless'] == "yes") {
		if (!is_array($config['wireless'])) {
			$config['wireless'] = array();
		}
		if (!is_array($config['wireless']['interfaces'])) {
			$config['wireless']['interfaces'] = array();
		}
		if (!is_array($config['wireless']['interfaces'][$wlanbaseif])) {
			$config['wireless']['interfaces'][$wlanbaseif] = array();
		}
	} else if (isset($config['wireless']['interfaces'][$wlanbaseif]))
		unset($config['wireless']['interfaces'][$wlanbaseif]);
	if (isset($_POST['diversity']) && is_numeric($_POST['diversity'])) {
		$wancfg['wireless']['diversity'] = $_POST['diversity'];
	} else if (isset($wancfg['wireless']['diversity'])) {
		unset($wancfg['wireless']['diversity']);
	}
	if (isset($_POST['txantenna']) && is_numeric($_POST['txantenna'])) {
		$wancfg['wireless']['txantenna'] = $_POST['txantenna'];
	} else if (isset($wancfg['wireless']['txantenna'])) {
		unset($wancfg['wireless']['txantenna']);
	}
	if (isset($_POST['rxantenna']) && is_numeric($_POST['rxantenna'])) {
		$wancfg['wireless']['rxantenna'] = $_POST['rxantenna'];
	} else if (isset($wancfg['wireless']['rxantenna'])) {
		unset($wancfg['wireless']['rxantenna']);
	}
	if ($_POST['hidessid_enable'] == "yes") {
		$wancfg['wireless']['hidessid']['enable'] = true;
	} else if (isset($wancfg['wireless']['hidessid']['enable'])) {
		unset($wancfg['wireless']['hidessid']['enable']);
	}
	if ($_POST['mac_acl_enable'] == "yes") {
		$wancfg['wireless']['wpa']['mac_acl_enable'] = true;
	} else if (isset($wancfg['wireless']['wpa']['mac_acl_enable'])) {
		unset($wancfg['wireless']['wpa']['mac_acl_enable']);
	}
	if ($_POST['rsn_preauth'] == "yes") {
		$wancfg['wireless']['wpa']['rsn_preauth'] = true;
	} else {
		unset($wancfg['wireless']['wpa']['rsn_preauth']);
	}
	if ($_POST['ieee8021x'] == "yes") {
		$wancfg['wireless']['wpa']['ieee8021x']['enable'] = true;
	} else if (isset($wancfg['wireless']['wpa']['ieee8021x']['enable'])) {
		unset($wancfg['wireless']['wpa']['ieee8021x']['enable']);
	}
	if ($_POST['wpa_strict_rekey'] == "yes") {
		$wancfg['wireless']['wpa']['wpa_strict_rekey'] = true;
	} else if (isset($wancfg['wireless']['wpa']['wpa_strict_rekey'])) {
		unset($wancfg['wireless']['wpa']['wpa_strict_rekey']);
	}
	if ($_POST['debug_mode'] == "yes") {
		$wancfg['wireless']['wpa']['debug_mode'] = true;
	} else if (isset($wancfg['wireless']['wpa']['debug_mode'])) {
		sunset($wancfg['wireless']['wpa']['debug_mode']);
	}
	if ($_POST['wpa_enable'] == "yes") {
		$wancfg['wireless']['wpa']['enable'] = $_POST['wpa_enable'] = true;
	} else if (isset($wancfg['wireless']['wpa']['enable'])) {
		unset($wancfg['wireless']['wpa']['enable']);
	}
	if ($_POST['wep_enable'] == "yes") {
		if (!is_array($wancfg['wireless']['wep'])) {
			$wancfg['wireless']['wep'] = array();
		}
		$wancfg['wireless']['wep']['enable'] = $_POST['wep_enable'] = true;
	} else if (isset($wancfg['wireless']['wep']))
		unset($wancfg['wireless']['wep']);
	if ($_POST['wme_enable'] == "yes") {
		if (!is_array($wancfg['wireless']['wme'])) {
			$wancfg['wireless']['wme'] = array();
		}
		$wancfg['wireless']['wme']['enable'] = $_POST['wme_enable'] = true;
	} else if (isset($wancfg['wireless']['wme']['enable']))
		unset($wancfg['wireless']['wme']['enable']);
	if ($_POST['puremode'] == "11g") {
		if (!is_array($wancfg['wireless']['pureg'])) {
			$wancfg['wireless']['pureg'] = array();
		}
		$wancfg['wireless']['pureg']['enable'] = true;
	} else if ($_POST['puremode'] == "11n") {
		if (!is_array($wancfg['wireless']['puren'])) {
			$wancfg['wireless']['puren'] = array();
		}
		$wancfg['wireless']['puren']['enable'] = true;
	} else {
		if (isset($wancfg['wireless']['pureg'])) {
			unset($wancfg['wireless']['pureg']);
		}
		if (isset($wancfg['wireless']['puren'])) {
			unset($wancfg['wireless']['puren']);
		}
	}
	if ($_POST['apbridge_enable'] == "yes") {
		if (!is_array($wancfg['wireless']['apbridge'])) {
			$wancfg['wireless']['apbridge'] = array();
		}
		$wancfg['wireless']['apbridge']['enable'] = $_POST['apbridge_enable'] = true;
	} else if (isset($wancfg['wireless']['apbridge']['enable']))
		unset($wancfg['wireless']['apbridge']['enable']);
	if ($_POST['standard'] == "11g Turbo" || $_POST['standard'] == "11a Turbo") {
		if (!is_array($wancfg['wireless']['turbo'])) {
			$wancfg['wireless']['turbo'] = array();
		}
		$wancfg['wireless']['turbo']['enable'] = true;
	} else if (isset($wancfg['wireless']['turbo']['enable']))
		unset($wancfg['wireless']['turbo']['enable']);
	$wancfg['wireless']['wep']['key'] = array();
	for ($i = 1; $i <= 4; $i++) {
		if ($_POST['key' . $i]) {
			$newkey = array();
			$newkey['value'] = $_POST['key' . $i];
			if ($_POST['txkey'] == $i) {
				$newkey['txkey'] = true;
			}
			$wancfg['wireless']['wep']['key'][] = $newkey;
		}
	}
	interface_sync_wireless_clones($wancfg, true);
}

function check_wireless_mode() {
	global $_POST, $config, $g, $wlan_modes, $wancfg, $if, $wlanif, $wlanbaseif, $old_wireless_mode, $input_errors;

	if ($wancfg['wireless']['mode'] == $_POST['mode']) {
		return;
	}

	if (does_interface_exist(interface_get_wireless_clone($wlanbaseif))) {
		$clone_count = 1;
	} else {
		$clone_count = 0;
	}
	if (isset($config['wireless']['clone']) && is_array($config['wireless']['clone'])) {
		foreach ($config['wireless']['clone'] as $clone) {
			if ($clone['if'] == $wlanbaseif) {
				$clone_count++;
			}
		}
	}
	if ($clone_count > 1) {
		$old_wireless_mode = $wancfg['wireless']['mode'];
		$wancfg['wireless']['mode'] = $_POST['mode'];
		if (!interface_wireless_clone("{$wlanif}_", $wancfg)) {
			$input_errors[] = sprintf(gettext("Unable to change mode to %s.  You may already have the maximum number of wireless clones supported in this mode."), $wlan_modes[$wancfg['wireless']['mode']]);
		} else {
			mwexec("/sbin/ifconfig " . escapeshellarg($wlanif) . "_ destroy");
		}
		$wancfg['wireless']['mode'] = $old_wireless_mode;
	}
}

// Find all possible media options for the interface
$mediaopts_list = array();
$intrealname = $config['interfaces'][$if]['if'];
exec("/sbin/ifconfig -m $intrealname | grep \"media \"", $mediaopts);
foreach ($mediaopts as $mediaopt){
	preg_match("/media (.*)/", $mediaopt, $matches);
	if (preg_match("/(.*) mediaopt (.*)/", $matches[1], $matches1)) {
		// there is media + mediaopt like "media 1000baseT mediaopt full-duplex"
		array_push($mediaopts_list, $matches1[1] . " " . $matches1[2]);
	} else {
		// there is only media like "media 1000baseT"
		array_push($mediaopts_list, $matches[1]);
	}
}

$pgtitle = array(gettext("Interfaces"), $pconfig['descr']);
$shortcut_section = "interfaces";

$closehead = false;
include("head.inc");
?>

<script type="text/javascript">
//<![CDATA[
	//Insure only one of two mutually exclusive options are checked
	function CheckOffOther(clicked, checkOff) {
		if (document.getElementById(clicked).checked) {
			document.getElementById(checkOff).checked=false;
		}
	}
//]]
</script>

<?php

if ($input_errors) {
	print_input_errors($input_errors);
}
if (is_subsystem_dirty('interfaces')) {
	print_info_box_np(sprintf('<p>' . gettext("The %s configuration has been changed."),
		$wancfg['descr']) . '</p><p>' . gettext('You must apply the changes in '.
		'order for them to take effect.').'</p><p>'.gettext('Don\'t forget to '.
		'adjust the DHCP Server range if needed after applying.') . '</p>');
}
if ($savemsg) {
	print_info_box($savemsg);
}

require_once('classes/Modal.class.php');

// isAjax=true
// ipprotocol=inet
// defaultgw = '';
// interface= + jQuery('#if').val()
// if (jQuery('#defaultgw').is(':checked'))
	// defaultgw = '&defaultgw=on';
// name= + jQuery('#name').val()
// descr= + jQuery('#gatewaydescr').val()
// gateway= + jQuery('#gatewayip').val()

foreach ([
	'IPv4' =>
		['id' => 'modal_add_gateway', 'ipprotocol' => 'inet'],
	'IPv6' =>
		['id' => 'modal_add_gateway_v6', 'ipprotocol' => 'inet6']
	] as $tile => $info) {
	$modal_add_gateway = new Modal("Add {$tile} Gateway", $info['id']);
	$modal_add_gateway->setAction('system_gateways_edit.php');

	$modal_add_gateway->addInput(new Form_Checkbox(
		'defaultgw',
		'Default Gateway',
		'Default Gateway',
		(strtoupper($if) == 'WAN'),
		'on'
	));

	$modal_add_gateway->addInput(new Form_Input(
		'name',
		'Name',
		'text',
		$wancfg['desc'] . 'GW'
	));

	$modal_add_gateway->addInput(new Form_Input(
		'gatewayip',
		"{$tile} Address",
		'text',
		''
	));

	$modal_add_gateway->addInput(new Form_Input(
		'descr',
		'Description',
		'text',
		''
	));

	foreach(['isAjax' => 'true',
		'ipprotocol' => $info['ipprotocol'],
		'interface' => $if,
	] as $name => $value) {
		$modal_add_gateway->addGlobal(new Form_Input(
			$name,
			$name,
			'hidden',
			$value
		));
	}

	print $modal_add_gateway;
}


require_once('classes/Form.class.php');

$form = new Form;

$section_general_configuration = new Form_Section('General Configuration');

$section_general_configuration->addInput(new Form_Checkbox(
	'enable',
	'Enable',
	'Enable Interface',
	$pconfig['enable'],
	'yes'
))->setAttribute('date-toggle', 'collapse')
	->setAttribute('data-target', '.toggle-enable_interface');

$group_general_configuration = (new Form_Group('Description'))
	->addClass('toggle-enable_interface', 'collapse');

if ($pconfig['enable']) {
	$group_general_configuration->addClass('in');
}

$group_general_configuration->add(new Form_Input(
	'descr',
	'Description',
	'text',
	$pconfig['descr'],
	['placeholder' => 'Description']
))->setWidth(3)
	->setHelp('Enter a description (name) for the interface here.');

$section_general_configuration->add($group_general_configuration);

$group_general_configuration = (new Form_Group('IPv4 Configuration Type'))
	->addClass('toggle-enable_interface', 'collapse');

if ($pconfig['enable']) {
	$group_general_configuration->addClass('in');
}

$group_general_configuration->add(new Form_Select(
	'type',
	'IPv4 Configuration Type',
	$pconfig['type'],
	array(
		'none'     => 'None',
		'staticv4' => 'Static IPv4',
		'dhcp'     => 'DHCP',
		'ppp'      => 'PPP',
		'pppoe'    => 'PPPoE',
		'pptp'     => 'PPTP',
		'l2tp'     => 'L2TP')
))->setWidth(2)
	->setAttribute('disable', $type_disabled)
	->setAttribute('data-toggle', 'collapse');

$section_general_configuration->add($group_general_configuration);

$group_general_configuration = (new Form_Group('IPv6 Configuration Type'))
	->addClass('toggle-enable_interface', 'collapse');

if ($pconfig['enable']) {
	$group_general_configuration->addClass('in');
}

$group_general_configuration->add(new Form_Select(
	'type6',
	'IPv6 Configuration Type',
	$pconfig['type6'],
	array(
		'none'     => 'None',
		'staticv6' => 'Static IPv6',
		'dhcp6'    => 'DHCP6',
		'slaac'    => 'SLAAC',
		'6rd'      => '6rd Tunnel',
		'6to4'     => '6to4 Tunnel',
		'track6'   => 'Track Interface')
))->setWidth(2)
	->setAttribute('disable', $type_disabled)
	->setAttribute('data-toggle', 'collapse');

$section_general_configuration->add($group_general_configuration);

$group_general_configuration_mac_address = (new Form_Group('MAC Address'))
	->addClass('toggle-enable_interface', 'collapse')
	->setHelp( 'Enter a MAC address in the following format: xx:xx:xx:xx:xx:xx '.
	'or leave blank. May be required with some cable connections.');

if ($pconfig['enable']) {
	$group_general_configuration_mac_address->addClass('in');
}

$group_general_configuration_mac_address->add(new Form_Input(
	'spoofmac',
	'MAC Address',
	'text',
	$pconfig['spoofmac'],
	['placeholder' => 'xx:xx:xx:xx:xx:xx']
))->setWidth(3);

$ip = getenv('REMOTE_ADDR');
$mac = str_replace("\n", "", `/usr/sbin/arp -an | grep {$ip} | cut -d" " -f4`);
unset($ip);
if($mac) {
	$group_general_configuration_mac_address->add(new Form_Button(
		'spoof-mac',
		'Insert local MAC address',
		'#'
	))->setAttribute('onclick', "document.forms[0].spoofmac.value='{$mac}';");
};
unset($mac);

$section_general_configuration->add($group_general_configuration_mac_address);

$group_general_configuration = (new Form_Group('MTU'))
	->addClass('toggle-enable_interface', 'collapse')
	->setHelp('If you leave this field blank, the adapter\'s default MTU will '.
		'be used. This is typically 1500 bytes but can vary in some circumstances.');

if ($pconfig['enable']) {
	$group_general_configuration->addClass('in');
}

$group_general_configuration->add(new Form_Input(
	'mtu',
	'MTU',
	'text',
	$pconfig['mtu'],
	['placeholder' => '1500']
))->setWidth(2);

$section_general_configuration->add($group_general_configuration);

$group_general_configuration = (new Form_Group('MSS'))
	->addClass('toggle-enable_interface', 'collapse')
	->setHelp('If you enter a value in this field, then MSS clamping for TCP '.
	'connections to the value entered above minus 40 (TCP/IP header size) will '.
	'be in effect.');

if ($pconfig['enable']) {
	$group_general_configuration->addClass('in');
}

$group_general_configuration ->add(new Form_Input(
	'mss',
	'MSS',
	'text',
	$pconfig['mss']
))->setWidth(2);

$section_general_configuration->add($group_general_configuration);

if (count($mediaopts_list) > 0) {
	$mediaopt_from_config = $config['interfaces'][$if]['media'] . ' ' . $config['interfaces'][$if]['mediaopt'];
	 if ($mediaopt_from_config != 'autoselect ' && $mediaopt_from_config != ' ') {
		 $group_general_configuration = (new Form_Group('Speed and Duplex'))
			 ->addClass('toggle-enable_interface', 'collapse');

		if ($pconfig['enable']) {
			$group_general_configuration->addClass('in');
		}

		 $group_general_configuration->add(new Form_Select(
			'mediaopt',
			'Speed and Duplex',
			$mediaopt_from_config,
			array_merge(
				array(
				'Default (no preference, typically autoselect)',
				'------- Media Supported by this interface -------'),
			$mediaopts_list)
		))->setHelp('Here you can explicitly set speed and duplex mode for this '.
			'interface. WARNING: You MUST leave this set to autoselect (automatically '.
			'negotiate speed) unless the port this interface connects to has its speed '.
			'and duplex forced.');
		 $section_general_configuration->add($group_general_configuration);
	 }
}

$form->add($section_general_configuration);

$section_static_ipv4_configuration = (new Form_Section('Static IPv4 Configuration'))
	->addClass('toggle-staticv4', 'collapse');

$group_static_ipv4_configuration_address = new Form_Group('IPv4 Address');

$group_static_ipv4_configuration_address->add(new Form_Input(
	'ipaddr',
	'IPv4 Address',
	'text',
	$pconfig['ipaddr'],
	['placeholder' => 'x.x.x.x']
))->setWidth(3);

$group_static_ipv4_configuration_address->add(new Form_Select(
	'subnet',
	'IPv4 Subnet Mask',
	$pconfig['subnet'],
	range(32, 1, -1)
))->setWidth(2);

$section_static_ipv4_configuration->add($group_static_ipv4_configuration_address);

$group_static_ipv4_configuration_gateway = new Form_Group('IPv4 Upstream Gateway');

$group_static_ipv4_configuration_gateway->add(new Form_Select(
	'gateway',
	'',
	$pconfig['gateway'],
	count($a_gateways) ? array_filter($a_gateways, function($gateway) {
			return ($gateway['interface']) == $if && is_ipaddrv4($gateway['gateway']);
		}) : array('none' => 'None')
));

$group_static_ipv4_configuration_gateway->add(new Form_Button(
	'',
	'Add New IPv4 Gateway',
	''
))->setAttribute('data-toggle', 'modal')
	->setAttribute('data-target', '#modal_add_gateway');

$section_static_ipv4_configuration->add($group_static_ipv4_configuration_gateway);

$form->add($section_static_ipv4_configuration);

$section_static_ipv6_configuration = (new Form_Section('Static IPv6 Configuration'))
	->addClass('toggle-staticv6', 'collapse');

$group_static_ipv6_configuration_address = new Form_Group('IPv6 Address');

$group_static_ipv6_configuration_address->add(new Form_Input(
	'ipaddr',
	'IPv6 Address',
	'text',
	$pconfig['ipaddrv6'],
	['placeholder' => 'x:x:x:x:x:x:x:x']
))->setWidth(3);

$group_static_ipv6_configuration_address->add(new Form_Select(
	'subnet',
	'IPv6 Subnet Mask',
	$pconfig['subnetv6'],
	range(128, 1, -1)
))->setWidth(2);

$section_static_ipv6_configuration->add($group_static_ipv6_configuration_address);

$group_static_ipv6_configuration_gateway = new Form_Group('IPv6 Upstream Gateway');

$group_static_ipv6_configuration_gateway->add(new Form_Select(
	'gatewayv6',
	'IPv6 Upstream Gateway',
	$pconfig['gatewayv6'],
	count($a_gateways) ? array_filter($a_gateways, function($gateway) {
			return ($gateway['interface']) == $if && is_ipaddrv6($gateway['gateway']);
		}) : array('none' => 'None')
));

$group_static_ipv6_configuration_gateway->add(new Form_Button(
	'',
	'Add New IPv6 Gateway',
	''
))->setAttribute('data-toggle', 'modal')
	->setAttribute('data-target', '#modal_add_gateway_v6');

$section_static_ipv6_configuration->add($group_static_ipv6_configuration_gateway);

$form->add($section_static_ipv6_configuration);

$section_dhcp_client_configuration = (new Form_Section('DHCP Client Configuration'))
	->addClass('toggle-dhcp', 'collapse');

$group_dhcp_client_configuration_config_option = new Form_Group('Advanced Configuration Options');

$group_dhcp_client_configuration_config_option->add(new Form_Checkbox(
	'adv_dhcp_config_advanced',
	'Advanced Configuration Options',
	'Advanced',
	$pconfig['adv_dhcp_config_advanced']
))->setWidth(2)
	->setAttribute('data-toggle', 'collapse')
	->setAttribute('data-target', '.toggle-adv_dhcp_config_advanced')
	->setAttribute('onclick', "CheckOffOther('')");

$group_dhcp_client_configuration_config_option->add(new Form_Checkbox(
	'adv_dhcp_config_file_override',
	'Advanced Configuration Options',
	'Configuration File Override',
	$pconfig['adv_dhcp_config_file_override']
))->setWidth(3)
	->setAttribute('data-toggle', 'collapse')
	->setAttribute('data-target', '.toggle-adv_dhcp_config_file_override');

$section_dhcp_client_configuration->add($group_dhcp_client_configuration_config_option);

$group_dhcp_configuration_file_overide = (new Form_Group('Configuration File Override'))
	->addClass('toggle-adv_dhcp_config_file_override', 'collapse');

if ($pconfig['adv_dhcp_config_file_override']) {
	$group_dhcp_configuration_file_overide->addClass('in');
}

$group_dhcp_configuration_file_overide->add(new Form_Input(
	'adv_dhcp_config_file_override_path',
	'Configuration File Override',
	'text',
	$pconfig['adv_dhcp_config_file_override_path']
))->setHelp('The value in this field is the full absolute path to a DHCP client '.
	'configuration file.  [/[dirname/[.../]]filename[.ext]]<br/>'.
	'Value Substitutions in Config File: {interface}, {hostname}, '.
	'{mac_addr_asciiCD}, {mac_addr_hexCD}<br/>'.
	'Where C is U(pper) or L(ower) Case, and D is \" :-.\" Delimiter (space, '.
	'colon, hyphen, or period) (omitted for none).<br/>'.
	'Some ISPs may require certain options be or not be sent.');

$section_dhcp_client_configuration->add($group_dhcp_configuration_file_overide);

$group_dhcp_client_configuration_host_name = (new Form_Group('Host Name'))
	->addClass('toggle-adv_dhcp_config_file_override', 'collapse')
	->setHelp('The value in this field is sent as the DHCP client identifier '.
	'and hostname when requesting a DHCP lease. Some ISPs may require '.
	'this (for client identification).');

if (!$pconfig['adv_dhcp_config_file_override']) {
	$group_dhcp_client_configuration_host_name->addClass('in');
}

$group_dhcp_client_configuration_host_name->add(new Form_Input(
	'dhcphostname',
	'Host Name',
	'text',
	$pconfig['dhcphostname']
));

$section_dhcp_client_configuration->add($group_dhcp_client_configuration_host_name);

$group_dhcp_client_configuration_alias_ipv4_address = (new Form_Group('Alias IPv4 Address'))
	->addClass('toggle-adv_dhcp_config_file_override', 'collapse')
	->setHelp('The value in this field is used as a fixed alias IPv4 address '.
	'by the DHCP client.');

if (!$pconfig['adv_dhcp_config_file_override']) {
	$group_dhcp_client_configuration_alias_ipv4_address->addClass('in');
}

$group_dhcp_client_configuration_alias_ipv4_address->add(new Form_Input(
	'alias-address',
	'Alias IPv4 Address',
	'text',
	$pconfig['alias-address'],
	['placeholder' => 'x.x.x.x']
))->setWidth(3);

$group_dhcp_client_configuration_alias_ipv4_address->add(new Form_Select(
	'subnet',
	'Alias IPv4 Subnet Mask',
	$pconfig['alias-subnet'],
	range(32, 1, -1)
))->setWidth(2);

$section_dhcp_client_configuration->add($group_dhcp_client_configuration_alias_ipv4_address);

$group_dhcp_client_configuration_leases_release_from = (new Form_Group('Reject Leases From'))
	->addClass('toggle-adv_dhcp_config_file_override', 'collapse')
	->setHelp('If there is a certain upstream DHCP server that should be ignored, '.
	'place the IP address or subnet of the DHCP server to be ignored here. '.
	'This is useful for rejecting leases from cable modems that offer private '.
	'IPs when they lose upstream sync.');

if (!$pconfig['adv_dhcp_config_file_override']) {
	$group_dhcp_client_configuration_leases_release_from->addClass('in');
}

$group_dhcp_client_configuration_leases_release_from->add(new Form_Input(
	'dhcprejectfrom',
	'Reject Leases From',
	'text',
	$pconfig['dhcprejectfrom']
));

$section_dhcp_client_configuration->add($group_dhcp_client_configuration_leases_release_from);

$group_dhcp_client_protocol_timing_presets = (new Form_Group('Protocol Timing Presets'))
	->addClass('toggle-adv_dhcp_config_advanced', 'collapse')
	->setHelp('The values in these fields are DHCP protocol timings used when '.'
	requesting a lease.');

if ($pconfig['adv_dhcp_config_advanced'] && !$pconfig['adv_dhcp_config_file_override']) {
	$group_dhcp_client_protocol_timing_presets->addclass('in');
}

foreach ([
	'Saved Config'    => ['id' => 'customdhcpptsavedcfg', 'value' => 'SavedCfg'],
	'pfSense Default' => ['id' => 'customdhcpptpfsensedefaults', 'value' => 'pfSense'],
	'FreeBSD Default' => ['id' => 'customdhcpptdhcpdefaults', 'value' => 'DHCP'],
	'Clear'           => ['id' => 'customdhcpptclear', 'value' => 'Clear']
	] as $label => $attributes) {
		$group_dhcp_client_protocol_timing_presets->add(new Form_Checkbox(
			'adv_dhcp_pt_values',
			'Presets',
			$label,
			false,
			$attributes['value']
		))->displayAsRadio()
		->setAttribute('onchnage', 'customdhcpptsetvalues(this, iform);')
		->setAttribute('id', $attributes['id']);
	}

$section_dhcp_client_configuration->add($group_dhcp_client_protocol_timing_presets);

$group_dhcp_client_protocol_timing = (new Form_Group('Protocol Timing'))
	->addClass('toggle-adv_dhcp_config_advanced', 'collapse');

if ($pconfig['adv_dhcp_config_advanced'] && !$pconfig['adv_dhcp_config_file_override']) {
	$group_dhcp_client_protocol_timing->addClass('in');
}

foreach ([
	'Timeout'          => 'adv_dhcp_pt_timeout',
	'Retry'            => 'adv_dhcp_pt_retry',
	'Select Timeout'   => 'adv_dhcp_pt_select_timeout',
	'Reboot'           => 'adv_dhcp_pt_reboot',
	'Backoff Cutoff'   => 'adv_dhcp_pt_backoff_cutoff',
	'Initial Interval' => 'adv_dhcp_pt_initial_interval'
	] as $label => $value) {
	$group_dhcp_client_protocol_timing->add(new Form_Input(
		$value,
		$label,
		'text',
		$pconfig[$value]
	))->setHelp($label)
	->setWidth(2)
	->setAttribute('id', $value)
	->setAttribute('onchange', "customdhcpptcheckradiobuton(document.form[0].adv_dhcp_pt_values, '');");
}

$section_dhcp_client_configuration->add($group_dhcp_client_protocol_timing);

$form->add($section_dhcp_client_configuration);

$section_dhcp_lease_requirements_and_requests = (new Form_Section('DHCP Leases Requirements and Requests'))
	->addClass('toggle-adv_dhcp_config_advanced', 'collapse');

if ($pconfig['adv_dhcp_config_advanced'] && !$pconfig['adv_dhcp_config_file_override']) {
	$section_dhcp_lease_requirements_and_requests->addClass('toggle-dhcp', 'in');
}

// TODO: add help for section to these links:
// $section_dhcp_lease_requirements_and_requests->setHelp('<a target="freebsd_dhcp" href="http://www.freebsd.org/cgi/man.cgi?query=dhclient.conf&amp;sektion=5#LEASE_REQUIREMENTS_AND_REQUESTS">Send</a> <a target="freebsd_dhcp" href="http://www.freebsd.org/cgi/man.cgi?query=dhcp-options&amp;sektion=5">Options</a>');

foreach([
	'Send Options' => [
		'name' => 'adv_dhcp_send_options',
		'help' => 'The values in this field are DHCP options to be sent when '.
			'requesting a DHCP lease. [option declaration [, ...]]</br>'.
			'Value Substitutions: {interface}, {hostname}, {mac_addr_asciiCD}, '.
			'{mac_addr_hexCD}.</br>'.
			'Where C is U(pper) or L(ower) Case, and D is " :-." Delimiter (space, '.
			'colon, hyphen, or period) (omitted for none).</br>'.
			'Some ISPs may require certain options be or not be sent.'],
	'Request Options' => [
		'name' => 'adv_dhcp_request_options',
		'help' => 'The values in this field are DHCP option 55 to be sent when '.
			'requesting a DHCP lease.  [option [, ...]]</br>'.
			'Some ISPs may require certain options be or not be requested.'],
	'Require Options' => [
		'name' => 'adv_dhcp_required_options',
		'help' => 'The values in this field are DHCP options required by the client '.
			'when requesting a DHCP lease.  [option [, ...]]'],
	'Option Modifiers' => [
		'name' => 'adv_dhcp_option_modifiers',
		'help' => 'The values in this field are DHCP option modifiers applied to '.
			'obtained DHCP lease.  [modifier option declaration [, ...]] modifiers: '.
			'(default, supersede, prepend, append)']
	] as $label => $info) {

	$section_dhcp_lease_requirements_and_requests->addinput(new form_input(
		$info['name'],
		$label,
		'text',
		$pconfig[$info['name']]
	))->setHelp($info['help']);

}
$form->add($section_dhcp_lease_requirements_and_requests);

$section_dhcp6_client_configuration = (new Form_Section('DHCPv6 Client Configuration'))
	->addClass('toggle-dhcp6');

$group_dhcp6_client_configuration_config_option = new Form_Group('Advanced Configuration Options');

$group_dhcp6_client_configuration_config_option->add(new Form_Checkbox(
	'adv_dhcp6_config_advanced',
	'Advanced Configuration Options',
	'Advanced',
	$pconfig['adv_dhcp6_config_advanced']
))->setWidth(2)
	->setAttribute('data-toggle', 'collapse')
	->setAttribute('data-target', '.toggle-adv_dhcp6_config_advanced');

$group_dhcp6_client_configuration_config_option->add(new Form_Checkbox(
	'adv_dhcp6_config_file_override',
	'Advanced Configuration Options',
	'Configuration File Override',
	$pconfig['adv_dhcp6_config_file_override']
))->setWidth(3)
	->setAttribute('data-toggle', 'collapse')
	->setAttribute('data-target', '.toggle-adv_dhcp6_config_file_override');

$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration_config_option);

$group_dhcp6_configuration_file_overide = (new Form_Group('Configuration File Override'))
	->addClass('toggle-adv_dhcp6_config_file_override', 'collapse');

if ($pconfig['adv_dhcp6_config_file_override']) {
	$group_dhcp6_configuration_file_overide->addClass('in');
}

$group_dhcp6_configuration_file_overide->add(new Form_Input(
	'adv_dhcp6_config_file_override_path',
	'Configuration File Override',
	'text',
	$pconfig['adv_dhcp6_config_file_override_path']
))->setHelp('The value in this field is the full absolute path to a dhcp6 client '.
	'configuration file.  [/[dirname/[.../]]filename[.ext]]<br/>'.
	'Value Substitutions in Config File: {interface}, {hostname}, '.
	'{mac_addr_asciiCD}, {mac_addr_hexCD}<br/>'.
	'Where C is U(pper) or L(ower) Case, and D is \" :-.\" Delimiter (space, '.
	'colon, hyphen, or period) (omitted for none).<br/>'.
	'Some ISPs may require certain options be or not be sent.');

$section_dhcp6_client_configuration->add($group_dhcp6_configuration_file_overide);

$group_dhcp6_client_configuration_prefix_delegation_size = (new Form_Group('DHCPv6 Prefix Delegation size'))
	->addClass('toggle-adv_dhcp6_config_advanced', 'toggle-adv_dhcp6_config_file_override', 'collapse')
	->setHelp('The value in this field is the delegated prefix length provided '.
		'by the DHCPv6 server. Normally specified by the ISP.');

if (!$pconfig['adv_dhcp6_config_advanced'] || !$pconfig['adv_dhcp6_config_file_override']) {
	$group_dhcp6_client_configuration_prefix_delegation_size->addClass('in');
}

$group_dhcp6_client_configuration_prefix_delegation_size->add(new Form_Select(
	'dhcp6-ia-pd-len',
	'DHCPv6 Prefix Delegation size',
	($pconfig['dhcp6-ia-pd-len']),
	["none" => "None",
	16 => "48",
	12 => "52",
	8  => "56",
	4  => "60",
	2  => "62",
	1  => "63",
	0  => "64"]
))->setWidth(2);

$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration_prefix_delegation_size);

foreach(['Use IPv4 connectivity as parent interface' => [
			'label' => 'Request a IPv6 prefix/information through the IPv4 connectivity link',
			'value' => 'dhcp6usev4iface'],
		'Request only a IPv6 prefix' => [
			'label' => 'Only request a IPv6 prefix, do not request a IPv6 address',
			'value' => 'dhcp6prefixonly'],
		'Send IPv6 prefix hint' => [
			'label' => 'Send an IPv6 prefix hint to indicate the desired prefix size for delegation',
			'value' => 'dhcp6-ia-pd-send-hint']
	] as $group => $info) {

	$group_dhcp6_client_configuration = (new Form_Group($group))
		->addClass('toggle-adv_dhcp6_config_advanced', 'toggle-adv_dhcp6_config_file_override', 'collapse');

	if (!$pconfig['adv_dhcp6_config_advanced'] || !$pconfig['adv_dhcp6_config_file_override']) {
		$group_dhcp6_client_configuration->addClass('in');
	}

	$group_dhcp6_client_configuration->add(new form_checkbox(
		$info['value'],
		'',
		$info['label'],
		($pconfig[$info['value']]),
		'yes'
	));

	$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration);
}

$group_dhcp6_client_configuration_advanced = (new Form_Group('DHCPv6 Client Advanced Configuration'))
	->addClass('toggle-adv_dhcp6_config_advanced', 'collapse');

if ($pconfig['adv_dhcp6_config_advanced']) {
	$group_dhcp6_client_configuration_advanced->addClass('in');
}

$group_dhcp6_client_configuration_advanced->add(new Form_Checkbox(
	'adv_dhcp6_interface_statement_information_only_enable',
	'',
	'Information Only',
	$pconfig['adv_dhcp6_interface_statement_information_only_enable']
));

foreach([ 'Send Options' => [
			'value' => 'adv_dhcp6_interface_statement_send_options',
			'help' =>
			'The values in this field are DHCP send options to be sent when '.
			'requesting a DHCP lease. [option declaration [, ...]]<br/>'.
			'Value Substitutions: {interface}, {hostname}, {mac_addr_asciiCD}, '.
			'{mac_addr_hexCD} <br/>'.
			'Where C is U(pper) or L(ower) Case, and D is " :-." Delimiter (space, '.
			'colon, hyphen, or period) (omitted for none).<br/>'.
			'Some DHCP services may require certain options be or not be sent.'],
		'Request Options' => [
			'value' => 'adv_dhcp6_interface_statement_request_options',
			'help' =>
			'The values in this field are DHCP request options to be sent when '.
			'requesting a DHCP lease. [option [, ...]]<br/>'.
			'Some DHCP services may require certain options be or not be requested.'],
		'Script' => [
			'value' => 'adv_dhcp6_interface_statement_script',
			'help' =>
			'The value in this field is the absolute path to a script invoked '.
			'on certain conditions including when a reply message is received.<br/>'.
			'[/[dirname/[.../]]filename[.ext]]']
	] as $label => $value) {
	$group_dhcp6_client_configuration_advanced = (new Form_Group($label))
		->addClass('toggle-adv_dhcp6_config_advanced', 'collapse');

	if ($pconfig['adv_dhcp6_config_advanced']) {
		$group_dhcp6_client_configuration_advanced->addClass('in');
	}

	$group_dhcp6_client_configuration_advanced->add(new Form_Input(
		$value['value'],
		'',
		'text',
		$pconfig['adv_dhcp6_interface_statement_send_options']
	))->setHelp($value['help']);

	$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration_advanced);
}

$group_dhcp6_client_configuration_advanced_address_allocation = new Form_Group('Non-Temporary Address Allocation');

$group_dhcp6_client_configuration_advanced_address_allocation->add(new Form_Checkbox(
	'adv_dhcp6_id_assoc_statement_address_enable',
	'Non-Temporary Address Allocation',
	'Non-Temporary Address Allocation',
	''
));

$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration_advanced_address_allocation);

foreach ([
	'id-assoc na ID' => 'adv_dhcp6_id_assoc_statement_address_id',
	'Address ipv6-address' => 'adv_dhcp6_id_assoc_statement_address',
	'pltime' => 'adv_dhcp6_id_assoc_statement_address_pltime',
	'vltime' => 'adv_dhcp6_id_assoc_statement_address_vltime'
] as $label => $name) {
	$group_dhcp6_client_configuration_advanced_address_allocation = new Form_Group($label);

	$group_dhcp6_client_configuration_advanced_address_allocation->add(new Form_Input(
		$label,
		'',
		'text',
		$pconfig[$name]
	));

	$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration_advanced_address_allocation);
}


$group_dhcp6_client_configuration_advanced_prefix_delegation = new Form_Group('Prefix Delegation');

$group_dhcp6_client_configuration_advanced_prefix_delegation->add(new Form_Checkbox(
	'adv_dhcp6_id_assoc_statement_prefix_enable',
	'Prefix Delegation',
	'Prefix Delegation',
	''
));

$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration_advanced_prefix_delegation);

foreach ([
	'id-assoc pd ID' => 'adv_dhcp6_id_assoc_statement_prefix_id',
	'Prefix ipv6-prefix' => 'adv_dhcp6_id_assoc_statement_prefix',
	'pltime' => 'adv_dhcp6_id_assoc_statement_prefix_pltime',
	'vltime' => 'adv_dhcp6_id_assoc_statement_prefix_vltime'
] as $label => $name) {
	$group_dhcp6_client_configuration_advanced_prefix_delegation = new Form_Group($label);

	$group_dhcp6_client_configuration_advanced_prefix_delegation->add(new Form_Input(
		$label,
		'',
		'text',
		$pconfig[$name]
	));

	$section_dhcp6_client_configuration->add($group_dhcp6_client_configuration_advanced_prefix_delegation);
}

// '<a target="FreeBSD_DHCP" href="http://www.freebsd.org/cgi/man.cgi?query=dhcp6c.conf&amp;sektion=5&amp;apropos=0&amp;manpath=FreeBSD+Ports#Prefix_interface_statement">Prefix Interface Statement</a>'

// 'Prefix Interface sla-id' => 'adv_dhcp6_prefix_interface_statement_sla_id',
// 'sla-len' => 'adv_dhcp6_prefix_interface_statement_sla_len'


// '<a target="FreeBSD_DHCP" href="http://www.freebsd.org/cgi/man.cgi?query=dhcp6c.conf&amp;sektion=5&amp;apropos=0&amp;manpath=FreeBSD+Ports#Authentication_statement">Authentication Statement</a>'

// 'authname' => 'adv_dhcp6_authentication_statement_authname',
// 'protocol' => 'adv_dhcp6_authentication_statement_protocol',
// 'algorithm' => 'adv_dhcp6_authentication_statement_algorithm',
// 'rdm' => 'adv_dhcp6_authentication_statement_rdm'


// '<a target="FreeBSD_DHCP" href="http://www.freebsd.org/cgi/man.cgi?query=dhcp6c.conf&amp;sektion=5&amp;apropos=0&amp;manpath=FreeBSD+Ports#Keyinfo_statement\">Keyinfo Statement</a>'

// 'keyname' => 'adv_dhcp6_key_info_statement_keyname',
// 'realm' => 'adv_dhcp6_key_info_statement_realm',
// 'keyid' => 'adv_dhcp6_key_info_statement_keyid',
// 'secret' => 'adv_dhcp6_key_info_statement_secret',
// 'expire' => 'adv_dhcp6_key_info_statement_expire'


$group_dhcp6_client_configuration_advanced_identity_association_statement = (new Form_Group('Identity Association Statement'))
	->addClass('toggle-adv_dhcp6_config_advanced', 'collapse');

$group_dhcp6_client_configuration_advanced_identity_association_statement->add(new Form_Checkbox(
	'adv_dhcp6_id_assoc_statement_prefix_enable',
	'Request only a IPv6 prefix',
	'Only request a IPv6 prefix, do not request a IPv6 address',
	($pconfig['dhcp6usev4iface']),
	'yes'
));



$form->add($section_dhcp6_client_configuration);

print $form;

include("foot.inc");
?>
