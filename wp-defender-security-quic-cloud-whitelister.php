<?php

/**
 * Plugin Name:  WP Defender Security QUIC.cloud Whitelister
 * Plugin URI:   https://github.com/tombonez/wp-defender-security-quic-cloud-whitelister
 * Description:  A WordPress plugin to whitelist the IP addresses of QUIC.cloud servers in Defender Security.
 * Version:      1.0.0
 * Author:       Tom Taylor
 * Author URI:   https://github.com/tombonez
 */

namespace WP_Defender_Security_Quic_Cloud_Whitelister;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP_Defender_Security_Quic_Cloud_Whitelister {

	private $file_path;

	public function __construct() {
		$this->file_path = WP_CONTENT_DIR . '/quic-cloud-ips.php';

		add_action( 'init', array( $this, 'init' ) );
		add_action( 'wp_defender_security_quic_cloud_whitelister', array( $this, 'ip_downloader' ) );

		add_filter( 'ip_lockout_default_whitelist_ip', array( $this, 'whitelist_ips' ) );

		if ( ! wp_next_scheduled( 'wp_defender_security_quic_cloud_whitelister' ) ) {
			wp_schedule_event( time(), 'twicedaily', 'wp_defender_security_quic_cloud_whitelister' );
		}
	}

	public function init() {
		if ( ! file_exists( $this->file_path ) ) {
			$this->ip_downloader();
		}
	}

	public function ip_downloader() {
		$url      = 'https://www.quic.cloud/ips?ln';
		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) ) {
			return;
		}

		$ips = explode( "\n", wp_remote_retrieve_body( $response ) );

		if ( empty( $ips ) ) {
			return;
		}

		$ips_array = array_filter( $ips );
		$ips_array = array_map( 'trim', $ips_array );

		global $wp_filesystem;

		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		$content = "<?php return array( '" . implode( "', '", $ips_array ) . "' );";
		$wp_filesystem->put_contents( $this->file_path, $content, FS_CHMOD_FILE );
	}

	public function whitelist_ips( $ips ) {
		if ( ! file_exists( $this->file_path ) || ! is_readable( $this->file_path ) ) {
			return $ips;
		}

		$quic_cloud_ips = include_once $this->file_path;

		if ( ! is_array( $quic_cloud_ips ) ) {
			return $ips;
		}

		return array_merge( $ips, $quic_cloud_ips );
	}
}

new WP_Defender_Security_Quic_Cloud_Whitelister();
