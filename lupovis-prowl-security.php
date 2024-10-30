<?php
/**
 * Plugin Name: Lupovis Prowl Security
 * Plugin URI: https://prowl.lupovis.io
 * Description: A security plugin that validate visitor IPs against the Lupovis Prowl API and blocks malicious IPs to avoid breaches
 * Version: 1.2
 * Author: Lupovis.io
 * Author URI: https://lupovis.io
 * License: GPL-2.0-or-later
 * Text Domain: lupovis-prowl-security
 */

// Activation hook
function lps_activate() {
    global $wpdb;

    // Define the table name.
    $table_name = $wpdb->prefix . "lps_blocked_ips";

    // Create a new table to store blocked IPs.
    $charset_collate = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        ip_address varchar(45) NOT NULL,
        blocked_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ttps text NOT NULL,
        PRIMARY KEY  (id),
        UNIQUE KEY ip_address (ip_address)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);

    // Create a new table to store failed login attempts.
    $failed_login_attempts_table_name = $wpdb->prefix . "lps_failed_login_attempts";
    $sql = "CREATE TABLE $failed_login_attempts_table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        ip_address varchar(45) NOT NULL,
        attempt_count int(11) NOT NULL DEFAULT 1,
        last_attempt datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        UNIQUE KEY ip_address (ip_address)
    ) $charset_collate;";

    dbDelta($sql);
}
register_activation_hook(__FILE__, 'lps_activate');

// Deactivation hook
function lps_deactivate() {
    global $wpdb;

    // Define the table name.
    $table_name = $wpdb->prefix . "lps_blocked_ips";

    // Drop the table created on activation.
    $wpdb->query("DROP TABLE IF EXISTS $table_name");

    // Drop the failed login attempts table created on activation.
    $failed_login_attempts_table_name = $wpdb->prefix . "lps_failed_login_attempts";
    $wpdb->query("DROP TABLE IF EXISTS $failed_login_attempts_table_name");
}
register_deactivation_hook(__FILE__, 'lps_deactivate');

// Settings page
function lps_add_settings_page() {
    add_options_page(
        'Lupovis Prowl Security',
        'Lupovis Prowl Security',
        'manage_options',
        'lps_settings',
        'lps_settings_page'
    );
}
add_action('admin_menu', 'lps_add_settings_page');

function lps_settings_page() {
    ?>
    <div class="wrap">
        <h1>Lupovis Prowl Security</h1>
        <form action="options.php" method="post">
            <?php
            settings_fields('lps_settings');
            do_settings_sections('lps_settings');
            submit_button();
            ?>
        </form>
        <div id="blocked_ips">
            <h2>Blocked IPs</h2>
            <?php lps_display_blocked_ips(); ?>
        </div>
    </div>
    <?php
}

function lps_register_settings() {
    // Register the API key setting.
    register_setting('lps_settings', 'lps_api_key');
    register_setting('lps_settings', 'lps_allowlist_ips');
    register_setting('lps_settings', 'lps_monitor_failed_logins');

    // Add the Configuration settings section.
    add_settings_section('lps_configuration_section', 'API Configuration', 'lps_configuration_section_callback', 'lps_settings');

    // Add the API key field to the Configuration section.  
    add_settings_field('lps_api_key', 'API Key', 'lps_api_key_field_callback', 'lps_settings', 'lps_configuration_section');

    // Add the allowlist IPs field to the Configuration section.    
    add_settings_field('lps_allowlist_ips', 'Allowlist IPs', 'lps_allowlist_ips_field_callback', 'lps_settings', 'lps_configuration_section');

    // Add the monitoring failed logins field to the Configuration section.
    add_settings_field('lps_monitor_failed_logins', 'Monitor Failed Logins', 'lps_monitor_failed_logins_field_callback', 'lps_settings', 'lps_configuration_section');

}

add_action('admin_init', 'lps_register_settings');

function lps_configuration_section_callback() {
echo '<p>Enter your Lupovis Prowl API key to enable the security plugin. Add allowed IPs separated by commas and enable monitoring for failed logins.</p>';
}

function lps_api_key_field_callback() {
    // Get the current value of the API key setting.
    $lps_api_key = get_option('lps_api_key', '');

    // Render the API key input field.
    echo '<input type="text" name="lps_api_key" value="' . esc_attr($lps_api_key) . '" size="50" />';

    // Add a button to get the API key.
    echo '<a href="https://aws.amazon.com/marketplace/pp/prodview-cr64x4lse5uui" target="_blank" class="button">Get your API key Now!</a>';
}


//function lps_allowlist_ips_field_callback() {
// Get the current value of the allowlist IPs setting.
//$lps_allowlist_ips = get_option('lps_allowlist_ips', '');
// Render the allowlist IPs input field.
//echo '<input type="text" name="lps_allowlist_ips" value="' . esc_attr($lps_allowlist_ips) . '" size="50" /><br><small>Enter allowed IPs separated by commas (e.g., 192.168.1.1,192.168.1.2).</small>';
//}

function lps_allowlist_ips_field_callback() {
    // Get the current value of the allowlist IPs setting.
    $allowed_ips = sanitize_text_field(get_option('lps_allowlist_ips', ''));
    $allowlist = array_map(function($ip) {
        return sanitize_text_field(trim($ip));
    }, explode(',', $allowed_ips));
    // Convert the array back to a string to be used in the input field.
    $lps_allowlist_ips = implode(',', $allowlist);
    // Render the allowlist IPs input field.
    echo '<input type="text" name="lps_allowlist_ips" value="' . esc_attr($lps_allowlist_ips) . '" size="50" /><br><small>Enter allowed IPs separated by commas (e.g., 192.168.1.1,192.168.1.2).</small>';
}


function lps_monitor_failed_logins_field_callback() {
// Get the current value of the monitor failed logins setting.
$lps_monitor_failed_logins = boolval(get_option('lps_monitor_failed_logins', ''));
// Render the monitor failed logins checkbox.
echo '<input type="checkbox" name="lps_monitor_failed_logins" value="1"' . checked(1, $lps_monitor_failed_logins, false) . ' />';
}

function lps_display_blocked_ips() {
global $wpdb;

// Define the table name.
$table_name = $wpdb->prefix . "lps_blocked_ips";

// Get the blocked IPs from the database.
$blocked_ips = $wpdb->get_results("SELECT * FROM $table_name ORDER BY blocked_at DESC");

if (count($blocked_ips) > 0) {
    echo '<table class="widefat">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>IP Address</th>';
    echo '<th>Blocked At</th>';
    echo '<th>TTPs</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';
    foreach ($blocked_ips as $blocked_ip) {
        echo '<tr>';
        echo '<td>' . esc_html($blocked_ip->ip_address) . '</td>';
        echo '<td>' . esc_html($blocked_ip->blocked_at) . '</td>';
        '</td>';
echo '<td>' . esc_html($blocked_ip->ttps) . '</td>';
echo '</tr>';
}
echo '</tbody>';
echo '</table>';
} else {
echo '<p>No IPs have been blocked yet.</p>';
}
}

function lps_check_ip() {
    // Get the visitor's IP address.
    $ip_address = sanitize_text_field($_SERVER['REMOTE_ADDR']);

    // Sanitize, validate and escape IP address
    if (!rest_is_ip_address($ip_address)) {
        wp_die('Invalid IP address');
    }

    $ip_address = esc_html($ip_address);

    // Check if the IP address is in the allowlist.
    $allowed_ips = get_option('lps_allowlist_ips', '');
    $allowlist = array_map('trim', explode(',', $allowed_ips));
    if (in_array($ip_address, $allowlist)) {
        return;
    }

    global $wpdb;
    
    // Define the table name.
    $table_name = $wpdb->prefix . "lps_blocked_ips";

    // Check if the IP address is already blocked.
    $blocked_ip = $wpdb->get_var($wpdb->prepare("SELECT ip_address FROM $table_name WHERE ip_address = %s", $ip_address));

    if ($blocked_ip) {
        // If the IP is already blocked, return early.
        return;
    }

    // Get the API key from the settings.
    $api_key = sanitize_text_field(get_option('lps_api_key', ''));

    // If the API key is not set, return early.
    if (empty($api_key)) {
        return;
    }

    // Check if the API response is cached.
    $response_data = get_transient('lps_check_ip_' . $ip_address);
    if ($response_data === false) {
        // Prepare the API request URL.
        $api_url = "https://84h9dq7p3c.execute-api.eu-west-1.amazonaws.com/live/GetIPReputation?ip={$ip_address}";

        // Set up the API request headers.
        $headers = [
            'x-api-key' => $api_key,
        ];

        // Send the API request.
        $response = wp_remote_get($api_url, ['headers' => $headers]);

        // Check for errors in the API request.
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return;
        }

        // Decode the API response JSON.
        $response_data = json_decode(wp_remote_retrieve_body($response), true);

        // Cache the API response for 24 hours.
        set_transient('lps_check_ip_' . $ip_address, $response_data, 24 * HOUR_IN_SECONDS);
    }

    // If the TTPs array is not empty, the IP is malicious.
    if (!empty($response_data['ttps'])) {
        // Insert the malicious IP into the blocked IPs table.
        $wpdb->query($wpdb->prepare(
        "INSERT INTO $table_name (ip_address, ttps) VALUES (%s, %s)",
        $ip_address,
        implode(', ', $response_data['ttps'])
    ));

        // Block the IP from accessing the website.
        wp_die('Your IP has been blocked due to suspicious activity.');
    }
}


add_action('init', 'lps_check_ip');

// Monitor failed login attempts
function lps_failed_login_attempt($username) {
if (get_option('lps_monitor_failed_logins', '') == 1) {
global $wpdb;

    // Get the visitor's IP address.
    $ip_address = sanitize_text_field($_SERVER['REMOTE_ADDR']);

    // Sanitize, validate and escape IP address
    if (!rest_is_ip_address($ip_address)) {
        wp_die('Invalid IP address');
    }

$ip_address = esc_html($ip_address);

    // Define the table name.
    $table_name = $wpdb->prefix . "lps_failed_login_attempts";

    // Check if the IP address already has failed attempts.
    $failed_attempt = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip_address = %s", $ip_address));

    if ($failed_attempt) {
        // Increment the attempt_count and update the last_attempt datetime.
        $wpdb->query($wpdb->prepare(
        "UPDATE $table_name SET attempt_count = attempt_count + 1, last_attempt = %s WHERE id = %d",
        current_time('mysql'),
        $failed_attempt->id));

        // If the attempt_count reaches 5, add the IP to the blocked IPs table.
        if ($failed_attempt->attempt_count >= 4) {
            $blocked_ips_table_name = $wpdb->prefix . "lps_blocked_ips";
            $wpdb->insert($blocked_ips_table_name, [
                'ip_address' => $ip_address,
                'ttps' => '5 failed login attempts',
            ]);
            // Block the IP from accessing the website.
            wp_die('Your IP has been blocked due to suspicious activity.'); // xavier insert
        }
    } else {
    // Insert the failed attempt into the failed login attempts table.
        $wpdb->query($wpdb->prepare(
        "INSERT INTO $table_name (ip_address) VALUES (%s)",
        $ip_address
    ));

    }
}
}
add_action('wp_login_failed', 'lps_failed_login_attempt');

    // Clear failed login attempts on successful login
function lps_clear_failed_attempts($user_login, $user) {
    if (get_option('lps_monitor_failed_logins', '') == 1) {
        global $wpdb;

        // Get the visitor's IP address.
        $ip_address = sanitize_text_field($_SERVER['REMOTE_ADDR']);

        // Sanitize, validate and escape IP address
        if (!rest_is_ip_address($ip_address)) {
            wp_die('Invalid IP address');
        }

        $ip_address = esc_html($ip_address);

        // Define the table name.
        $table_name = $wpdb->prefix . "lps_failed_login_attempts";

        // Remove the failed login attempts for the IP address.
        $wpdb->delete($table_name, ['ip_address' => $ip_address]);
    }
}
add_action('wp_login', 'lps_clear_failed_attempts', 10, 2);





