
# Download and extract the latest WordPress release
wp_download_url="https://wordpress.org/latest.tar.gz"
wp_tmp_dir=$(mktemp -d)
wget -P "$wp_tmp_dir" "$wp_download_url"
tar -zxf "$wp_tmp_dir/latest.tar.gz" -C "$install_dir" --strip-components=1
rm -r "$wp_tmp_dir"

# Generate unique WordPress secrets
wp_auth_key=$(openssl rand -base64 48)
wp_secure_auth_key=$(openssl rand -base64 48)
wp_logged_in_key=$(openssl rand -base64 48)
wp_nonce_key=$(openssl rand -base64 48)
wp_auth_salt=$(openssl rand -base64 48)
wp_secure_auth_salt=$(openssl rand -base64 48)
wp_logged_in_salt=$(openssl rand -base64 48)
wp_nonce_salt=$(openssl rand -base64 48)

# Set ownership to match the installation directory
chown -R $(stat -c "%U:%G" "$install_dir") "$install_dir"

# Create a new WordPress configuration file
wp_config="$install_dir/wp-config.php"
cat <<EOL >"$wp_config"
<?php
define('DB_NAME', '$db_name');
define('DB_USER', '$db_user');
define('DB_PASSWORD', '$db_password');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY', '$wp_auth_key');
define('SECURE_AUTH_KEY', '$wp_secure_auth_key');
define('LOGGED_IN_KEY', '$wp_logged_in_key');
define('NONCE_KEY', '$wp_nonce_key');
define('AUTH_SALT', '$wp_auth_salt');
define('SECURE_AUTH_SALT', '$wp_secure_auth_salt');
define('LOGGED_IN_SALT', '$wp_logged_in_salt');
define('NONCE_SALT', '$wp_nonce_salt');

\$table_prefix = 'wp_';

define('WP_DEBUG', false);

if ( !defined('ABSPATH') )
  define('ABSPATH', dirname(__FILE__) . '/');

require_once(ABSPATH . 'wp-settings.php');
EOL