#!/bin/bash

# Prompt for the installation directory
read -p "Enter the full path where you want to install WordPress (e.g., /var/www/html/myblog): " install_dir
read -p "Enter the user that will run wp: " local_user

# Verify the installation directory
if [ ! -d "$install_dir" ]; then
    echo "The specified directory does not exist."
    exit 1
fi

if [ -f "/usr/local/bin/wp" ]; then
    echo "wp already installed"
else
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    mv wp-cli.phar /usr/local/bin/wp
fi

# Database name, user, and admin user
hex=$(openssl rand -hex 3)
DB_NAME="wp_${hex}"
DB_USER="wp_${hex}"
DB_PASS=$(openssl rand -base64 12)
WP_ADMIN_USER="admin"
WP_ADMIN_PASS=$(openssl rand -base64 12)

WP_ADMIN_EMAIL="user@example.com"
WP_URL=""
WP_TITLE=""

# Create MySQL database and user
mysql <<MYSQL_SCRIPT
CREATE DATABASE $DB_NAME DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

# Install WordPress using WP-CLI
sudo -u ${local_user} -s wp core download --path="${install_dir}" --locale=en_US

# Create wp-config.php file
sudo -u ${local_user} -s wp config create \
    --path="${install_dir}" \
    --dbname="$DB_NAME" \
    --dbuser="$DB_USER" \
    --dbpass="$DB_PASS" \
    --locale=en_US

# Install WordPress
sudo -u ${local_user} -s wp core install \
  --path="${install_dir}" \
  --admin_user="$WP_ADMIN_USER" \
  --admin_password="$WP_ADMIN_PASS"

sudo -u ${local_user} -s wp core install \
  --path="${install_dir}" \
  --url="$WP_URL" \
  --title="$WP_TITLE" \
  --admin_user="$WP_ADMIN_USER" \
  --admin_password="$WP_ADMIN_PASS" \
  --admin_email="$WP_ADMIN_EMAIL"

sudo -u ${local_user} -s wp core install --url="http://example.com" --title="My WordPress Site" --admin_user="$admin_user" --admin_password="$admin_password" --admin_email="admin@example.com" --path="$install_dir"

sudo -u zaza -s wp core install --url="http://example.com" --title="My WordPress Site" --admin_user="admin" --admin_password="zaza" --admin_email="admin@example.com"

wp plugin install all-in-one-seo-pack all-in-one-wp-migration amp google-analytics-for-wordpress jetpack w3-total-cache wp-mail-smtp --path="$install_dir"
wp plugin activate jetpack

wp_user_create=$(wp user create "$admin_user" admin@example.com --user_pass="$admin_password" --path="$install_dir")
echo "#############################################################"

if [[ $wp_user_create == *"Success"* ]]; then
    echo "WordPress is now installed and configured in $install_dir."
    echo "username: $admin_user | password: $admin_password"
    echo "You can access it in your web browser to complete the setup."
else
    echo "Error creating the WordPress admin user."
    exit 1
fi
echo "#############################################################"

exit 0
