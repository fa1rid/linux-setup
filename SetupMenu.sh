#!/bin/bash
version="0.2.1"
# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi
cron_dir="/root/cron/"
mkdir -p ${cron_dir}

# Function to generate a random password
generate_password() {
    local LENGTH="$1"
    if [[ -z "$LENGTH" ]]; then
        LENGTH=16 # Default password length
    fi

    LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+{}:<>?' </dev/urandom | head -c "$LENGTH"
}
ssl_nginx_snippet="/etc/nginx/snippets/ssl-snippet.conf"
common_nginx_snippet="/etc/nginx/snippets/common-snippet.conf"
caching_nginx_snippet="/etc/nginx/snippets/caching-snippet.conf"
# default_domain="domain.local"
# default_user="default"

PHP_Versions=("7.4" "8.2")

generate_php_conf() {
    username=$1
    domain=$2
    phpVer=$3
    # memory_limit
    read -p "Enter memory_limit value in MB (or press Enter to use the default '256'): " memory_limit
    # Use the user input if provided, or the default value if the input is empty
    if [ -z "$memory_limit" ]; then
        memory_limit=256
    fi
    echo "Memory_limit is: ${memory_limit}"

    # time_zone
    read -p "Enter time_zone (or press Enter to use the default 'Asia/Dubai'): " time_zone
    # Use the user input if provided, or the default value if the input is empty
    if [ -z "$time_zone" ]; then
        time_zone="Asia/Dubai"
    fi
    echo "time_zone is: ${time_zone}"

    # upload_max_filesize
    read -p "Enter upload_max_filesize in MB (max 100) (or press Enter to use the default '100'): " upload_max_filesize
    # Use the user input if provided, or the default value if the input is upload_max_filesize
    if [ -z "$upload_max_filesize" ]; then
        upload_max_filesize=100
    fi
    echo "upload_max_filesize is: ${upload_max_filesize}"
    sleep 1
    # Calculate post_max_size
    post_max_size=$((upload_max_filesize + 1))

    cat >"/etc/php/${phpVer}/fpm/pool.d/${username}-${domain}.conf" <<EOF
[${domain}]
user = ${username}
group = users
listen = /run/php/${phpVer}-fpm-${domain}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 15
pm.start_servers = 10
pm.min_spare_servers = 10
pm.max_spare_servers = 10
pm.max_requests = 5000
request_terminate_timeout = 300
pm.process_idle_timeout = 10s
chdir = /
catch_workers_output = yes

php_value[memory_limit] = ${memory_limit}M
php_value[upload_max_filesize] = ${upload_max_filesize}M
php_value[post_max_size] = ${post_max_size}M

php_value[open_basedir] = "/var/www/${username}/${domain}/:/tmp/:/usr/share/GeoIP/"
php_value[date.timezone] = "${time_zone}"
php_value[disable_functions] = "opcache_get_status"
php_value[error_reporting] = "E_ALL & ~E_DEPRECATED & ~E_STRICT"
php_value[expose_php] = off
php_value[max_execution_time] = 300
php_value[output_buffering] = 8192

php_value[session.gc_probability] = 1
php_value[session.sid_length] = 100
php_value[session.name] = "SID"

php_value[opcache.huge_code_pages] = 1
php_value[opcache.max_wasted_percentage] = 10
php_value[opcache.interned_strings_buffer] = 64
php_value[opcache.memory_consumption] = 384
php_value[opcache.max_accelerated_files] = 16229
php_value[opcache.revalidate_path] = 0
php_value[opcache.revalidate_freq] = 60

; [opcache.jit]
; A value of 50-100% of the current Opcache shared memory for Opcode might be the ideal value for opcache.jit_buffer_size.
EOF
    systemctl restart php${phpVer}-fpm
}

# Function to install PHP
install_php() {

    # memory_limit
    read -p "Enter memory_limit value in MB (or press Enter to use the default '256'): " memory_limit
    # Use the user input if provided, or the default value if the input is empty
    if [ -z "$memory_limit" ]; then
        memory_limit=256
    fi
    echo "Memory_limit is: ${memory_limit}"

    # time_zone
    read -p "Enter time_zone (or press Enter to use the default 'Asia/Dubai'): " time_zone
    # Use the user input if provided, or the default value if the input is empty
    if [ -z "$time_zone" ]; then
        time_zone="Asia/Dubai"
    fi
    echo "time_zone is: ${time_zone}"

    if [ -f "/etc/apt/sources.list.d/php.list" ]; then
        echo "PHP Repo Exists"
    else
        # Adding sury's PHP repo
        echo "Installing sury's PHP repo"
        curl -sSL https://packages.sury.org/php/README.txt | bash -x
        echo
    fi
    # upload_max_filesize
    read -p "Enter upload_max_filesize in MB (max 100) (or press Enter to use the default '100'): " upload_max_filesize
    # Use the user input if provided, or the default value if the input is upload_max_filesize
    if [ -z "$upload_max_filesize" ]; then
        upload_max_filesize=100
    fi
    echo "upload_max_filesize is: ${upload_max_filesize}"
    sleep 1
    # Calculate post_max_size
    post_max_size=$((upload_max_filesize + 1))

    for phpVer in "${PHP_Versions[@]}"; do
        echo -e "\nInstalling PHP ${phpVer}"
        # Essential & Commonly Used Extensions Extensions
        apt install -y bc php${phpVer}-{fpm,mysqli,mbstring,curl,xml,intl,gd,zip,bcmath,apcu,sqlite3,imagick,tidy,gmp,bz2,ldap,pcntl} >/dev/null 2>&1
        # bz2
        # [PHP Modules] bcmath calendar Core ctype curl date dom exif FFI fileinfo filter ftp gd gettext hash iconv intl json libxml mbstring mysqli mysqlnd openssl pcntl pcre PDO pdo_mysql Phar posix readline Reflection session shmop SimpleXML sockets sodium SPL standard sysvmsg sysvsem sysvshm tokenizer xml xmlreader xmlwriter xsl Zend OPcache zip zlib apcu sqlite3 imagick tidy
        # [Zend Modules]
        # Zend OPcache

        # Less Commonly Used Extensions
        # apt install php${phpVer}-{soap,pspell,xmlrpc,memcached}

        # For dev
        # apt install php${phpVer}-{dev}

        # Modify default configs
        sed -i "s/memory_limit = .*/memory_limit = ${memory_limit}M/" /etc/php/${phpVer}/cli/php.ini

        # Enable JIT
        # ; tracing: An alias to the granular configuration 1254.
        # ; function: An alias to the granular configuration 1205.
        enableJIT=$(echo "${phpVer} > 8" | bc)
        if [ "$enableJIT" -eq 1 ]; then
        sed -i "s/opcache.jit.*/opcache.jit=function/" "/etc/php/${phpVer}/mods-available/opcache.ini"
        echo "opcache.jit_buffer_size = 256M" >> "/etc/php/${phpVer}/mods-available/opcache.ini"
        fi

        # Set default time zone
        time_zone_escaped=$(printf '%s\n' "${time_zone}" | sed -e 's/[\/&]/\\&/g' -e 's/["'\'']/\\&/g')
        sed -i "s/;date\.timezone =.*/date.timezone = ${time_zone_escaped}/" /etc/php/${phpVer}/cli/php.ini

        # Set upload_max_filesize and post_max_size
        sed -i "s/upload_max_filesize = .*/upload_max_filesize = ${upload_max_filesize}M/" /etc/php/${phpVer}/cli/php.ini
        sed -i "s/post_max_size = .*/post_max_size = ${post_max_size}M/" /etc/php/${phpVer}/cli/php.ini

        if [ -f "/etc/php/${phpVer}/fpm/pool.d/www.conf" ]; then
            mv /etc/php/${phpVer}/fpm/pool.d/www.conf /etc/php/${phpVer}/fpm/pool.d/www.disabled
        fi

        echo "Stopping service as there are no configs.."
        systemctl stop php${phpVer}-fpm

        echo "Done Installing PHP ${phpVer}"
        echo "----------------------------------"
    done

    # Install Composer
    if [ -f "/usr/local/bin/composer" ]; then
        echo "Composer already installed"
    else
        read -p "Enter PHP version to install composer: (default 7.4) " composer_php_ver
        # Use the user input if provided, or the default value if the input is empty
        if [ -z "$composer_php_ver" ]; then
            composer_php_ver=7.4
        fi
        curl -sS https://getcomposer.org/installer | php${composer_php_ver}
        echo "Moving 'composer.phar' to '/usr/local/bin/composer'"
        mv composer.phar /usr/local/bin/composer
    fi

    echo "PHP installation and configuration complete."

}

# Function to install Nginx
install_nginx() {

    # COUNTRY="US"
    # STATE="California"
    # LOCALITY="San Francisco"
    COUNTRY="AE"
    STATE="Dubai"
    LOCALITY="Dubai"
    ORGANIZATION="MyCompany"
    ORG_UNIT="IT"
    COMMON_NAME="localhost"
    EMAIL="webmaster@example.com"

    if [ -f "/etc/apt/sources.list.d/nginx.list" ]; then
        echo -e "\nnginx Repo Exists"
    else
        # Adding sury's nginx repo
        echo -e "\nInstalling sury's nginx repo"
        curl -sSL https://packages.sury.org/nginx/README.txt | bash -x
        echo
    fi

    PACKAGE_NAME="nginx"
    # Check if the package is installed
    if dpkg -l | grep -q "^ii  $PACKAGE_NAME "; then
        echo "$PACKAGE_NAME is already installed."
    else
        echo "$PACKAGE_NAME is not installed. Installing..."
        apt update
        apt install -y $PACKAGE_NAME >/dev/null 2>&1
        echo "$PACKAGE_NAME has been installed."
    fi

    # Add log rotation for nginx
    sed -i "s/^\/var\/log\/nginx\/\*\.log/\/var\/www\/*\/logs\/*\/*.log/" /etc/logrotate.d/nginx
    #     bash -c 'cat <<EOT >> /etc/logrotate.d/nginx
    # /var/www/*/logs/*/*.log {
    #     daily
    #     missingok
    #     rotate 14
    #     compress
    #     delaycompress
    #     notifempty
    #     create 0640 www-data adm
    #     sharedscripts
    #     prerotate
    # 		if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
    # 			run-parts /etc/logrotate.d/httpd-prerotate; \
    # 		fi \
    # 	endscript
    #     postrotate
    #         invoke-rc.d nginx rotate >/dev/null 2>&1
    #     endscript
    # }
    # EOT'

    # Create log folder for the main profile
    rm -rf /var/www/html
    # basedir="/var/www/${default_user}/"
    # mkdir -p ${basedir}${default_domain}/public
    # mkdir -p ${basedir}logs/${default_domain}/
    # chown -R default:www-data ${basedir}
    # chmod 710 ${basedir}

    # Generate self-signed SSL certificate
    nginx_key="/etc/ssl/private/nginx.key"
    nginx_cert="/etc/ssl/certs/nginx.crt"
    # nginx_dhparams2048="/etc/ssl/dhparams2048.pem"
    # openssl dhparam -out ${nginx_dhparams2048} 2048

    if [ ! -f "$nginx_cert" ] || [ ! -f "$nginx_key" ]; then
        echo -e "\nGenerating new self-signed cert for nginx.."
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$nginx_key" \
            -out "$nginx_cert" \
            -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORG_UNIT/CN=$COMMON_NAME/emailAddress=$EMAIL"
    fi

    # Configure nginx for production use
    if [ -f "/etc/nginx/nginx.conf" ]; then
        mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    fi

    if [ -f "$ssl_nginx_snippet" ]; then
        echo "SSL snippet file already exist at $ssl_nginx_snippet"
    else
        echo "ssl_certificate ${nginx_cert};" >"$ssl_nginx_snippet"
        echo "ssl_certificate_key ${nginx_key};" >>"$ssl_nginx_snippet"
        echo "SSL snippet file generated at $ssl_nginx_snippet"
    fi

    cat >"${caching_nginx_snippet}" <<EOF
location ~* \.(?:ico|gif|jpe?g|png|htc|xml|otf|ttf|eot|woff|woff2|svg|css|js)\$ {
    expires 1d;
    add_header Cache-Control public;
    open_file_cache max=3000 inactive=120s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 4;
    open_file_cache_errors on;
}
EOF

    cat >"${common_nginx_snippet}" <<EOF
index index.html index.htm index.php;
# index "index.html" "index.cgi" "index.pl" "index.php" "index.xhtml" "index.htm" "index.shtml";

add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
# Prevent external sources from loading for (XSS) and data injection attacks
# add_header Content-Security-Policy "default-src 'self';";
add_header Referrer-Policy same-origin;
add_header X-XSS-Protection "1; mode=block";
# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";

location = /favicon.ico {
    access_log off;
    log_not_found off;
}
location = /robots.txt {
    access_log off;
    log_not_found off;
}

location ~ /\.ht {
    deny all;
}

# Deny access to any git repository
location ~ /\.git {
    deny all;
}

# Deny access to xmlrpc.php - a common brute force target against Wordpress
location = /xmlrpc.php {
    deny all;
    access_log off;
    log_not_found off;
    return 444;
}
EOF
    bash -c 'cat <<EOT >/etc/nginx/nginx.conf
user www-data;
worker_processes auto;
worker_rlimit_nofile 20960;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept        on;  
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    types_hash_max_size 2048;
    server_tokens off;
    server_names_hash_bucket_size 128;

    include /etc/nginx/mime.types;
    # default_type application/octet-stream;
    # ssl_dhparam ${nginx_dhparams2048};
    ssl_protocols TLSv1.2 TLSv1.3;
    proxy_ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256";

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOT'

    cat >/etc/nginx/conf.d/gzip.conf <<EOF
gzip on;
gzip_static on;
gzip_comp_level 5;
gzip_min_length 10000; #10kb
gzip_proxied any;
gzip_vary on;

gzip_types
application/atom+xml
application/javascript
application/json
application/rss+xml
application/vnd.ms-fontobject
application/x-font-opentype
application/x-font-truetype
application/x-font-ttf
application/x-javascript
application/xhtml+xml
application/xml
font/eot
font/opentype
font/otf
font/truetype
image/svg+xml
image/vnd.microsoft.icon
image/x-icon
image/x-win-bitmap
text/css
text/javascript
text/plain
text/xml
text/x-component;
EOF
    cat >/etc/nginx/conf.d/brotli.conf <<EOF
brotli on;
brotli_comp_level 6;
brotli_static on;
brotli_min_length 10000; #10kb

brotli_types
application/atom+xml
application/javascript
application/json
application/rss+xml
application/vnd.ms-fontobject
application/x-font-opentype
application/x-font-truetype
application/x-font-ttf
application/x-javascript
application/xhtml+xml
application/xml
font/eot
font/opentype
font/otf
font/truetype
image/svg+xml
image/vnd.microsoft.icon
image/x-icon
image/x-win-bitmap
text/css
text/javascript
text/plain
text/xml
text/x-component;
EOF

    if [ ! -f "/etc/nginx/sites-available/default.disabled" ]; then
        mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.disabled
        rm /etc/nginx/sites-enabled/default
    fi

    # Restart nginx for changes to take effect
    systemctl restart nginx

    echo "Nginx setup completed!"

}

# Function to install MariaDB Server
install_mariadb_server() {
    # Prompt for variable values
    # read -p "Enter the InnoDB buffer pool size (e.g., 512M): " INNODB_BUFFER_POOL_SIZE
    # read -p "Enter the root password for MariaDB: " DB_ROOT_PASS
    read -p "Enter the application username: " DB_USER
    read -p "Enter the password for the application user: " DB_USER_PASS
    read -p "Enter the name for the database: " DB_NAME

    # Variables
    # DB_ROOT_PASS="your_root_password"
    # DB_USER="your_app_user"
    # DB_USER_PASS="your_app_user_password"
    # DB_NAME="your_db_name"

    PACKAGE_NAME="mariadb-server"
    # Check if the package is installed
    if dpkg -l | grep -q "^ii  $PACKAGE_NAME "; then
        echo "$PACKAGE_NAME is already installed."
    else
        echo "$PACKAGE_NAME is not installed. Installing..."
        apt update && apt upgrade -y
        apt install -y $PACKAGE_NAME >/dev/null 2>&1
        echo "$PACKAGE_NAME has been installed."
    fi
    # mysql_secure_installation
    # Secure MariaDB installation
    # mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED VIA unix_socket WITH GRANT OPTION;FLUSH PRIVILEGES;"
    # mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASS';"
    # mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;";
    # mysql -e "SHOW GRANTS FOR 'root'@'localhost';"

    # Remove anonymous users
    mysql -e "DELETE FROM mysql.user WHERE User='';"
    # Disallow root login remotely
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    # Remove the test database
    mysql -e "DROP DATABASE IF EXISTS test;"
    # Reload privilege tables
    mysql -e "FLUSH PRIVILEGES;"

    echo -e "\nMySQL secure installation completed.\n"

    # Create a new database and user
    mysql -e "CREATE DATABASE $DB_NAME;"
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_USER_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    mysql -e "SELECT @@character_set_server AS character_set, @@collation_server AS collation;"

    # Show users and their permissions
    mysql -e "SELECT user, host, plugin, password FROM mysql.user;"
    grants_commands=$(mysql -e "SELECT GROUP_CONCAT('SHOW GRANTS FOR \'', user, '\'@\'', host, '\';' SEPARATOR ' ') AS query FROM mysql.user;" | grep -v "query")
    mysql -e "$grants_commands"

    # Update MariaDB configuration for production use
    #     cat <<EOT >>/etc/mysql/mariadb.conf.d/50-server.cnf
    # # Custom configuration for production use
    # # You can add more configurations here

    # # InnoDB settings
    # innodb_buffer_pool_size = $INNODB_BUFFER_POOL_SIZE
    # innodb_flush_log_at_trx_commit = 2
    # innodb_file_per_table = 1
    # innodb_open_files = 400
    # EOT

    # Restart MariaDB
    systemctl restart mariadb

    # Enable and start MariaDB on boot
    systemctl enable mariadb

    echo "MariaDB setup and configuration completed!"
}

# Function to install MariaDB Client
install_mariadb_client() {
    # Install the MariaDB client
    echo "Installing MariaDB client..."
    apt update
    apt install -y mariadb-client >/dev/null 2>&1

    read -p "Enter the MariaDB server hostname or IP (without port): " db_host
    read -p "Enter the database username: " db_user
    read -s -p "Enter the password for the database user: " db_pass
    echo

    # Create a configuration file for the MariaDB client
    cat <<EOF >~/.my.cnf
[client]
host=$db_host
user=$db_user
password=$db_pass
EOF
    # Secure the configuration file
    chmod 600 ~/.my.cnf
    echo
    cat ~/.my.cnf
    echo
    echo "MariaDB client has been installed and configured."

}

# Function to install Memcached
install_memcached() {
    # Install Memcached and required dependencies
    apt update
    apt install -y memcached libmemcached-tools >/dev/null 2>&1

    # Configure Memcached
    echo "-m 512" >>/etc/memcached.conf       # Set memory limit to 512MB
    echo "-l 127.0.0.1" >>/etc/memcached.conf # Bind to localhost
    echo "-p 11211" >>/etc/memcached.conf     # Use port 11211
    echo "-U 0" >>/etc/memcached.conf         # Run as the root user
    echo "-t 4" >>/etc/memcached.conf         # Use 4 threads

    # Restart Memcached
    systemctl restart memcached

    # Enable Memcached to start on system boot
    systemctl enable memcached

    echo "Memcached installation and configuration complete"
}

# Function to install PHPMyAdmin
install_phpmyadmin() {

    while true; do
        # Prompt for the username
        read -p "Enter vhost username: " vuser
        # Prompt for the domain name
        read -p "Enter vhost domain name (e.g., example.com): " domain

        web_dir="/var/www/${vuser}/${domain}"

        # Check if the username contains only alphanumeric characters
        if [[ ! -d "$web_dir" ]]; then
            echo "Directory doesn't exit."
            exit 1
        else
            break
        fi
    done

    PHPMYADMIN_VERSION="5.2.1" # Update this to the desired phpMyAdmin version
    INSTALL_DIR="${web_dir}/public/dbadmin"

    read -p "Make sure mariadb connection is configured and press enter" CONFIRM_XYZ
    read -p "Enter new password for dbadmin user: " dbadmin_pass
    # read -p "Enter new password for management user (pma)" pmapass
    # Generate a password with default length
    pmapass=$(generate_password)
    echo "pmapass: $pmapass"

    # Create Database User for phpMyAdmin.
    # mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'dbadmin'@'localhost' IDENTIFIED BY '${dbadmin_pass}' WITH GRANT OPTION;FLUSH PRIVILEGES;"
    # Fix for AWS managed databses (RDS):
    mysql -e "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, PROCESS, REFERENCES, INDEX, ALTER, SHOW DATABASES, CREATE TEMPORARY TABLES, LOCK TABLES, REPLICATION SLAVE, REPLICATION CLIENT, CREATE VIEW, EVENT, TRIGGER, SHOW VIEW, DELETE HISTORY, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EXECUTE ON *.* TO 'dbadmin'@'localhost' IDENTIFIED BY '${dbadmin_pass}' WITH GRANT OPTION;FLUSH PRIVILEGES;"

    # Create Database User for phpMyAdmin management (for multi user use).
    mysql -e "GRANT SELECT, INSERT, UPDATE, DELETE ON phpmyadmin.* TO 'pma'@'localhost' IDENTIFIED BY '${pmapass}';"

    # Download and Extract phpMyAdmin archive
    mkdir -p "${INSTALL_DIR}"

    if [ ! -f "phpMyAdmin-${PHPMYADMIN_VERSION}-english.tar.gz" ]; then
        wget "https://files.phpmyadmin.net/phpMyAdmin/${PHPMYADMIN_VERSION}/phpMyAdmin-${PHPMYADMIN_VERSION}-english.tar.gz"

    fi
    tar -xzvf "phpMyAdmin-${PHPMYADMIN_VERSION}-english.tar.gz" --strip-components=1 -C "${INSTALL_DIR}" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Extraction successful."
    else
        echo "Extraction failed."
        return
    fi

    # Create config file
    cp "${INSTALL_DIR}/config.sample.inc.php" "${INSTALL_DIR}/config.inc.php"

    # Load phpmyadmin database into the database
    mysql <"${INSTALL_DIR}/sql/create_tables.sql"

    # Generate a random blowfish secret for enhanced security
    BLOWFISH_SECRET=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)
    sed -i "s|cfg\['blowfish_secret'\] = ''|cfg\['blowfish_secret'\] = '${BLOWFISH_SECRET}'|" "${INSTALL_DIR}/config.inc.php" || echo "Error on setting blowfish_secret"
    # sed -i "s/\$cfg\['blowfish_secret'\] = '';.*/\$cfg\['blowfish_secret'\] = '$(pwgen -s 32 1)';/" "${INSTALL_DIR}/config.inc.php"

    # Set pma password
    sed -i "s/pmapass/${pmapass}/" "${INSTALL_DIR}/config.inc.php" || echo "Error on pma password"

    # Uncomment all $cfg['Servers'] to enable configuration storage, a database and several tables used by the administrative pma database user. These tables enable a number of features in phpMyAdmin, including Bookmarks, comments, PDF generation, and more.
    sed -i '/^\/\/.*Servers/s/^\/\/ //' "${INSTALL_DIR}/config.inc.php" || echo "Error on Uncomment all \$cfg['Servers']"

    # Make a new directory where phpMyAdmin will store its temporary files
    # mkdir -p /var/lib/phpmyadmin/tmp
    # chown -R www-data:www-data /var/lib/phpmyadmin

    # Set uplaod, save, and tmp Dir
    # mkdir -p "${INSTALL_DIR}/tmp"
    sed -i "s/\$cfg\['UploadDir'\] = '';/\$cfg\['UploadDir'\] = 'tmp';/" "${INSTALL_DIR}/config.inc.php" || echo "Error on setting UploadDir"
    sed -i "s/\$cfg\['SaveDir'\] = '';/\$cfg\['SaveDir'\] = 'tmp';/" "${INSTALL_DIR}/config.inc.php" || echo "Error on setting SaveDir"
    echo "\$cfg['TempDir'] = '${INSTALL_DIR}/tmp';" >>"${INSTALL_DIR}/config.inc.php"

    # Allow access from specific IP addresses (replace with your IP addresses)
    # echo "\$cfg['Servers'][\$i]['AllowDeny']['rules'] = array('allow' => array('your_ip_address')); " >> $phpmyadmin_config

    # Allow access from any IP addresses
    sed -e '/controlhost/ s/^\/*/\/\/ /' -i "${INSTALL_DIR}/config.inc.php" || echo "Error on setting controlhost"
    sed -e '/controlport/ s/^\/*/\/\/ /' -i "${INSTALL_DIR}/config.inc.php" || echo "Error on setting controlport"

    # Adjust permissions
    chown -R "${vuser}:users" "${INSTALL_DIR}"
    # chmod -R 770 "${INSTALL_DIR}"
    chmod 660 "${INSTALL_DIR}/config.inc.php"

}

# Function to remove MariaDB
remove_mariadb() {
    # Ask for confirmation
    read -p "This will uninstall MariaDB. Are you sure? (y/n): " confirmation

    if [[ $confirmation != "y" ]]; then
        echo "Aborting."
        return 0
    fi

    # Uninstall MariaDB
    apt remove --purge mariadb-server mariadb-client
    # apt remove --purge mariadb* mysql*
    echo -e "\nRunning dpkg -l | grep -e mysql -e mariadb "
    dpkg -l | grep -e mysql -e mariadb

    read -p "Do you want to remove configurations by running apt autoremove? (y/n): " confirmation2

    if [[ $confirmation2 != "y" ]]; then
        apt autoremove
    fi

    # Delete configuration and database files
    # rm -rf /etc/mysql /var/lib/mysql /var/log/mysql

    # Remove MariaDB user and group
    # deluser mysql
    # delgroup mysql

    echo -e "\nMariaDB has been purged from the system. All databases and configuration files have been deleted."
}

# Function to remove PHP
remove_php() {
    # Ask for confirmation
    read -p "This will purge PHP and its configuration.. Are you sure? (y/n): " confirmation

    if [[ $confirmation != "y" ]]; then
        echo "Aborting."
        return 0
    fi

    for phpVer in "${PHP_Versions[@]}"; do

        # Purge PHP packages
        apt purge php${phpVer}-* && apt autoremove

    done

    # Remove PHP configuration files
    rm -rf /etc/php/

    echo "PHP and its configuration have been purged."
}

# Function to remove Nginx
remove_nginx() {
    # Ask for confirmation
    read -p "This will purge Nginx and its configuration.. Are you sure? (y/n): " confirmation

    if [[ $confirmation != "y" ]]; then
        echo "Aborting."
        return 0
    fi

    # Stop Nginx if it's running
    systemctl stop nginx

    # Purge Nginx and its configuration
    apt purge nginx nginx-common && apt autoremove

    # Remove configuration files
    rm -rf /etc/nginx

    echo "Nginx and its configuration have been purged."
}

# Function to remove Memcached
remove_memcached() {
    # Ask for confirmation
    read -p "This will purge Memcached and its configuration.. Are you sure? (y/n): " confirmation

    if [[ $confirmation != "y" ]]; then
        echo "Aborting."
        return 0
    fi
    # Stop Memcached service
    systemctl stop memcached

    # Purge Memcached data
    rm -rf /var/lib/memcached/*

    # Remove Memcached configuration files
    apt remove --purge memcached

    # Also remove configuration files
    rm -rf /etc/memcached.conf

    echo "Memcached purged and configuration files removed."
}

cleanUp() {
    # Clean up
    apt autoremove
    apt autoclean
    apt update
    apt autoremove -y
    apt clean
}

install_standard_packages() {

    # Install the "standard" task automatically
    # apt install -y tasksel
    # echo "standard" | tasksel install

    apt update && apt install -y \
        curl \
        wget \
        git \
        nano \
        unzip \
        htop \
        net-tools \
        nftables \
        bind9-dnsutils \
        cron \
        logrotate \
        ncurses-term \
        mime-support \
        bzip2 \
        iproute2 \
        pciutils \
        bc >/dev/null 2>&1

    # The following additional packages will be installed:
    # bind9-host bind9-libs ca-certificates file git-man libcurl3-gnutls libcurl4 liberror-perl
    # libfstrm0 libgdbm-compat4 libgdbm6 libjemalloc2 libldap-2.5-0 libldap-common liblmdb0
    # libmagic-mgc libmagic1 libmaxminddb0 libnghttp2-14 libnl-3-200 libnl-genl-3-200 libperl5.36
    # libprotobuf-c1 libpsl5 librtmp1 libsasl2-2 libsasl2-modules libsasl2-modules-db libssh2-1 libuv1
    # mailcap media-types openssl patch perl perl-modules-5.36 publicsuffix xz-utils
    # Need to get 25.6 MB of archives.
    # After this operation, 132 MB of additional disk space will be used.

    # Clean up
    apt autoremove -y
    apt clean

    echo "Standard packages installation complete."
}

install_configure_SSH() {

    # Update package lists
    apt update

    # Install SSH server
    apt install openssh-server -y >/dev/null 2>&1

    # Backup the original configuration
    if [ -e "/etc/ssh/sshd_config_backup" ]; then
        echo "Backup file '/etc/ssh/sshd_config_backup' already exists."
    else
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config_backup
    fi

    # Enable root login (not recommended for production)
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

    # Disable root's ability to use password-based authentication
    # sed -i 's/PermitRootLogin yes/PermitRootLogin without-password/' /etc/ssh/sshd_config

    # Set SSH port to 4444
    sed -i 's/#Port 22/Port 4444/' /etc/ssh/sshd_config

    # Disable password authentication (use key-based authentication)
    # sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Enable PasswordAuthentication
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

    # Allow only specific users or groups to log in via SSH (replace with your username)
    # echo "AllowUsers your_username" >> /etc/ssh/sshd_config

    # Restart SSH service (for changes to take effect immediately)
    systemctl restart sshd

}

configure_terminal_system_banners() {
    echo "Setting server's timezone to Asia/Dubai"
    timedatectl set-timezone Asia/Dubai || echo "Failed to set timezone"
    echo ""
    read -p "Do you want to restore the original configuration from the backup? (y/n): " restore_choice
    if [ "$restore_choice" == "y" ]; then
        # Check if Backup exist
        if [ -e "/etc/bash.bashrc.backup" ]; then
            cp /etc/bash.bashrc.backup /etc/bash.bashrc
            cp_success=$?
            if [ $cp_success -eq 0 ]; then
                echo "Original configuration has been restored."
            else
                echo "Failed to restore original configuration."
            fi
        else
            echo "Backup file '/etc/bash.bashrc.backup' doesn't exists."
        fi
        return
    fi

    # Backup the original configuration
    if [ -e "/etc/bash.bashrc.backup" ]; then
        echo "Skipping Backup (already exists) '/etc/bash.bashrc.backup'."
    else
        echo -e "Creating backup (bash.bashrc.backup)...\n"
        cp /etc/bash.bashrc /etc/bash.bashrc.backup
    fi

    # Define the new PS1 prompt with color codes
    # hetzner uses red yeloow cyan yellow pink
    # Define colors using ANSI escape codes
    RED="\[\033[01;31m\]"
    GREEN="\[\033[01;32m\]"
    YELLOW="\[\033[01;33m\]"
    PINK="\[\033[01;35m\]"
    CYAN="\[\033[01;36m\]"
    RESET="\[\033[0m\]"

    # Set the customized PS1 variable
    CUSTOM_PS1="'\${debian_chroot:+(\$debian_chroot)}${RED}\\u${YELLOW}@${CYAN}\\h ${YELLOW}\\w ${PINK}\\\$ ${RESET}'"
    escaped_PS1=$(echo "$CUSTOM_PS1" | sed 's/[\/&]/\\&/g')

    # Replace the old PS1 line with the new one
    sed -i "s/PS1=.*/PS1=${escaped_PS1}/" /etc/bash.bashrc

    # "echo \"IP: \$(hostname -I | awk '{print \$1}') \$(ip -o -4 route show to default | awk '{print $5}')\""

    aliases=(
        "alias ls='ls --color=auto'"
        "alias ll='ls -lh'"
        "alias la='ls -A'"
        "alias l='ls -CF'"
        "alias grep='grep --color=auto'"
        "alias fgrep='fgrep --color=auto'"
        "alias egrep='egrep --color=auto'"
        "export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'"
        "HISTSIZE=10000"
        "HISTFILESIZE=20000"
        "IP_Add=\"\$(hostname -I | awk '{print \$1}') \$(ip -o -4 route show to default)\""
        # "echo -e \" \\e[91mIP:\\e[0m \${IP_Add}\""
        "sinfo"
    )
    for value in "${aliases[@]}"; do
        escaped_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g' -e 's/["'\'']/\\&/g')
        if ! grep -qF "$value" "/etc/bash.bashrc"; then
            echo "$value" >>"/etc/bash.bashrc"
        fi
    done

    # Notify user about the changes
    echo "PS1 prompt, aliases, exports, and history settings have been updated for all users."

    cat >"/etc/issue" <<EOFX
\e{lightblue}\s \m \r (Time: \t\e{reset})
\e{lightblue}\S{PRETTY_NAME} \v\e{reset}
\e{lightgreen}\n.\o : \4\e{reset}
EOFX
    echo "FServer!" >/etc/motd

    sinfo_script="/usr/local/bin/sinfo"
    # Use a here document to create the script content
    cat >"$sinfo_script" <<'EOF'
#!/bin/bash

# Get IP and Route
IP_Add="$(hostname -I | awk '{print $1}') $(ip -o -4 route show to default)"

# Get OS information
os_info=$(lsb_release -d -s 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2- | tr -d '"')

# Get kernel information
kernel_info=$(uname -smr)

# Get uptime
uptime_info=$(uptime -p | sed 's/up //')

# Get package count
package_count=$(dpkg -l | grep -c '^ii' 2>/dev/null || rpm -qa --last | wc -l 2>/dev/null)

# Get shell information
shell_info=$($SHELL --version 2>&1 | head -n 1)

# Get disk usage
disk_info=$(df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 ")"}')

# Get CPU information
cpu_info=$(lscpu | awk -F ': ' '/^Model name/ {gsub(/^[ \t]+/, "", $2); print $2}')

# Get GPU information
gpu_info=$(lspci | grep -i "VGA" | awk -F ': ' '{print $2}')

# Get RAM information
ram_info=$(free -h | grep "Mem:" | awk '{print $3 " / " $2}')

# Print the gathered information
echo -e " \e[91mIP:\e[0m $IP_Add"
echo -e " \e[91mOS:\e[0m $os_info"
echo -e " \e[91mKernel:\e[0m $kernel_info"
echo -e " \e[91mUptime:\e[0m $uptime_info"
echo -e " \e[91mPackages:\e[0m $package_count"
echo -e " \e[91mShell:\e[0m $shell_info"
echo -e " \e[91mDisk:\e[0m $disk_info"
echo -e " \e[91mCPU:\e[0m $cpu_info"
echo -e " \e[91mGPU:\e[0m $gpu_info"
echo -e " \e[91mRAM:\e[0m $ram_info"
EOF

    echo "Script generated and saved as $sinfo_script"
    chmod +x "$sinfo_script"

}

add_cloudflare() {
    cloudflare_script="/usr/local/bin/cloudflare_sync"
    cat >"$cloudflare_script" <<'EOF'
#!/bin/bash

CLOUDFLARE_FILE_PATH=/etc/nginx/conf.d/cloudflare.conf

echo "#Cloudflare" > $CLOUDFLARE_FILE_PATH;
echo "" >> $CLOUDFLARE_FILE_PATH;

echo "# - IPv4" >> $CLOUDFLARE_FILE_PATH;
for i in `curl https://www.cloudflare.com/ips-v4`; do
        echo "set_real_ip_from $i;" >> $CLOUDFLARE_FILE_PATH;
done

echo "" >> $CLOUDFLARE_FILE_PATH;
echo "# - IPv6" >> $CLOUDFLARE_FILE_PATH;
for i in `curl https://www.cloudflare.com/ips-v6`; do
        echo "set_real_ip_from $i;" >> $CLOUDFLARE_FILE_PATH;
done

echo "" >> $CLOUDFLARE_FILE_PATH;
echo "real_ip_header CF-Connecting-IP;" >> $CLOUDFLARE_FILE_PATH;

#test configuration and reload nginx
nginx -t && systemctl reload nginx
EOF

    chmod 700 "$cloudflare_script"

    echo "Fetching IPs from cloudflare.."
    cloudflare_sync >/dev/null 2>&1
    # Add daily cron job
    echo "Adding cron job.."

    echo "30 1 * * * root ${cloudflare_script} >/dev/null 2>&1" >"${cron_dir}cloudflare"
    chmod 660 "${cron_dir}cloudflare"
    cat "${cron_dir}"* | crontab -
    echo -e "Loaded cron jobs:\n"
    crontab -l
    # Jobs inside "/etc/cron.d/" directory are monitored for changes
    # /etc/init.d/cron reload
    # systemctl restart cron
    # /var/spool/cron/crontabs
}

read_mysql_config() {
    # Array of configuration parameters to check
    CONFIG_PARAMS=(
        "bind_address"
        "character_set_server"
        "collation_server"
        "innodb_adaptive_flushing"
        "innodb_buffer_pool_size"
        "innodb_doublewrite"
        "innodb_file_per_table"
        "innodb_flush_log_at_timeout"
        "innodb_flush_log_at_trx_commit"
        "innodb_flush_method"
        "innodb_flush_neighbors"
        "innodb_io_capacity"
        "innodb_log_file_size"
        "innodb_open_files"
        "innodb_read_io_threads"
        "innodb_thread_concurrency"
        "innodb_write_io_threads"
        "key_buffer_size"
        "log_error"
        "long_query_time"
        "max_allowed_packet"
        "max_connections"
        "min_examined_row_limit"
        "performance_schema"
        "query_cache_limit"
        "query_cache_size"
        "query_cache_type"
        "skip_name_resolve"
        "skip_secure_auth"
        "slow_query_log"
        "slow_query_log_file"
        "table_definition_cache"
        "table_open_cache"
        "thread_cache_size"
    )

    # Loop through each configuration parameter and retrieve its value
    for param in "${CONFIG_PARAMS[@]}"; do
        value=$(mysql -BNe "SHOW VARIABLES LIKE '$param';" | awk '{print $2}')
        echo -e "\e[91m${param}=\e[0m $value"
    done

    mysql -e "SELECT user, host, plugin, password FROM mysql.user;"
    grants_commands=$(mysql -e "SELECT GROUP_CONCAT('SHOW GRANTS FOR \'', user, '\'@\'', host, '\';' SEPARATOR ' ') AS query FROM mysql.user;" | grep -v "query")
    mysql -e "$grants_commands"
}

create_vhost() {
    while true; do
        # Prompt for the domain name
        read -p "Enter the domain name (e.g., example.com): " domain

        # Check if the domain name follows common rules
        if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo "Invalid domain name format. Please enter a valid domain name (e.g., example.com)."
        fi
    done

    while true; do
        # Prompt for the username
        read -p "Enter new username: " vuser
        # Check if the username contains only alphanumeric characters
        if [[ "$vuser" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            break
        else
            echo "Username should only contain letters (uppercase and lowercase), numbers, underscores, and hyphens. Please try again."
        fi
    done

    if id "${vuser}" &>/dev/null; then
        echo "User ${vuser} exists."
    else
        echo "User ${vuser} does not exist."
        useradd -N -m -s $(which bash) -d "/var/www/${vuser}" ${vuser}
        passwd "$vuser"

    fi

    # Prompt the user to choose between two options
    PS3="Please select PHP version: "

    # Define the options
    options=("PHP 7.4" "PHP 8.2" "Quit")

    # Display the options and prompt for a choice
    select choice in "${options[@]}"; do
        case $REPLY in
        1)
            phpVer=7.4
            break
            ;;
        2)
            phpVer=8.2
            break
            ;;
        3)
            echo "Exiting the script."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please choose 1 or 2."
            ;;
        esac
    done

    # Create vhost directories
    basedir="/var/www/${vuser}/"
    mkdir -p "${basedir}/logs/${domain}"
    mkdir -p "${basedir}/${domain}/public/"
    chmod 710 ${basedir}
    chown ${vuser}:www-data ${basedir}
    chown -R ${vuser}:users ${basedir}*

    # Generate php config
    generate_php_conf "${vuser}" "${domain}" "${phpVer}"

    # Generate nginx config
    generate_nginx_vhost "${vuser}" "${domain}" "${phpVer}"

    # Enable nginx site
    if [ -L "/etc/nginx/sites-enabled/${domain}.conf" ]; then
        echo -e "\nSymbolic link '/etc/nginx/sites-enabled/${domain}.conf' already exists."
    else
        if [ -e "/etc/nginx/sites-enabled/${domain}.conf" ]; then
            echo -e "\nqFile or directory with the name '/etc/nginx/sites-enabled/${domain}.conf' already exists. Cannot create the symbolic link."
        else
            ln -s /etc/nginx/sites-available/${vuser}-${domain}.conf /etc/nginx/sites-enabled/
            echo -e "\nSymbolic link '/etc/nginx/sites-enabled/${vuser}-${domain}.conf' created to '/etc/nginx/sites-available/${vuser}-${domain}.conf'"
        fi
    fi
    nginx -t && systemctl reload nginx
}

generate_nginx_vhost() {
    vuser="$1"
    domain="$2"
    phpVer="$3"

    read -p "Is this default domain? (y/n) " is_default
    if [[ "$is_default" == "y" ]]; then
        server_name="server_name _"
    else
        server_name="server_name $domain www.${domain}"
    fi

    cat <<EOT >/etc/nginx/sites-available/${vuser}-${domain}.conf
server {
    listen 80;
    ${server_name};
    # root /var/www/${vuser}/${domain}/public;
    # access_log /var/www/${vuser}/logs/${domain}/access.log;
    # error_log /var/www/${vuser}/logs/${domain}/error.log error;
    # error_page 404 /404.html;

    # Redirect www to non-www
    if (\$host ~* ^www\.(.*)) {
        set \$redirect_host \$1;
        rewrite ^(.*)\$ https://\$redirect_host\$request_uri permanent;
    }

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;

    # client_max_body_size 1M;
    # location / {
    #     # First attempt to serve request as file, then as directory, then fall back to displaying a 404.
    #     try_files \$uri \$uri/ =404;
    # }

    # include ${common_nginx_snippet};
}

server {
    listen 443 ssl http2;
    ${server_name};
    root /var/www/${vuser}/${domain}/public;
    include ${ssl_nginx_snippet};
    include ${common_nginx_snippet};
    access_log /var/www/${vuser}/logs/${domain}/ssl_access.log;
    error_log /var/www/${vuser}/logs/${domain}/ssl_error.log error;
    # error_page 404 /404.html;

    client_max_body_size 102M;

    # Redirect www to non-www
    if (\$host ~* ^www\.(.*)) {
        set \$redirect_host \$1;
        rewrite ^(.*)\$ https://\$redirect_host\$request_uri permanent;
    }

    # Limiting the Rate of Requests: each unique IP address is limited to 10 requests per second with 5 requests bursting.
    # location /login/ {
    #     limit_req zone=one burst=5;
    # }

    # Limiting the Number of Connections: limit the number of connections that can be opened by a unique IP address.
    # limit_conn_zone \$binary_remote_addr zone=addr:10m;
    # location /something/ {
    #     limit_conn addr 10;
    # }

   location ~ \.php(/.*)?$ {
        fastcgi_pass unix:/run/php/${phpVer}-fpm-${domain}.sock;
        include snippets/fastcgi-php.conf;
        fastcgi_read_timeout 300;
    }

    location / {
       try_files \$uri \$uri/ /index.php\$is_args\$args;
    }
}
EOT
}

install_more_packages() {
    apt update

    apt install -y build-essential software-properties-common python3 python3-pip >/dev/null 2>&1

    echo "More Packages installation complete."
}

# Function to display the menu
display_menu() {
    clear
    echo "===== Farid's Setup Menu v${version} ====="
    echo "1. Install PHP 7 and 8"
    echo "2. Install Nginx"
    echo "3. Install MariaDB Server"
    echo "4. Install MariaDB Client"
    echo "5. Install Memcached"
    echo "6. Install PHPMyAdmin"
    echo "7. Remove MariaDB"
    echo "8. Remove PHP"
    echo "9. Remove Nginx"
    echo "10. Remove Memcached"
    echo "11. Clean up (autoremove, autoclean, update)"
    echo "12 Install Standard Packages"
    echo "13 Install & configure SSH (port 4444 allows root with pass)"
    echo "14 Configure terminal and system banners"
    echo "15 Read mysql/MariaDB config"
    echo "16 Add cloudflare IPs SYNC script with cron job"
    echo "17 Create vhostx"
    echo "0. Exit"
    echo "==============================="
}

# Main script loop
while true; do
    display_menu
    read -p "Enter your choice: " choice

    case $choice in
    1) install_php ;;
    2) install_nginx ;;
    3) install_mariadb_server ;;
    4) install_mariadb_client ;;
    5) install_memcached ;;
    6) install_phpmyadmin ;;
    7) remove_mariadb ;;
    8) remove_php ;;
    9) remove_nginx ;;
    10) remove_memcached ;;
    11) cleanUp ;;
    12) install_standard_packages ;;
    13) install_configure_SSH ;;
    14) configure_terminal_system_banners ;;
    15) read_mysql_config ;;
    16) add_cloudflare ;;
    17) create_vhost ;;
    0) exit ;;
    *) echo "Invalid choice. Please select again." ;;
    esac

    read -p "Press Enter to continue..."
done
