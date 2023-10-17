#!/bin/bash

servo_version="0.4.2"

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

#########################################

cron_dir="/root/cron/"
mkdir -p ${cron_dir}
cloudflare_config_dir="/etc/letsencrypt/cloudflare"
ssl_nginx_snippet="/etc/nginx/snippets/ssl-snippet.conf"
common_nginx_snippet="/etc/nginx/snippets/common-snippet.conf"
caching_nginx_snippet="/etc/nginx/snippets/caching-snippet.conf"
# default_domain="domain.local"
# default_user="default"

PHP_Versions=("7.4" "8.2")

# Check if MariaDB is installed
if command -v mariadb &>/dev/null; then
    DB_CMD="mariadb"
    DUMP_CMD="mariadb-dump"
elif command -v mysql &>/dev/null; then
    DB_CMD="mysql"
    DUMP_CMD="mysqldump"
fi

#########################################

# Function to check for updates
check_for_update() {
    local github_repo="fa1rid/linux-setup"
    local script_name="Servo.sh"
    local script_folder="setup_menu"
    local local_script_path="/usr/local/bin/"

    if ! command -v curl &>/dev/null; then
        apt update && apt install curl
    fi
    latest_version=$(curl -s "https://raw.githubusercontent.com/${github_repo}/main/${script_folder}/version.txt")
    echo "Latest Version: ($latest_version)"
    if [ "$latest_version" != "$servo_version" ]; then
        echo "A newer version ($latest_version) is available. Updating..."
        curl -so "${local_script_path}${script_name}" "https://raw.githubusercontent.com/$github_repo/main/${script_folder}/$script_name" || echo "Failed to connect"
        chmod +x "${local_script_path}${script_name}"
        echo "Update complete. Please run the script again."
        exit 0
    else
        echo "You have the latest version ($servo_version) of the script."
    fi
}

is_valid_domain() {
    local domain="$1"
    local regex="^(http(s)?://)?[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+$"

    if [[ $domain =~ $regex ]]; then
        return 0 # Valid domain
    else
        return 1 # Invalid domain
    fi
}

gen_pass() {
    local length="$1"
    local min_numbers="$2"
    local min_special_chars="$3"

    if [[ -z "$length" ]]; then
        length=20
    fi

    if [[ -z "$min_numbers" ]]; then
        min_numbers=3
    fi

    if [[ -z "$min_special_chars" ]]; then
        min_special_chars=0
    fi

    # Validate input
    if ((length < min_numbers + min_special_chars)); then
        echo "Error: The total length should be at least as large as the sum of minimum numbers and minimum special characters."
        return 1
    fi

    # Define character sets
    local lowercase='abcdefghijklmnopqrstuvwxyz'
    local uppercase='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    local numbers='0123456789'
    local special_chars='!@#$%^&*'

    # Initialize the variables
    local password=""
    local rand_num=""
    local rand_special=""
    local rand_char=""

    # Ensure minimum numbers
    for ((i = 0; i < min_numbers; i++)); do
        rand_num="${numbers:RANDOM%${#numbers}:1}"
        password="${password}${rand_num}"
    done

    # Ensure minimum special characters
    for ((i = 0; i < min_special_chars; i++)); do
        rand_special="${special_chars:RANDOM%${#special_chars}:1}"
        password="${password}${rand_special}"
    done

    # Calculate the remaining characters needed
    remaining_length=$((length - min_numbers - min_special_chars))

    # Generate the remaining random characters
    for ((i = 0; i < remaining_length; i++)); do
        rand_char="${lowercase}${uppercase}"
        rand_char="${rand_char:RANDOM%${#rand_char}:1}"
        password="${password}${rand_char}"
    done

    # Shuffle the password characters
    password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')
    echo "$password"

    # Usage
    # total_length="$1"
    # min_num="$2"
    # min_special="$3"
}

# Function to generate a random password
generate_password() {
    local LENGTH="$1"
    if [[ -z "$LENGTH" ]]; then
        LENGTH=20 # Default password length
    fi
    local password
    password=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$LENGTH")
    echo "$password"
    # LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+{}:<>?' </dev/urandom | head -c "$LENGTH"
}

# Function to list directory contents and prompt for selection
select_from_dir() {
    # Usage: select_from_dir [directory]
    clear >&2
    local directory="$1"
    local selection=
    local selected_item

    if [ -z "$directory" ]; then
        read -rp "Enter directory path: " directory
    fi

    # Check if the path ends with a slash and remove it if present
    directory="${directory%/}"
    echo "Select a file/folder from $directory:" >&2
    echo "0. Return" >&2

    local count=1
    for item in "$directory"/*; do
        if [ -e "$item" ]; then
            if [ -d "$item" ]; then
                echo -e "\033[32m${count}. $(basename "$item")\033[0m" >&2
            else
                echo -e "\033[34m${count}. $(basename "$item")\033[0m" >&2
            fi
            count=$((count + 1))
        fi
    done
    while [ -z "$selection" ]; do
        read -r selection

        if [[ ! "$selection" =~ ^[0-9]+$ ]]; then
            echo "Invalid input. Please enter a number." >&2
            selection=
            continue
        fi

        if [ "$selection" -eq 0 ]; then
            break
        fi

        if [ "$selection" -ge 1 ] && [ "$selection" -lt "$count" ]; then
            selected_item=$(ls -1 "$directory" | sed -n "${selection}p")
            echo "$directory/$selected_item"
            break
        else
            echo "Invalid selection. Please choose a valid option." >&2
            selection=
        fi

    done
}

generate_php_conf() {
    local username=$1
    local domain=$2
    local phpVer=$3
    local memory_limit
    local time_zone
    local time_zone
    local upload_max_filesize
    local post_max_size

    # memory_limit
    read -rp "Enter memory_limit value in MB (or press Enter to use the default '256'): " memory_limit
    # Use the user input if provided, or the default value if the input is empty
    if [ -z "$memory_limit" ]; then
        memory_limit=256
    fi
    echo "Memory_limit is: ${memory_limit}"

    # time_zone
    read -rp "Enter time_zone (or press Enter to use the default 'Asia/Dubai'): " time_zone
    # Use the user input if provided, or the default value if the input is empty
    if [ -z "$time_zone" ]; then
        time_zone="Asia/Dubai"
    fi
    echo "time_zone is: ${time_zone}"

    # upload_max_filesize
    read -rp "Enter upload_max_filesize in MB (max 100) (or press Enter to use the default '100'): " upload_max_filesize
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
    systemctl restart "php${phpVer}-fpm"
}

manage_php() {
    while true; do
        echo "Choose an option:"
        echo "1. Install PHP"
        echo "2. Remove (purge) PHP"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) install_php ;;
        2) remove_php ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

# Function to install PHP
install_php() {
    local memory_limit
    local time_zone
    local upload_max_filesize
    local post_max_size
    local enableJIT
    local time_zone_escaped
    local composer_php_ver

    # memory_limit
    read -rp "Enter memory_limit value in MB (or press Enter to use the default '256'): " memory_limit
    # Use the user input if provided, or the default value if the input is empty
    if [ -z "$memory_limit" ]; then
        memory_limit=256
    fi
    echo "Memory_limit is: ${memory_limit}"

    # time_zone
    read -rp "Enter time_zone (or press Enter to use the default 'Asia/Dubai'): " time_zone
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
    read -rp "Enter upload_max_filesize in MB (max 100) (or press Enter to use the default '100'): " upload_max_filesize
    # Use the user input if provided, or the default value if the input is upload_max_filesize
    if [ -z "$upload_max_filesize" ]; then
        upload_max_filesize=100
    fi
    echo "upload_max_filesize is: ${upload_max_filesize}"
    sleep 1
    # Calculate post_max_size
    post_max_size=$((upload_max_filesize + 1))
    apt update
    for phpVer in "${PHP_Versions[@]}"; do
        echo -e "\nInstalling PHP ${phpVer}"

        if [ -f "/etc/php/${phpVer}/fpm/pool.d/www.disabled" ]; then
            "mv /etc/php/${phpVer}/fpm/pool.d/www.disabled" "/etc/php/${phpVer}/fpm/pool.d/www.conf"
        fi

        # Essential & Commonly Used Extensions Extensions
        apt install -y bc php"${phpVer}"-{fpm,mysqli,mbstring,curl,xml,intl,gd,zip,bcmath,apcu,sqlite3,imagick,tidy,gmp,bz2,ldap,memcached} || (echo "Failed to install" && return 1)
        # bz2
        # [PHP Modules] bcmath calendar Core ctype curl date dom exif FFI fileinfo filter ftp gd gettext hash iconv intl json libxml mbstring mysqli mysqlnd openssl pcntl pcre PDO pdo_mysql Phar posix readline Reflection session shmop SimpleXML sockets sodium SPL standard sysvmsg sysvsem sysvshm tokenizer xml xmlreader xmlwriter xsl Zend OPcache zip zlib apcu sqlite3 imagick tidy
        # [Zend Modules]
        # Zend OPcache

        # Less Commonly Used Extensions
        # apt install php"${phpVer}"-{soap,pspell,xmlrpc,memcached}

        # For dev
        # apt install php${phpVer}-{dev}

        # Modify default configs
        sed -i "s/memory_limit = .*/memory_limit = ${memory_limit}M/" "/etc/php/${phpVer}/cli/php.ini"

        # Enable JIT
        # ; tracing: An alias to the granular configuration 1254.
        # ; function: An alias to the granular configuration 1205.
        enableJIT=$(echo "${phpVer} > 8" | bc)
        if [ "$enableJIT" -eq 1 ]; then
            # sed -i "s/opcache.jit.*/opcache.jit=function/" "/etc/php/${phpVer}/mods-available/opcache.ini"
            # echo "opcache.jit_buffer_size = 256M" >>"/etc/php/${phpVer}/mods-available/opcache.ini"
            echo "Skipping enabling JIT.."
        fi

        # Set default time zone
        time_zone_escaped=$(printf '%s\n' "${time_zone}" | sed -e 's/[\/&]/\\&/g' -e 's/["'\'']/\\&/g')
        sed -i "s/;date\.timezone =.*/date.timezone = ${time_zone_escaped}/" "/etc/php/${phpVer}/cli/php.ini"

        # Set upload_max_filesize and post_max_size
        sed -i "s/upload_max_filesize = .*/upload_max_filesize = ${upload_max_filesize}M/" "/etc/php/${phpVer}/cli/php.ini"
        sed -i "s/post_max_size = .*/post_max_size = ${post_max_size}M/" "/etc/php/${phpVer}/cli/php.ini"

        if [ -f "/etc/php/${phpVer}/fpm/pool.d/www.conf" ]; then
            mv "/etc/php/${phpVer}/fpm/pool.d/www.conf" "/etc/php/${phpVer}/fpm/pool.d/www.disabled"
        fi

        # echo "Stopping service as there are no configs.."
        # systemctl stop php${phpVer}-fpm

        echo "Done Installing PHP ${phpVer}"
        echo "----------------------------------"
    done

    # Install Composer
    if [ -f "/usr/local/bin/composer" ]; then
        echo "Composer already installed"
    else
        read -rp "Enter PHP version to install composer: (default 7.4) " composer_php_ver
        # Use the user input if provided, or the default value if the input is empty
        if [ -z "$composer_php_ver" ]; then
            composer_php_ver=7.4
        fi
        curl -sS https://getcomposer.org/installer | "php${composer_php_ver}"
        echo "Moving 'composer.phar' to '/usr/local/bin/composer'"
        mv composer.phar /usr/local/bin/composer
    fi

    echo "PHP installation and configuration complete."

}

# Function to remove PHP
remove_php() {
    local confirm
    read -rp "This will purge PHP and its configuration.. Are you sure? (y/n): " confirm

    if [[ $confirm != "y" ]]; then
        echo "Aborting."
        return 0
    fi

    for phpVer in "${PHP_Versions[@]}"; do

        # Purge PHP packages
        apt purge "php${phpVer}-"* && apt autoremove

    done

    # Remove PHP configuration files
    rm -rf /etc/php/

    echo "PHP and its configuration have been purged."
}

manage_nginx() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install nginx"
        echo "2. Remove (purge) nginx"
        echo "3. Create vhost"
        echo "4. Add cloudflare IPs (nginx) SYNC script with cron job"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) install_nginx ;;
        2) remove_nginx ;;
        3) create_vhost ;;
        4) add_cloudflare ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

# Function to install Nginx
install_nginx() {

    local COMMON_NAME="localhost"

    if [ -f "/etc/apt/sources.list.d/nginx.list" ]; then
        echo -e "\nnginx Repo Exists"
    else
        # Adding sury's nginx repo
        echo -e "\nInstalling sury's nginx repo"
        curl -sSL https://packages.sury.org/nginx/README.txt | bash -x
        echo
    fi

    local PACKAGE_NAME="nginx"
    # Check if the package is installed
    if dpkg -l | grep -q "^ii  $PACKAGE_NAME "; then
        echo "$PACKAGE_NAME is already installed."
    else
        echo "$PACKAGE_NAME is not installed. Installing..."
        apt update && apt install -y $PACKAGE_NAME || (echo "Failed to install $PACKAGE_NAME" && return 1)
        echo "$PACKAGE_NAME has been installed."
    fi

    systemctl enable nginx

    # Add log rotation for nginx
    sed -i "s/^\/var\/log\/nginx\/\*\.log/\/var\/www\/*\/logs\/*\/*.log/" /etc/logrotate.d/nginx

    # Create log folder for the main profile
    rm -rf /var/www/html

    # Generate self-signed SSL certificate
    local nginx_key="/etc/ssl/private/nginx.key"
    local nginx_cert="/etc/ssl/certs/nginx.crt"
    # nginx_dhparams2048="/etc/ssl/dhparams2048.pem"
    # openssl dhparam -out ${nginx_dhparams2048} 2048

    if [ ! -f "$nginx_cert" ] || [ ! -f "$nginx_key" ]; then
        echo -e "\nGenerating new self-signed cert for nginx.."
        # rsa:2048
        # ec:<(openssl ecparam -name prime256v1)
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$nginx_key" \
            -out "$nginx_cert" \
            -subj "/CN=$COMMON_NAME"
        # -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORG_UNIT/CN=$COMMON_NAME/emailAddress=$EMAIL"
    fi

    # Backup nginx configs if not already backed up
    if [ ! -f "/etc/nginx/nginx.conf.backup" ]; then
        mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    fi

    if [ -f "$ssl_nginx_snippet" ]; then
        echo "SSL snippet file already exist at $ssl_nginx_snippet"
    else
        echo "ssl_certificate ${nginx_cert};" >"$ssl_nginx_snippet"
        echo "ssl_certificate_key ${nginx_key};" >>"$ssl_nginx_snippet"
        echo "SSL snippet file generated at $ssl_nginx_snippet"
    fi

    cat >"${caching_nginx_snippet}" <<EOFX
location ~* \.(?:ico|gif|jpe?g|png|htc|otf|ttf|eot|woff|woff2|svg|css|js)\$ {
    # expires 30d;
    add_header Cache-Control "max-age=2592000, public";
    open_file_cache max=3000 inactive=120s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 4;
    open_file_cache_errors on;
}
EOFX

    cat >"${common_nginx_snippet}" <<EOFX
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

location ~ /\.(.*) {
    deny all;
}

# Deny access to xmlrpc.php - a common brute force target against Wordpress
location = /xmlrpc.php {
    deny all;
    access_log off;
    log_not_found off;
    return 444;
}
EOFX
    bash -c 'cat <<EOTX >/etc/nginx/nginx.conf
user www-data;
worker_processes auto;
worker_rlimit_nofile 20960;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 2048;
    multi_accept        on; 
}

http {
    fastcgi_buffer_size 16k; # 4k/8k/16k/32k
    fastcgi_buffers 64 16k;
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
    ssl_prefer_server_ciphers off;
    ssl_ciphers "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305";

    # Enable session resumption to improve performance
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1h;
    ssl_session_tickets on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOTX'
    local compression_types='application/atom+xml
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
text/x-component;'

    cat >/etc/nginx/conf.d/gzip.conf <<EOFX
gzip on;
gzip_static on;
gzip_comp_level 5;
gzip_min_length 10000; #10kb
gzip_proxied any;
gzip_vary on;

gzip_types
$compression_types
EOFX
    cat >/etc/nginx/conf.d/brotli.conf <<EOFX
brotli on;
brotli_comp_level 6;
brotli_static on;
brotli_min_length 10000; #10kb

brotli_types
$compression_types
EOFX

    if [ ! -f "/etc/nginx/sites-available/default.disabled" ]; then
        mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.disabled
        rm /etc/nginx/sites-enabled/default
    fi

    # Restart nginx for changes to take effect
    nginx -t && systemctl restart nginx

    echo "Nginx setup completed!"

}

# Function to remove Nginx
remove_nginx() {
    local confirmation
    # Ask for confirmation
    read -rp "This will purge Nginx and its configuration.. Are you sure? (y/n): " confirmation

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

manage_mariadb() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. install_mariadb_server"
        echo "2. install_mariadb_client"
        echo "3. Remove (purge) mariadb"
        echo "4. Backup Database (Dump)"
        echo "5. Restore Database (Dump)"
        echo "6. Create db and its user"
        echo "7. Read mysql/MariaDB config"
        echo "0. Quit"

        read -rp "Enter your choice: " choice
        case $choice in
        1) install_mariadb_server ;;
        2) install_mariadb_client ;;
        3) remove_mariadb ;;
        4) backup_db ;;
        5) restore_db ;;
        6) create_db_user ;;
        7) read_mysql_config ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
    # Backup:
    # mysqldump database_name > backup.sql
    # To back up all the databases:
    # mysqldump -A > backup.sql

    # restore:
    # mysql < backup.sql
    # To restore the data to a specific database, include the database name in the command
    # mysql -D bitnami_app < backup.sql
}

# Function to restore a database from a dump
restore_db() {
    local db_name="$1"
    local dump_file="$2"

    # Check if both arguments are provided
    if [ -z "$db_name" ] || [ -z "$dump_file" ]; then
        read -rp "Enter the database name to restore to: " db_name
        read -rp "Enter the path to the database dump file (supported: gz,xz,zip, or raw): " dump_file

        # Check again if they are empty
        if [ -z "$db_name" ] || [ -z "$dump_file" ]; then
            echo "Both database name and dump file path are required."
            return 1
        fi
    fi

    # Check if the dump file exists
    if [ ! -f "$dump_file" ]; then
        echo "Dump file '$dump_file' does not exist."
        return 1
    fi

    # Determine the compression format based on file extension
    local ext="${dump_file##*.}"
    local decompress_command="cat" # Default to no decompression

    case "$ext" in
    gz) decompress_command="gzip -dc" ;;
    xz) decompress_command="xz -dc" ;;
    zip) decompress_command="unzip -p" ;;
    esac

    # Restore the database dump
    $decompress_command "$dump_file" | $DB_CMD "$db_name"

    echo "Database '$db_name' restored from '$dump_file'."
}

# Function to create a database dump with a timestamped filename
backup_db() {

    local db_name="$1"
    local save_location="$2"
    local timestamp
    local dump_file

    # Check if both arguments are provided
    if [ -z "$db_name" ] || [ -z "$save_location" ]; then
        read -rp "Enter the database name: " db_name
        read -rp "Enter the save location (e.g., /path/to/save): " save_location

        # Check again if they are empty
        if [ -z "$db_name" ] || [ -z "$save_location" ]; then
            echo "Both database name and save location are required."
            return 1
        fi
    fi

    # Generate a timestamp with underscores
    timestamp=$(date +"%Y_%m_%d_%H_%M_%S")

    # Define the dump file name
    dump_file="${db_name}_${timestamp}.sql.xz"

    # Create the database dump and compress it
    $DUMP_CMD "$db_name" | xz -9 >"$save_location/$dump_file"

    echo "Database dump saved as: $save_location/$dump_file"

    # Call the function with command-line arguments if provided
    # Backup_Database "$1" "$2"
}

create_db_user() {
    read -rp "Enter a name for the database: " DB_NAME
    read -rp "Enter a db username: " DB_USER
    read -rp "Enter a password for the db user: " DB_USER_PASS

    # Create a new database and user
    $DB_CMD -e "CREATE DATABASE $DB_NAME;"
    $DB_CMD -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_USER_PASS';"
    $DB_CMD -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    $DB_CMD -e "FLUSH PRIVILEGES;"

    echo "Done."
}

# Function to install MariaDB Server
install_mariadb_server() {
    local install_from
    local PACKAGE_NAME
    local grants_commands
    local confirmation
    local install_repo

    read -rp $'Install from:\n 1. Mariadb repo\n 2. Debian repo\n Choice: ' install_from
    if [[ $install_from == "1" ]]; then
        if [ -f "/etc/apt/sources.list.d/mariadb.list" ]; then
            echo "mariadb Repo Exists"
            read -rp $'Reinstall repo? (y/n): ' confirmation
            if [[ $confirmation != "y" ]]; then
                echo "Skipping adding repo."
            else
                install_repo=1
            fi
        else
            install_repo=1
        fi

        if [[ $install_repo == "1" ]]; then
            # Add MariaDB Repository
            echo "Adding mariadb repo.."
            curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | bash -s -- || {
                echo "Failed adding Mariadb repo"
                return 1
            }
            if [ -f "/etc/apt/sources.list.d/mariadb.list.old_1" ]; then
                rm mariadb.list.old_1
            fi
        fi
    fi

    PACKAGE_NAME="mariadb-server"
    # Check if the package is installed
    if dpkg -l | grep -q "^ii  $PACKAGE_NAME "; then
        echo "$PACKAGE_NAME is already installed."
        return
    else
        echo "$PACKAGE_NAME is not installed. Installing..."
        apt update && apt install -y $PACKAGE_NAME || (echo "Failed to install $PACKAGE_NAME" && return 1)
        echo "$PACKAGE_NAME has been installed."
    fi
    # Prompt for variable values
    # read -rp "Enter the InnoDB buffer pool size (e.g., 512M): " INNODB_BUFFER_POOL_SIZE
    # read -rp "Enter the root password for MariaDB: " DB_ROOT_PASS

    # mysql_secure_installation
    # Secure MariaDB installation
    # mariadb -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED VIA unix_socket WITH GRANT OPTION;FLUSH PRIVILEGES;"
    # mariadb -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASS';"
    # mariadb -e "ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;";
    # mariadb -e "SHOW GRANTS FOR 'root'@'localhost';"

    # Remove anonymous users
    mariadb -e "DELETE FROM mysql.user WHERE User='';"
    # Disallow root login remotely
    mariadb -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    # Remove the test database
    mariadb -e "DROP DATABASE IF EXISTS test;"
    # Reload privilege tables
    mariadb -e "FLUSH PRIVILEGES;"

    echo -e "\nMySQL secure installation completed.\n"

    mariadb -e "SELECT @@character_set_server AS character_set, @@collation_server AS collation;"

    # Show users and their permissions
    mariadb -e "SELECT user, host, plugin, password FROM mysql.user;"
    grants_commands=$(mariadb -e "SELECT GROUP_CONCAT('SHOW GRANTS FOR \'', user, '\'@\'', host, '\';' SEPARATOR ' ') AS query FROM mysql.user;" | grep -v "query")
    mariadb -e "$grants_commands"

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
    local db_host
    local db_user
    local db_pass

    # Install the MariaDB client
    echo "Installing MariaDB client..."
    apt update && apt install -y mariadb-client || (echo "Failed to install mariadb-client" && return 1)

    read -rp "Enter the MariaDB server hostname or IP (without port): " db_host
    read -rp "Enter the database username: " db_user
    read -rps "Enter the password for the database user: " db_pass
    echo

    # Create a configuration file for the MariaDB client
    cat >~/.my.cnf <<EOF
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

# Function to remove MariaDB
remove_mariadb() {
    local confirmation
    local confirmation2
    # Ask for confirmation
    read -rp "This will uninstall MariaDB. Are you sure? (y/n): " confirmation

    if [[ $confirmation != "y" ]]; then
        echo "Aborting."
        return 0
    fi

    # Uninstall MariaDB
    apt remove --purge mariadb-server mariadb-client
    # apt remove --purge mariadb* mysql*
    echo -e "\nRunning dpkg -l | grep -e mysql -e mariadb "
    dpkg -l | grep -e mysql -e mariadb

    read -rp "Do you want to remove configurations by running apt autoremove? (y/n): " confirmation2

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

manage_memcached() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install memcached"
        echo "2. Remove (purge) memcached"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) install_memcached ;;
        2) remove_memcached ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

# Function to install Memcached
install_memcached() {
    # Install Memcached and required dependencies
    apt update && apt install -y memcached libmemcached-tools || (echo "Failed" && return 1)

    # Configure Memcached
    # echo "-m 256" >>/etc/memcached.conf       # Set memory limit to 256MB
    # echo "-l 127.0.0.1" >>/etc/memcached.conf # Bind to localhost
    # echo "-p 11211" >>/etc/memcached.conf     # Use port 11211
    # echo "-U 0" >>/etc/memcached.conf         # Run as the root user
    # echo "-t 4" >>/etc/memcached.conf         # Use 4 threads

    # Restart Memcached
    systemctl restart memcached

    # Enable Memcached to start on system boot
    systemctl enable memcached

    echo "Memcached installation and configuration complete"
}

# Function to remove Memcached
remove_memcached() {
    local confirmation

    # Ask for confirmation
    read -rp "This will purge Memcached and its configuration.. Are you sure? (y/n): " confirmation

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

# Function to install PHPMyAdmin
install_phpmyadmin() {
    local vuser
    local domain
    local web_dir
    local PHPMYADMIN_VERSION
    local INSTALL_DIR
    local dbadmin_pass
    local pmapass
    local BLOWFISH_SECRET

    while true; do
        # Prompt for the username
        read -rp "Enter vhost username: " vuser
        # Prompt for the domain name
        read -rp "Enter vhost domain name (e.g., example.com): " domain

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

    read -rp "Make sure mariadb connection is configured and press enter"
    read -rp "Enter new password for dbadmin user: " dbadmin_pass
    # read -rp "Enter new password for management user (pma)" pmapass
    # Generate a password with default length
    pmapass=$(gen_pass)
    echo "pmapass: $pmapass"

    # Create Database User for phpMyAdmin.
    # $DB_CMD -e "GRANT ALL PRIVILEGES ON *.* TO 'dbadmin'@'localhost' IDENTIFIED BY '${dbadmin_pass}' WITH GRANT OPTION;FLUSH PRIVILEGES;"
    # Fix for AWS managed databses (RDS):
    $DB_CMD -e "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, PROCESS, REFERENCES, INDEX, ALTER, SHOW DATABASES, CREATE TEMPORARY TABLES, LOCK TABLES, REPLICATION SLAVE, REPLICATION CLIENT, CREATE VIEW, EVENT, TRIGGER, SHOW VIEW, DELETE HISTORY, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EXECUTE ON *.* TO 'dbadmin'@'localhost' IDENTIFIED BY '${dbadmin_pass}' WITH GRANT OPTION;FLUSH PRIVILEGES;"

    # Create Database User for phpMyAdmin management (for multi user use).
    $DB_CMD -e "GRANT SELECT, INSERT, UPDATE, DELETE ON phpmyadmin.* TO 'pma'@'localhost' IDENTIFIED BY '${pmapass}';"

    # Download and Extract phpMyAdmin archive
    mkdir -p "${INSTALL_DIR}"

    if [ ! -f "phpMyAdmin-${PHPMYADMIN_VERSION}-english.tar.gz" ]; then
        wget "https://files.phpmyadmin.net/phpMyAdmin/${PHPMYADMIN_VERSION}/phpMyAdmin-${PHPMYADMIN_VERSION}-english.tar.gz"

    fi

    if tar -xzvf "phpMyAdmin-${PHPMYADMIN_VERSION}-english.tar.gz" --strip-components=1 -C "${INSTALL_DIR}" >/dev/null 2>&1; then
        echo "Extraction successful."
    else
        echo "Extraction failed."
        return
    fi

    # Create config file
    cp "${INSTALL_DIR}/config.sample.inc.php" "${INSTALL_DIR}/config.inc.php"

    # Load phpmyadmin database into the database
    $DB_CMD <"${INSTALL_DIR}/sql/create_tables.sql"

    # Generate a random blowfish secret for enhanced security
    BLOWFISH_SECRET=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)
    sed -i "s|cfg\['blowfish_secret'\] = ''|cfg\['blowfish_secret'\] = '${BLOWFISH_SECRET}'|" "${INSTALL_DIR}/config.inc.php" || echo "Error on setting blowfish_secret"

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

cleanUp() {
    apt autoremove
    apt autoclean
    apt update
    apt clean
}

install_std_packages() {
    local confirmation

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
        bc \
        jq \
        dmidecode

    read -rp "Remove Exim4? (y/n) " confirmation
    if [[ "$confirmation" == "y" ]]; then
        echo -e "\nRunning apt purge exim4-*\n"
        apt -y purge exim4-*
    fi

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
    local sshd_config="/etc/ssh/sshd_config"

    # Update package lists & Install SSH server
    apt update && apt install openssh-server -y || return 1

    # Backup the original configuration
    if [ -e "${sshd_config}_backup" ]; then
        echo "Backup file '${sshd_config}_backup' already exists."
    else
        cp "$sshd_config" "${sshd_config}_backup"
    fi

    # Enable root login (not recommended for production)
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' "$sshd_config"
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' "$sshd_config"

    # Disable root's ability to use password-based authentication
    # sed -i 's/PermitRootLogin yes/PermitRootLogin without-password/' "$sshd_config"

    # Set SSH port to 4444
    sed -i 's/#Port 22/Port 4444/' "$sshd_config"

    # Disable password authentication (use key-based authentication)
    # sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$sshd_config"

    # Enable PasswordAuthentication
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' "$sshd_config"
    sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' "$sshd_config"
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' "$sshd_config"

    # Allow only specific users or groups to log in via SSH (replace with your username)
    # echo "AllowUsers your_username" >> "$sshd_config"

    # Restart SSH service (for changes to take effect immediately)
    systemctl restart sshd

}

config_system() {
    local restore_choice
    local bashrc="/etc/bash.bashrc"

    echo "Setting server's timezone to Asia/Dubai"
    timedatectl set-timezone Asia/Dubai || echo "Failed to set timezone"
    echo ""
    read -rp "Do you want to restore the original configuration from the backup? (y/n): " restore_choice
    if [ "$restore_choice" == "y" ]; then
        # Check if Backup exist
        if [ -e "${bashrc}.backup" ]; then
            if cp ${bashrc}.backup ${bashrc}; then
                echo "Original configuration has been restored."
            else
                echo "Failed to restore original configuration."
            fi
        else
            echo "Backup file '${bashrc}.backup' doesn't exists."
        fi
        return
    fi

    # Backup the original configuration
    if [ -e "${bashrc}.backup" ]; then
        echo "Skipping Backup (already exists) '${bashrc}.backup'."
    else
        echo -e "Creating backup (bash.bashrc.backup)...\n"
        cp ${bashrc} ${bashrc}.backup
    fi

    # Define the new PS1 prompt with color codes
    # hetzner uses red yeloow cyan yellow pink
    # Define colors using ANSI escape codes
    local RED="\[\033[01;31m\]"
    local GREEN="\[\033[01;32m\]"
    local YELLOW="\[\033[01;33m\]"
    local PINK="\[\033[01;35m\]"
    local CYAN="\[\033[01;36m\]"
    local RESET="\[\033[0m\]"

    # Set the customized PS1 variable
    local CUSTOM_PS1="'\${debian_chroot:+(\$debian_chroot)}${RED}\\u${YELLOW}@${CYAN}\\h ${YELLOW}\\w ${PINK}\\\$ ${RESET}'"
    local escaped_PS1
    escaped_PS1=$(echo "$CUSTOM_PS1" | sed 's/[\/&]/\\&/g')

    # Replace the old PS1 line with the new one
    sed -i "s/PS1=.*/PS1=${escaped_PS1}/" ${bashrc}

    # "echo \"IP: \$(hostname -I | awk '{print \$1}') \$(ip -o -4 route show to default | awk '{print $5}')\""

    local aliases=(
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
        # local escaped_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g' -e 's/["'\'']/\\&/g')
        if ! grep -qF "$value" "${bashrc}"; then
            echo "$value" >>"${bashrc}"
        fi
    done

    # Notify user about the changes
    echo "PS1 prompt, aliases, exports, and history settings have been updated for all users."

    cat >"/etc/issue" <<EOFX
\e{lightblue}\s \m \r (Server Time: \t\e{reset})
\e{lightblue}\S{PRETTY_NAME} \v\e{reset}
\e{lightgreen}\n.\o : \4\e{reset}
EOFX
    echo -n "" >/etc/motd
    chmod -x /etc/update-motd.d/10-uname

    local sinfo_script="/usr/local/bin/sinfo"
    # Use a here document to create the script content
    cat >"$sinfo_script" <<'EOF'
#!/bin/bash

# Get Script version
script_version=$(Servo.sh version)

# Get IP and Route
IP_Add="$(hostname -I | awk '{print $1}') $(ip -o -4 route show to default)"

# Get OS information
os_info=$(lsb_release -d -s 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2- | tr -d '"')' '$(cat /etc/debian_version)

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

# Get Machine information
machine_info=$(dmidecode -t system | grep -E "Manufacturer:|Product Name:" | awk -F': ' '{print $2}' | tr '\n' ' ')

# lspci -nn | grep -i ethernet

# Print the gathered information
echo -e " \e[91mServo V:\e[0m $script_version"
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
echo -e " \e[91mMachine:\e[0m $machine_info"
EOF

    echo "Script generated and saved as $sinfo_script"
    chmod +x "$sinfo_script"

}

add_cloudflare() {
    local cloudflare_script="/usr/local/bin/cloudflare_sync"
    cat >"$cloudflare_script" <<'EOFX'
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
EOFX

    chmod 700 "$cloudflare_script"

    echo "Fetching IPs from cloudflare.."
    cloudflare_sync
    # Add daily cron job
    echo "Adding cron job.."

    echo "30 1 * * * root ${cloudflare_script}" >"${cron_dir}cloudflare"
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
    local CONFIG_PARAMS=(
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
    local param
    # Loop through each configuration parameter and retrieve its value
    for param in "${CONFIG_PARAMS[@]}"; do
        local value
        value=$($DB_CMD -BNe "SHOW VARIABLES LIKE '$param';" | awk '{print $2}')
        echo -e "\e[91m${param}=\e[0m $value"
    done

    $DB_CMD -e "SELECT user, host, plugin, password FROM mysql.user;"
    grants_commands=$($DB_CMD -e "SELECT GROUP_CONCAT('SHOW GRANTS FOR \'', user, '\'@\'', host, '\';' SEPARATOR ' ') AS query FROM mysql.user;" | grep -v "query")
    $DB_CMD -e "$grants_commands"
}

create_vhost() {
    local domain
    local vuser
    local REPLY
    local PS3

    while true; do
        # Prompt for the domain name
        read -rp "Enter the domain name (e.g., example.com): " domain

        # Check if the domain name follows common rules
        if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo "Invalid domain name format. Please enter a valid domain name (e.g., example.com)."
        fi
    done

    while true; do
        # Prompt for the username
        read -rp "Enter new username: " vuser
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
        useradd -N -m -s "$(which bash)" -d "/var/www/${vuser}" "${vuser}"
        rm -rf /var/www/"${vuser}"/{.bashrc,.profile,.bash_logout}
        passwd -l "$vuser"
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
            return 0
            ;;
        *) echo "Invalid choice. Please choose 1 or 2." ;;
        esac
    done

    # Create vhost directories
    basedir="/var/www/${vuser}/"
    mkdir -p "${basedir}/logs/${domain}"
    mkdir -p "${basedir}/${domain}/public/"
    chmod 710 "${basedir}"
    chown "${vuser}:www-data" "${basedir}"
    chown -R "${vuser}:users" "${basedir}"*

    # Generate php config
    generate_php_conf "${vuser}" "${domain}" "${phpVer}"

    # Generate nginx config
    generate_nginx_vhost "${vuser}" "${domain}" "${phpVer}"

    # Enable nginx site
    if [ -L "/etc/nginx/sites-enabled/${vuser}-${domain}.conf" ]; then
        echo -e "\nSymbolic link '/etc/nginx/sites-enabled/${vuser}-${domain}.conf' already exists."
    else
        if [ -e "/etc/nginx/sites-enabled/${vuser}-${domain}.conf" ]; then
            echo -e "\nqFile or directory with the name '/etc/nginx/sites-enabled/${vuser}-${domain}.conf' already exists. Cannot create the symbolic link."
        else
            ln -s "/etc/nginx/sites-available/${vuser}-${domain}.conf" /etc/nginx/sites-enabled/
            echo -e "\nSymbolic link '/etc/nginx/sites-enabled/${vuser}-${domain}.conf' created to '/etc/nginx/sites-available/${vuser}-${domain}.conf'"
        fi
    fi
    nginx -t && systemctl reload nginx
}

generate_nginx_vhost() {
    local vuser="$1"
    local domain="$2"
    local phpVer="$3"
    local server_name
    local is_default

    read -rp "Is this default domain? (y/n) " is_default
    if [[ "$is_default" == "y" ]]; then
        server_name="server_name _"
    else
        server_name="server_name $domain www.${domain}"
    fi

    cat >"/etc/nginx/sites-available/${vuser}-${domain}.conf" <<EOTX
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
    include ${caching_nginx_snippet};
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
EOTX
}

install_more_packages() {
    apt update && apt install -y build-essential software-properties-common python3 python3-pip

    echo "More Packages installation complete."
}

install_docker() {
    # Add Docker's official GPG key:
    apt-get update && apt-get install -y ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Add the repository to Apt sources:
    local architecture
    architecture=$(dpkg --print-architecture)
    local codename
    codename=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)

    echo "deb [arch=$architecture signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $codename stable" |
        tee /etc/apt/sources.list.d/docker.list >/dev/null
    apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

remove_docker() {
    # Remove the official docker
    apt purge docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    # for pkg in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; do apt-get -y remove $pkg; done
    # Remove debian's docker
    # for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do apt-get -y remove $pkg; done
    apt purge docker.io docker-doc docker-compose podman-docker containerd runc

}

manage_docker() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install docker"
        echo "2. Remove (purge) docker"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) install_docker ;;
        2) remove_docker ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

manage_wordpress() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install Wordpress"
        echo "0. Quit"

        read -rp "Enter your choice: " choice
        case $choice in
        1) install_wordpress ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

install_wordpress() {
    local install_dir
    local local_user
    local wpURL
    # Prompt for the installation directory
    read -rp "Enter the full path where you want to install WordPress (e.g., /var/www/html/myblog): " install_dir
    read -rp "Enter the user that will run wp: " local_user
    read -rp "Enter the URL to access Wordpres: (e.g., https://example.com) " wpURL

    # Verify the installation directory
    if [ ! -d "$install_dir" ]; then
        echo "The specified directory does not exist."
        exit 1
    fi

    if [ -f "/usr/local/bin/wp" ]; then
        echo " Notice: wp-cli already installed"
    else
        curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
        chmod +x wp-cli.phar
        mv wp-cli.phar /usr/local/bin/wp
    fi

    # Database name, user, and admin user
    local hex
    hex=$(openssl rand -hex 3)
    local DB_NAME="wp_${hex}"
    local DB_USER="wp_${hex}"
    local DB_PASS
    DB_PASS=$(openssl rand -base64 12)
    local WP_ADMIN_USER="admin"
    local WP_ADMIN_PASS
    WP_ADMIN_PASS=$(openssl rand -base64 12)

    local WP_ADMIN_EMAIL="user@example.com"
    local WP_URL="${wpURL}"
    local WP_TITLE="Your Site Title"

    # Create MySQL database and user
    $DB_CMD <<MYSQL_SCRIPT
CREATE DATABASE $DB_NAME DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

    # Download WordPress using WP-CLI
    echo -e "\n Downloading WordPress using WP-CLI"
    sudo -u "${local_user}" -s wp core download --path="${install_dir}" --locale=en_US

    # Create wp-config.php file
    echo -e "\n Creating wp-config.php file"
    sudo -u "${local_user}" -s wp config create \
        --path="${install_dir}" \
        --dbname="$DB_NAME" \
        --dbuser="$DB_USER" \
        --dbpass="$DB_PASS" \
        --locale=en_US

    # Install WordPress
    echo -e "\n Installing WordPress"
    sudo -u "${local_user}" -s wp core install \
        --path="${install_dir}" \
        --url="$WP_URL" \
        --title="$WP_TITLE" \
        --admin_user="$WP_ADMIN_USER" \
        --admin_password="$WP_ADMIN_PASS" \
        --admin_email="$WP_ADMIN_EMAIL"

    echo -e "\n Installing Plugins"
    # sudo -u "${local_user}" -s wp plugin install all-in-one-seo-pack all-in-one-wp-migration amp google-analytics-for-wordpress jetpack w3-total-cache wp-mail-smtp --path="$install_dir"
    sudo -u "${local_user}" -s wp plugin install amp google-analytics-for-wordpress wp-mail-smtp wordfence --path="$install_dir"
    echo -e "\n Activating Plugins"
    # sudo -u "${local_user}" -s wp plugin activate jetpack --path="$install_dir"

    cat >>"${install_dir}/wp-config.php" <<'EOFX'
/**
 * Disable pingback.ping xmlrpc method to prevent WordPress from participating in DDoS attacks
 * More info at: https://docs.bitnami.com/general/apps/wordpress/troubleshooting/xmlrpc-and-pingback/
 */
if ( !defined( 'WP_CLI' ) ) {
	// remove x-pingback HTTP header
	add_filter("wp_headers", function($headers) {
		unset($headers["X-Pingback"]);
		return $headers;
	});
	// disable pingbacks
	add_filter( "xmlrpc_methods", function( $methods ) {
		unset( $methods["pingback.ping"] );
		return $methods;
	});
}
EOFX

    # wp_user_create=$(wp user create "$admin_user" admin@example.com --user_pass="$admin_password" --path="$install_dir")
    echo "#############################################################"

    # if [[ $wp_user_create == *"Success"* ]]; then
    echo "WordPress is now installed and configured in $install_dir."
    echo "username: $WP_ADMIN_USER | password: $WP_ADMIN_PASS"
    echo "You can access it in your web browser to complete the setup."
    # else
    # echo "Error creating the WordPress admin user."
    # exit 1
    # fi
    echo "#############################################################"

}

# Function to fix files and folders permissions
fix_permissions() {

    # chown -R user:group TARGET
    # find TARGET -type d -exec chmod 775 {} \;
    # find TARGET -type f -exec chmod 664 {} \;
    # chmod 640 TARGET/wp-config.php

    local target="$1"
    local user="$2"
    local group="$3"

    # Prompt for input if any argument is missing
    if [ -z "$target" ]; then
        read -rp "Enter the target directory: " target
    fi

    if [ -z "$user" ]; then
        read -rp "Enter the user: " user
    fi

    if [ -z "$group" ]; then
        read -rp "Enter the group: " group
    fi

    # Check if all arguments are provided
    if [ -z "$target" ] || [ -z "$user" ] || [ -z "$group" ]; then
        echo "Usage: fix_permissions <target> <user> <group>"
        return 1
    fi

    # Fix ownership
    chown -R "$user:$group" "$target"

    # Set directory permissions to 775 and file permissions to 664
    find "$target" -type d -exec chmod 775 {} \;
    find "$target" -type f -exec chmod 664 {} \;

    echo "Permissions fixed for '$target'."
}

# Function to comment or uncomment lines in a config file
comment_uncomment() {
    local search_pattern="$1"
    local config_file="$2"
    local comment_uncomment="$3"

    # Check if the config file exists
    if [ ! -f "$config_file" ]; then
        echo "Error: Config file '$config_file' not found."
        return 1
    fi

    # Define the AWK script
    local awk_script='
  {
    # Count leading whitespace (tabs or spaces)
    whitespace_count = match($0, /^[ \t]*/)
    whitespace = substr($0, RSTART, RLENGTH)
    line = substr($0, RLENGTH + 1)

    # Check if the line matches the search pattern
    if ($0 ~ search_pattern) {
      if (comment_uncomment == "comment" && substr(line, 1, 1) != "#") {
        # Comment the line and add a space after the comment symbol if needed
        if (substr(line, 1, 1) != " ") {
          line = " " line
        }
        $0 = whitespace "#" line
      } else if (comment_uncomment == "uncomment") {
        # Uncomment the line and remove all preceding comment symbols and spaces
        sub(whitespace "[# ]*", whitespace, $0)
      }
    }

    # Print the modified line
    print
  }
  '

    # Use AWK to process the config file and redirect the output to a temporary file
    awk -v search_pattern="$search_pattern" -v comment_uncomment="$comment_uncomment" "$awk_script" "$config_file" >"$config_file.tmp" || {
        echo " Error in awk in comment_uncomment IN '$config_file'"
        return 1
    }

    # Replace the original config file with the temporary file
    mv "$config_file.tmp" "$config_file" || {
        echo " Error in mv in comment_uncomment IN '$config_file'"
        return 1
    }

    # echo "Success ${comment_uncomment}ing IN '$config_file'"
    echo "Success"

    # Example usage:
    # comment_uncomment "search_pattern" "/path/to/config/file" "comment"
    # comment_uncomment "search_pattern" "/path/to/config/file" "uncomment"
}

# Function to add a new line under a pattern with correct indentation
add_line_under_pattern() {
    local pattern_to_match="$1"
    local config_file="$2"
    local new_line="$3"

    # Check if the config file exists
    if [ ! -f "$config_file" ]; then
        echo "Config file not found: $config_file"
        return 1
    fi

    # Escape special characters in the pattern
    local escaped_pattern
    escaped_pattern=$(sed 's/[][\/.^$*]/\\&/g' <<<"$pattern_to_match")

    # Get the indentation of the pattern line
    local indentation
    indentation=$(sed -n "/$escaped_pattern/{s/^\([[:space:]]*\).*$/\1/;p;q}" "$config_file")

    # Check if the new line already exists after the pattern line
    if grep -qFx "${indentation}${new_line}" "$config_file"; then
        echo "The new line already exists after the pattern. No duplicate line added."
    else
        # Use sed to insert the new line under the pattern with the same indentation
        sed -i "\%$escaped_pattern%a\\${indentation}${new_line}" "$config_file" && echo "Success" || echo "Failed: ADDING '$new_line' UNDER '$pattern_to_match' IN '$config_file' "

    fi

    # Example usage:
    # add_line_under_pattern "include /etc/nginx/snippets/ssl" /path/to/your/config/file.conf "new_line_to_append"

}
######### Certbot Start #########
# Function to configure Cloudflare
certbot_create_cloudflare_config() {
    local cloudflare_email
    local cloudflare_api_key
    read -rp "Enter your Cloudflare email: " cloudflare_email
    read -rp "Enter your Cloudflare API Token: " cloudflare_api_key

    config_name="$cloudflare_email"

    # Create the Cloudflare configuration
    mkdir -p "${cloudflare_config_dir}/$config_name"
    cat >"${cloudflare_config_dir}/${config_name}.ini" <<EOF
dns_cloudflare_api_token = $cloudflare_api_key
EOF
    chmod 600 "${cloudflare_config_dir}/${config_name}.ini"
}

# Function to list existing Cloudflare configurations and return the selected name
certbot_list_cloudflare_config() {
    local config_names=()
    echo "Existing Cloudflare configurations:"
    i=1
    for config in "${cloudflare_config_dir}"/*; do
        if [ -f "$config" ]; then
            local config_name
            config_name=$(basename "$config")
            config_names+=("$config_name")
            echo -e "\n \033[32m$i. $config_name\033[0m"
            cat "$config"
            ((i++))
        fi
    done
}

# Function to get a new or renew a certificate
get_certbot_certificate() {
    local domain_name
    read -rp "Enter your domain name (e.g., example.com): " domain_name

    # Check if any Cloudflare configurations exist
    local selected_config
    selected_config=$(select_from_dir "${cloudflare_config_dir}")
    echo "Selected file: $selected_config"

    read -rp "Press Enter to continue..."

    # Request the certificate (For debugging add: --dry-run -vvv)
    if certbot certonly -n --dns-cloudflare -d "${domain_name},*.${domain_name}" --dns-cloudflare-propagation-seconds 60 --dns-cloudflare-credentials "${selected_config}"; then
        mkdir -p /etc/ssl
        cp -r "/etc/letsencrypt/live/${domain_name}" /etc/ssl/
    fi

    # For CURL
    # zid 1c2a1aaa99b81e8ecfae3d1e81e52e60
    # curl -X GET "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name=_acme-challenge.domain.com" \
    #   -H "Authorization: Bearer {api_token}" \
    #   -H "Content-Type:application/json" | jq .

}

set_nginx_cert() {

    local nginx_conf_dir="/etc/nginx/sites-available"
    local ssl_dir="/etc/ssl"

    nginx_config=$(select_from_dir "$nginx_conf_dir")
    echo "Selected config: $nginx_config"

    local domain_name
    domain_name=$(get_domain_from_nginx_conf_path "${nginx_config}")
    [[ -n $domain_name ]] || {
        echo "$domain_name"
        return 1
    }

    echo -e "\n Domain: ${domain_name}\n"

    mkdir -p "/etc/nginx/snippets/"
    snippet_path="/etc/nginx/snippets/ssl-$domain_name-snippet.conf"

    cat >"$snippet_path" <<EOFX
ssl_certificate $ssl_dir/$domain_name/fullchain.pem;
ssl_certificate_key $ssl_dir/$domain_name/privkey.pem;
EOFX

    # Add or update the include line in the nginx configuration
    if grep -q "include $snippet_path;" "$nginx_config"; then
        comment_uncomment "include $snippet_path;" "$nginx_config" uncomment
    else
        add_line_under_pattern "include ${ssl_nginx_snippet};" "$nginx_config" "include $snippet_path;"
    fi
    comment_uncomment "include ${ssl_nginx_snippet};" "$nginx_config" comment
    nginx -t && systemctl reload nginx
}

get_domain_from_nginx_conf_path() {
    local path="$1"

    # Extract the base filename
    local domain_name="${path##*/}"

    # Remove the file extension
    domain_name="${domain_name%.*}"

    # Get domain with subomain
    # domain_name="${base_filename##*-}"

    # Get domain only - Use awk to split the string by hyphen and capture the last part after the last dot
    domain_name=$(echo "$domain_name" | awk -F'[-.]' '{print $(NF-1) "." $NF}')

    domain_name=$(echo "$domain_name" | awk -F'[-.]' '{print $(NF-1) "." $NF}')

    if is_valid_domain "$domain_name"; then
        echo "$domain_name"
        return 0
    else
        echo "${domain_name} is not a valid domain."
        return 1
    fi
}

# Function to revert to self-signed certificate
revert_to_self_signed() {
    # read -rp "Enter the domain name to revert to a self-signed certificate (e.g., example.com): " domain_name
    echo "Select nginx config"
    local nginx_config
    nginx_config=$(select_from_dir "/etc/nginx/sites-available/")
    echo "Selected config: $nginx_config"

    local domain_name
    domain_name=$(get_domain_from_nginx_conf_path "${nginx_config}")
    [[ -n $domain_name ]] || {
        echo "$domain_name"
        return 1
    }

    # nginx_config="/etc/nginx/sites-available/$domain_name"

    if [ -f "$nginx_config" ]; then
        local snippet_path="/etc/nginx/snippets/ssl-$domain_name-snippet.conf"

        # echo "Commenting: include $snippet_path;"
        comment_uncomment "include $snippet_path;" "$nginx_config" comment

        comment_uncomment "include ${ssl_nginx_snippet};" "$nginx_config" uncomment
        nginx -t && systemctl reload nginx

        # echo "Reverted $domain_name to use the self-signed certificate."
    else
        echo "Nginx configuration file not found."
    fi
}

install_certbot() {
    # Check if Certbot is installed
    if ! command -v certbot &>/dev/null; then
        echo "Certbot is not installed. Installing Certbot..."
        apt-get update && apt-get -y install certbot python3-certbot-dns-cloudflare
    fi
}

manage_certbot() {
    local choice
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. Install Certbot"
        echo "2. Get/Renew Certificate"
        echo "3. Set nginx Cert"
        echo "4. Revert nginx to Self-Signed Certificate"
        echo "5. List cloudflare configs"
        echo "6. Create cloudflare config"
        echo "0. Quit"
        echo -e "\033[0m"

        read -rp "Enter your choice: " choice

        case $choice in
        1) install_certbot ;;
        2) get_certbot_certificate ;;
        3) set_nginx_cert ;;
        4) revert_to_self_signed ;;
        5) certbot_list_cloudflare_config ;;
        6) certbot_create_cloudflare_config ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}
######### Certbot END #########

list_users() {
    local RED='\033[1;31m'
    local GREEN='\033[1;32m'
    local YELLOW='\033[1;33m'
    local RESET='\033[0m'
    local login_status
    local can_login

    # Create a header for the table
    printf "${GREEN}%-20s%-20s%-20s%-20s%-20s${RESET}\n" "Username" "User ID" "Group ID" "Home Directory" "Can Login"

    # Use the awk command to extract user information and format it
    awk -F: 'BEGIN {OFS="\t"} {print $1, $3, $4, $6}' /etc/passwd |
        while IFS=$'\t' read -r username uid gid home; do
            can_login=$(awk -F: -v user="$username" '$1 == user {print $2}' /etc/shadow)
            if [[ "$can_login" == *":"* || "$can_login" == "!"* ]]; then
                login_status="${RED}No${RESET}"
            else
                login_status="${GREEN}Yes${RESET}"
            fi
            printf "${YELLOW}%-20s${RESET}%-20s%-20s%-20s${login_status}\n" "$username" "$uid" "$gid" "$home"
        done

}

list_groups() {
    local GREEN='\033[1;32m'
    local YELLOW='\033[1;33m'
    local RESET='\033[0m'
    local gid
    local members

    # Create a header for the table
    printf "${GREEN}%-20s%-20s%-20s${RESET}\n" "Group Name" "Group ID" "Group Members"

    # Iterate through each group, list members, and sort by group name
    for groupname in $(cut -d: -f1 /etc/group | sort); do
        gid=$(getent group "$groupname" | cut -d: -f3)
        members=$(members "$groupname" 2>/dev/null)

        if [ -z "$members" ]; then
            members="N/A"
        fi

        printf "${YELLOW}%-20s${RESET}%-20s${members}\n" "$groupname" "$gid"
    done

}

manage_users() {

    # Check if the 'members' command is available
    if ! command -v members >/dev/null 2>&1; then
        echo "The 'members' command is not installed. Installing..."
        apt update && apt-get install -y members
    fi
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. List Users"
        echo "2. List Groups"
        echo "3. "
        echo "0. Quit"
        echo -e "\033[0m"

        read -rp "Enter your choice: " choice

        case $choice in
        1) list_users ;;
        2) list_groups ;;
        3) ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

manage_rsync() {

    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. Install rsync & add log rotation"
        echo "2. Rsync push letsencrypt"
        echo "0. Quit"
        echo -e "\033[0m"

        read -rp "Enter your choice: " choice

        case $choice in
        1) install_rsync ;;
        2) rsync_push_letsencrypt ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

install_rsync() {
    # Check if the 'rsync' command is available
    if ! command -v rsync >/dev/null 2>&1; then
        echo "The 'rsync' command is not installed. Installing..."
        apt update && apt-get install -y rsync
    fi

    echo -e "\nAdding log rotation.."
    cat >/etc/logrotate.d/rsync <<EOFX
/var/log/rsync/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root root
}
EOFX
    mkdir /var/log/rsync
    chown root:root /var/log/rsync
    chmod 640 /var/log/rsync
}

rsync_push_letsencrypt() {
    local path
    path=$(select_from_dir "/etc/letsencrypt/live/")
    local domain="${path##*/}"
    local host
    local port
    local user
    read -rp "Enter host or IP: " host
    read -rp "Enter port: " port
    read -rp "Enter user (default root): " user
    if [ -z "$user" ]; then
        user=root
    fi
    rsync --log-file="/var/log/rsync/letsencrypt.log" --stats -uavhzPL "/etc/letsencrypt/live/${domain}" -e "ssh -p $port" "${user}@${host}":/etc/ssl/
    echo "Log written to '/var/log/rsync/letsencrypt.log'"
}

version() {
    echo ${servo_version}
}

main() {
    if [ $# -ge 1 ]; then
        local function_name="$1"
        shift # Remove the function name from the argument list
        "$function_name" "$@"
    else
        # Define an array where each element contains "function|option"
        local menu=(
            "exit                       | Exit"
            "check_for_update           | Update script"
            "install_configure_SSH      | Install & configure SSH (port 4444, enable root)"
            "install_std_packages       | Install Standard Packages"
            "config_system              | Configure terminal and system banners"
            "manage_php                 | Manage PHP 7 and 8"
            "manage_nginx               | Manage Nginx"
            "manage_mariadb             | Manage MariaDB"
            "manage_memcached           | Manage Memcached"
            "install_phpmyadmin         | Install PHPMyAdmin"
            "manage_docker              | Manage Docker"
            "manage_wordpress           | Manage Wordpress"
            "install_more_packages      | Install (build-essential software-properties-common python3)"
            "fix_permissions            | Set Files/Folders Permissions"
            "manage_certbot             | Manage Certbot"
            "manage_users               | Manage Users"
            "manage_rsync               | Manage Rsync"
            "cleanUp                    | Clean up (autoremove, autoclean, update)"
        )
        # Alternative way of spliting menu
        # awk -F '|' '{print $2}' | sed 's/^[[:space:]]*//'
        # awk -F '|' '{print $1}' | sed 's/[[:space:]]*$//'

        # Display the menu
        while true; do
            clear # Clear the screen
            echo -e "\033[93m===== Farid's Setup Menu v${servo_version} =====\033[92m"

            # Iterate through the menu array and display menu options with numbers
            local index
            for index in "${!menu[@]}"; do
                option_description=$(echo "${menu[index]}" | sed -E 's/ +\| */\t/g' | cut -f 2)
                echo "$((index)). $option_description"
            done

            echo -e "\033[93mAvailable functions:\033[94m"
            echo "  backup_db [database_name] [save_location]"
            echo "  restore_db [database_name] [db_filename]"
            echo "  fix_permissions <target> <user> <group>"
            echo -e "\033[93m===============================\033[0m"

            # Prompt the user for a choice
            local choice
            read -rp "Enter your choice (0-$((${#menu[@]} - 1))): " choice
            if [[ ! $choice =~ ^[0-9]+$ ]]; then
                continue
            fi
            ((choice = 10#$choice))
            # Check if the choice is within a valid range
            if [ "$choice" -lt ${#menu[@]} ]; then
                selected_option="${menu[choice]}"
                function_name=$(echo "$selected_option" | sed -E 's/ +\| */\t/g' | cut -f 1)
                $function_name
                read -n 1 -srp "Press any key to continue..."
            fi
        done
    fi
}

main "$@"
# Wordpress
# define('WP_MEMORY_LIMIT', '256M');
# wp plugin list
# wp plugin deactivate --all
# wp plugin deactivate [plugin_name]
# wp theme activate twentynineteen
# "plugins" folder change the folder name to something like "plugins_disabled"
# To identify the problematic plugin, (e.g., plugin-name to _plugin-name)
# define('WP_DEBUG', true);
# define('WP_DEBUG_LOG', true);
# define('WP_DEBUG_DISPLAY', false);
# @ini_set('display_errors',0);
