#!/bin/bash
# shellcheck disable=SC2016,SC2119,SC2155,SC2206,SC2207,SC2254,SC2086,SC1091
# Shellcheck ignore list:
#  - SC2016: Expressions don't expand in single quotes, use double quotes for that.
#  - SC2119: Use foo "$@" if function's $1 should mean script's $1.
#  - SC2155: Declare and assign separately to avoid masking return values.
#  - SC2206: Quote to prevent word splitting, or split robustly with mapfile or read -a.
#  - SC2207: Prefer mapfile or read -a to split command output (or quote to avoid splitting).
#  - SC2254: Quote expansions in case patterns to match literally rather than as a glob.
#
servo_version="0.8.9"
# curl -H "Cache-Control: no-cache" -sS "https://raw.githubusercontent.com/fa1rid/linux-setup/main/setup_menu/Servo.sh" -o /usr/local/bin/Servo.sh && chmod +x /usr/local/bin/Servo.sh

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    # Bash programmable completion
    _completion() {
        local cur prev cword opts #words
        # COMPREPLY=($words)
        # return
        _init_completion -n = || return

        opts="compress decompress db_backup db_restore perm_set gen_pass rsync_push_letsencrypt rsync_push_ssl"
        if ((cword == 1)); then
            COMPREPLY=($(compgen -W "$opts" -- "$cur"))
            return
        fi

        if ((cword == 2)); then
            case "${prev}" in
            compress)
                local formats="zip tar gz bz2 xz 7z"
                COMPREPLY=($(compgen -W "${formats}" -- ${cur}))
                return
                ;;
                # decompress)
                #     # printf "Hint: You need to pass the path.\n"
                #     # Implement dynamic completions here based on available files
                #     return
                # ;;
            *) ;;
            esac
        fi
        _filedir
        # COMPREPLY+=($(compgen -o plusdirs -A file "$cur"))

    }
    complete -F _completion Servo.sh
    return
    # complete -p Servo.sh
    # complete -r Servo.sh
fi
# Check if the script is run as root
# if [[ $EUID -ne 0 ]]; then
#     echo "This script must be run as root."
#     exit 1
# fi
if [[ ! -e /usr/share/bash-completion/completions/Servo.sh ]]; then
    ln -s /usr/local/bin/Servo.sh /usr/share/bash-completion/completions/
fi
#########################################

cron_dir="/etc/cron.d"
cron_dir_user="$HOME/.cron"
cloudflare_config_dir="/etc/cloudflare"
ssl_nginx_snippet="/etc/nginx/snippets/ssl.conf"
common_nginx_snippet="/etc/nginx/snippets/common.conf"
caching_nginx_snippet="/etc/nginx/snippets/caching.conf"
# default_domain="domain.local"
# default_user="default"

PHP_Versions=("7.4" "8.2")

# Check if MariaDB is installed
if command -v mariadb &>/dev/null; then
    DB_CMD="mariadb"
elif command -v mysql &>/dev/null; then
    DB_CMD="mysql"
fi

if command -v mariadb-dump &>/dev/null; then
    DUMP_CMD="mariadb-dump"
elif command -v mysqldump &>/dev/null; then
    DUMP_CMD="mysqldump"
fi

#########################################

path_exists() {
    local path=$1
    if [ -e "$path" ]; then
        return 0
    else
        return 1
    fi
}

file_exists() {
    local file_path=$1
    if [ -f "$file_path" ]; then
        return 0
    else
        return 1
    fi
}

# Validate if a command is available on the system
validate_command() {
    if ! command -v "$1" &>/dev/null; then
        echo "Error: $1 is not installed on this system."
        return 1
    fi
    return 0
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
generate_pass() {
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

# Function to fix files and folders permissions
perm_set() {

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
        echo "Usage: ${FUNCNAME[0]} <target> <user> <group>"
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

php_manage() {
    while true; do
        echo "Choose an option:"
        echo "1. Install PHP"
        echo "2. Remove (purge) PHP"
        echo "3. Install PHPMyAdmin"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) php_install ;;
        2) php_remove ;;
        3) php_install_myadmin ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

# Function to install PHP
php_install() {
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
    apt-get update
    for phpVer in "${PHP_Versions[@]}"; do
        echo -e "\nInstalling PHP ${phpVer}"

        # if [ -f "/etc/php/${phpVer}/fpm/pool.d/www.disabled" ]; then
        #     mv "/etc/php/${phpVer}/fpm/pool.d/www.disabled" "/etc/php/${phpVer}/fpm/pool.d/www.conf"
        # fi

        # Essential & Commonly Used Extensions Extensions
        apt-get install -y bc php"${phpVer}"-{fpm,mysqli,mbstring,curl,xml,intl,gd,zip,bcmath,apcu,sqlite3,imagick,tidy,gmp,bz2,ldap,memcached} || { echo "Failed to install" && return 1; }
        # bz2
        # [PHP Modules] bcmath calendar Core ctype curl date dom exif FFI fileinfo filter ftp gd gettext hash iconv intl json libxml mbstring mysqli mysqlnd openssl pcntl pcre PDO pdo_mysql Phar posix readline Reflection session shmop SimpleXML sockets sodium SPL standard sysvmsg sysvsem sysvshm tokenizer xml xmlreader xmlwriter xsl Zend OPcache zip zlib apcu sqlite3 imagick tidy
        # [Zend Modules]
        # Zend OPcache

        # Less Commonly Used Extensions
        # apt-get install php"${phpVer}"-{soap,pspell,xmlrpc,memcached}

        # For dev
        # apt-get install php${phpVer}-{dev}

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
        read -rp "Enter PHP version to install composer: (default 8.2) " composer_php_ver
        # Use the user input if provided, or the default value if the input is empty
        if [ -z "$composer_php_ver" ]; then
            composer_php_ver=8.2
        fi
        curl -sS https://getcomposer.org/installer | "php${composer_php_ver}"
        echo "Moving 'composer.phar' to '/usr/local/bin/composer'"
        mv composer.phar /usr/local/bin/composer
    fi

    echo "PHP installation and configuration complete."

}

# Function to remove PHP
php_remove() {
    local confirm
    read -rp "This will purge PHP and its configuration.. Are you sure? (y/n): " confirm

    if [[ $confirm != "y" ]]; then
        echo "Aborting."
        return 0
    fi

    for phpVer in "${PHP_Versions[@]}"; do

        # Purge PHP packages
        apt purge -y "php${phpVer}-"* && apt-get autoremove -y

    done

    # Remove PHP configuration files
    rm -rf /etc/php/

    echo "PHP and its configuration have been purged."
}

php_conf_generate() {
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

# Function to install PHPMyAdmin
php_install_myadmin() {
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

    read -rp "Enter new password for dbadmin user: " dbadmin_pass
    read -rp "Make sure mariadb connection is configured and press enter to start installation"

    PHPMYADMIN_VERSION="5.2.1" # Update this to the desired phpMyAdmin version
    INSTALL_DIR="${web_dir}/public/dbadmin"
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

nginx_manage() {

    nginx_conf_domain_get() {
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

    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install nginx"
        echo "2. Remove (purge) nginx"
        echo "3. Create vhost"
        echo "4. Add cloudflare IPs (nginx) SYNC script with cron job"
        echo "5. Install Cert"
        echo "6. Uninstall Cert"
        echo "7. Backup nginx config (vhosts and ssl snippets)"
        echo "8. Restore nginx config"
        echo "9. Install RTMP module"
        echo "10. Install Caddy"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) nginx_install ;;
        2) nginx_remove ;;
        3) nginx_vhost_create ;;
        4) nginx_cloudflare_add ;;
        5) nginx_cert_install ;;
        6) nginx_cert_uninstall ;;
        7) nginx_backup_config ;;
        8) nginx_restore_config ;;
        9) nginx_install_rtmp ;;
        10) nginx_install_caddy ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

nginx_install_caddy() {
    apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update && apt install caddy && caddy list-modules
}

nginx_install_rtmp() {
    apt-get install libnginx-mod-rtmp
}

# Function to install Nginx
nginx_install() {
    local COMMON_NAME="localhost"

    # First, detect the OS
    local OS=$(lsb_release -is)
    local OS_Codename=$(lsb_release -cs)

    if [ "$OS" = "Ubuntu" ]; then
        # This is Ubuntu, use the PPA
        if [ -f "/etc/apt/sources.list.d/ondrej-ubuntu-nginx-$(lsb_release -cs).list" ]; then
            echo -e "\nOndrej Sury's Nginx PPA already exists."
        else
            echo -e "\nAdding Ondrej Sury's Nginx PPA for Ubuntu."
            # software-properties-common is needed for add-apt-repository
            apt-get update && apt-get install -y software-properties-common
            add-apt-repository ppa:ondrej/nginx -y
        fi
        
        # Install Nginx and modules for Ubuntu
        echo "Installing Nginx for Ubuntu..."
        case "$OS_Codename" in
            "noble")
                echo "Installing brotli for Ubuntu 24 (Noble)..."
                sudo apt-get install -y nginx-full libnginx-mod-http-brotli-static libnginx-mod-http-brotli-filter || { echo "Failed to install nginx on Ubuntu" && return 1; }
                ;;
            *)
                echo "Unsupported Ubuntu version: $OS_Codename"
                return 1
                ;;
        esac

    elif [ "$OS" = "Debian" ]; then
        # This is Debian, use the packages.sury.org repository
        if grep -qR "packages.sury.org/nginx" /etc/apt/sources.list.d/; then
            echo -e "\nSury's nginx Repo Exists"
        else
            # Adding sury's nginx repo for Debian
            echo -e "\nInstalling sury's nginx repo for Debian"
            curl -sSL https://packages.sury.org/nginx/README.txt | bash -x
            echo
            # Create the pinning configuration file
            #         local PIN_FILE="/etc/apt/preferences.d/sury-repo-pin"
            #         tee "$PIN_FILE" >/dev/null <<EOLX
            # Package: *
            # Pin: origin packages.sury.org
            # Pin-Priority: 1000
            # EOLX
        fi

        # Install Nginx and modules for Debian
        echo "Installing Nginx for Debian..."
        case "$OS_Codename" in
            "bookworm")
                echo "Installing brotli for Debian 12 (Bookworm)..."
                sudo apt-get install -y nginx-full libnginx-mod-brotli || { echo "Failed to install nginx on Debian" && return 1; }
                ;;
            "trixie")
                echo "Installing brotli for Debian 13 (Trixie)..."
                sudo apt-get install -y nginx-full libnginx-mod-http-brotli-static libnginx-mod-http-brotli-filter || { echo "Failed to install nginx on Debian" && return 1; }
                ;;
            *)
                echo "Unsupported Debian version: $OS_Codename"
                return 1
                ;;
        esac

    else
        echo "Unsupported operating system: $OS"
        return 1
    fi

    systemctl enable nginx
    # Create log folder for the main profile
    rm -rf /var/www/html

    # Add log rotation for nginx
    # sed -i "s/^\/var\/log\/nginx\/\*\.log/\/var\/www\/*\/logs\/*\/*.log/" /etc/logrotate.d/nginx

    cat >"/etc/logrotate.d/nginx" <<'EOFX'
/var/www/*/logs/*/*.log {
	size 50M
	missingok
	rotate 15
	compress
	delaycompress
	notifempty
	create 0640 www-data adm
	sharedscripts
	prerotate
		if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
			run-parts /etc/logrotate.d/httpd-prerotate; \
		fi \
	endscript
	postrotate
		invoke-rc.d nginx rotate >/dev/null 2>&1
	endscript
}
EOFX

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

    cat >"${caching_nginx_snippet}" <<'EOFX'
location ~* \.(?:ico|gif|jpe?g|png|htc|otf|ttf|eot|woff|woff2|svg|css|js)$ {
    # expires 30d;
    add_header Cache-Control "max-age=2592000, public";
    open_file_cache max=3000 inactive=120s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 4;
    open_file_cache_errors on;
}
EOFX

    cat >"${common_nginx_snippet}" <<'EOFX'
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
    cat >/etc/nginx/nginx.conf <<'EOTX'
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
    # With only ECDHE ciphers in use, you don't need a custom DH parameter file.
    # If you were to use DHE cipher suites, you would generate one (e.g. using openssl dhparam)

    ssl_protocols TLSv1.2 TLSv1.3;
    proxy_ssl_protocols TLSv1.2 TLSv1.3;

    # For TLSv1.3, remove AES_256 support
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256;

    # For TLSv1.2 the server's preference isn't critical when only strong ciphers are used.
    # (Note: TLSv1.3 cipher suites are chosen by OpenSSL and are not affected by this.)
    ssl_prefer_server_ciphers on;

    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';


    # Enable session resumption to improve performance
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-available/*.conf;
}
EOTX

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
nginx_remove() {
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
    apt-get remove --purge nginx* libnginx* -y && apt-get autoremove -y

    # Remove configuration files
    rm -rf /etc/nginx

    dpkg --audit
    dpkg --configure --pending

    echo "Nginx and its configuration have been purged."
}

nginx_backup_config() {
    tar -czf nginx_config_backup.tar.gz /etc/nginx/snippets/ssl-*.conf "/etc/nginx/sites-available" "/etc/nginx/sites-enabled" || echo "Success: nginx_config_backup.tar.gz" || echo "Backup Failed."
}

nginx_restore_config() {
    local path="$1"
    read -rp "Enter path to file/directory: " path
    # Remove quotes if present in the input path
    path=${path//\"/}
    # Remove trailing slash if present in the input path
    path=${path%/}

    if ! path_exists "$path"; then
        echo "Path doesn't exist"
        return 1
    fi

    tar -xzvf "${path}" -C /
}

nginx_cloudflare_add() {
    local cloudflare_script="/usr/local/bin/cloudflare_sync"
    cat >"$cloudflare_script" <<'EOFX'
#!/bin/bash

CLOUDFLARE_FILE_PATH=/etc/nginx/conf.d/cloudflare.conf
TEMP_FILE=$(mktemp)
HASH_FILE=/var/tmp/cloudflare_hash

# Fetch new Cloudflare IPs and verify them
new_ipv4=$(curl -sS https://www.cloudflare.com/ips-v4)
new_ipv6=$(curl -sS https://www.cloudflare.com/ips-v6)

if [[ -z $new_ipv4 || -z $new_ipv6 ]]; then
    echo "Failed to fetch Cloudflare IPs. Aborting."
    exit 1
fi

# Calculate hashes of the new IPs
new_hash=$(echo -n "$new_ipv4$new_ipv6" | sha256sum | cut -d ' ' -f 1)

# Check if the IPs have changed
if [ -f $HASH_FILE ] && [ "$(cat $HASH_FILE)" = "$new_hash" ]; then
    echo "Cloudflare IPs have not changed. No update needed."
    exit 0
fi

# Write the new configuration to a temporary file
echo "#Cloudflare" > $TEMP_FILE;
echo "" >> $TEMP_FILE;

echo "# - IPv4" >> $TEMP_FILE;
echo "$new_ipv4" | while read -r i; do
    echo "set_real_ip_from $i;" >> $TEMP_FILE;
done

echo "" >> $TEMP_FILE;
echo "# - IPv6" >> $TEMP_FILE;
echo "$new_ipv6" | while read -r i; do
    echo "set_real_ip_from $i;" >> $TEMP_FILE;
done

echo "" >> $TEMP_FILE;
echo "real_ip_header CF-Connecting-IP;" >> $TEMP_FILE;

if [[ -f "$CLOUDFLARE_FILE_PATH" ]]; then
    mv "$CLOUDFLARE_FILE_PATH" "${CLOUDFLARE_FILE_PATH}.bak"
fi
mv $TEMP_FILE $CLOUDFLARE_FILE_PATH

# Test the new configuration
nginx -t

if [ $? -eq 0 ]; then
    # Update the hash file with the new hash
    echo "$new_hash" > $HASH_FILE

    echo "Cloudflare IPs updated successfully."
    systemctl reload nginx
else
    echo "New configuration test failed. Rolling back."
    if [[ -f "${CLOUDFLARE_FILE_PATH}.bak" ]]; then
        mv "${CLOUDFLARE_FILE_PATH}.bak" "$CLOUDFLARE_FILE_PATH"
    fi
    exit 1
fi
EOFX

    chmod 700 "$cloudflare_script"

    echo "Fetching IPs from cloudflare.."
    cloudflare_sync
    # Add daily cron job
    echo "Adding cron job.."

    if [[ ! -d "/var/log/nginx/" ]]; then
        mkdir -p /var/log/nginx/
    fi

    echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >"${cron_dir}/cloudflare"
    echo "30 1 * * * root ${cloudflare_script} >> /var/log/nginx/cloudflare.log 2>&1" >>"${cron_dir}/cloudflare"
    chmod 644 "${cron_dir}/cloudflare"
    # cat "${cron_dir}"/* | crontab -
    echo -e "cat ${cron_dir}/cloudflare\n"
    cat "${cron_dir}/cloudflare"
    # crontab -l
    # Jobs inside "/etc/cron.d/" directory are monitored for changes
    # /etc/init.d/cron reload
    # systemctl restart cron
    # /var/spool/cron/crontabs
}

nginx_cert_install() {
    local nginx_conf_dir="/etc/nginx/sites-available"
    local ssl_dir="/etc/ssl"
    local ssl_cert

    nginx_config=$(select_from_dir "$nginx_conf_dir")
    echo "Selected config: $nginx_config"

    local domain_name
    domain_name=$(nginx_conf_domain_get "${nginx_config}")
    [[ -n $domain_name ]] || {
        echo "Error: domain_name is empty"
        echo "$domain_name"
        return 1
    }

    echo -e "\n Domain: ${domain_name}\n"
    sleep 2

    ssl_cert=$(select_from_dir "$ssl_dir")
    echo "Selected cert: $ssl_cert"

    # Get Base Name
    local ssl_cert_name="${ssl_cert##*/}"

    if ! [ -f "${ssl_cert}/fullchain.cer" ]; then
        echo "File does not exist: ${ssl_cert}/fullchain.cer"
        return 1
    fi
    if ! [ -f "${ssl_cert}/privkey.pem" ]; then
        echo "File does not exist: ${ssl_cert}/fullchain.cer"
        return 1
    fi

    mkdir -p "/etc/nginx/snippets/"
    snippet_path="/etc/nginx/snippets/ssl-$ssl_cert_name.conf"

    cat >"$snippet_path" <<EOFX
ssl_certificate "$ssl_cert/fullchain.cer";
ssl_certificate_key "$ssl_cert/privkey.pem";
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

# Function to revert to self-signed certificate
nginx_cert_uninstall() {
    # read -rp "Enter the domain name to revert to a self-signed certificate (e.g., example.com): " domain_name
    echo "Select nginx config"
    local nginx_config
    nginx_config=$(select_from_dir "/etc/nginx/sites-available/")
    echo "Selected config: $nginx_config"

    local domain_name
    domain_name=$(nginx_conf_domain_get "${nginx_config}")
    [[ -n $domain_name ]] || {
        echo "Error: domain_name is empty"
        echo "$domain_name"
        return 1
    }

    # nginx_config="/etc/nginx/sites-available/$domain_name"

    if [ -f "$nginx_config" ]; then
        local snippet_path="/etc/nginx/snippets/ssl-$domain_name.conf"

        # echo "Commenting: include $snippet_path;"
        comment_uncomment "include $snippet_path;" "$nginx_config" comment

        comment_uncomment "include ${ssl_nginx_snippet};" "$nginx_config" uncomment
        nginx -t && systemctl reload nginx

        # echo "Reverted $domain_name to use the self-signed certificate."
    else
        echo "Nginx configuration file not found."
    fi
}

nginx_vhost_create() {
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
    php_conf_generate "${vuser}" "${domain}" "${phpVer}"

    # Generate nginx config
    nginx_conf_generate "${vuser}" "${domain}" "${phpVer}"

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

nginx_conf_generate() {
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
    listen 443 ssl;
    http2 on;
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

mariadb_manage() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install mariadb server"
        echo "2. Install mariadb client"
        echo "3. Remove (purge) mariadb"
        echo "4. Backup Database (Dump)"
        echo "5. Restore Database (Dump)"
        echo "6. Create db and its user"
        echo "7. Read mysql/MariaDB config"
        echo "0. Quit"

        read -rp "Enter your choice: " choice
        case $choice in
        1) mariadb_server_install ;;
        2) mariadb_client_install ;;
        3) mariadb_remove ;;
        4) db_backup ;;
        5) db_restore ;;
        6) db_create ;;
        7) db_config_read ;;
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

# Function to install MariaDB Server
mariadb_server_install() {
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

    PACKAGE_NAME="mariadb-server mariadb-backup"
    # Check if the package is installed
    if dpkg -l | grep -q "^ii  $PACKAGE_NAME "; then
        echo "$PACKAGE_NAME is already installed."
        return
    else
        echo "$PACKAGE_NAME is not installed. Installing..."
        apt-get update && apt-get install -y $PACKAGE_NAME || { echo "Failed to install $PACKAGE_NAME" && return 1; }
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
mariadb_client_install() {
    local db_host
    local db_user
    local db_pass

    # Install the MariaDB client
    echo "Installing MariaDB client..."
    apt-get update && apt-get install -y mariadb-client || { echo "Failed to install mariadb-client" && return 1; }

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
mariadb_remove() {
    local confirmation
    local confirmation2
    # Ask for confirmation
    read -rp "This will uninstall MariaDB. Are you sure? (y/n): " confirmation

    if [[ $confirmation != "y" ]]; then
        echo "Aborting."
        return 0
    fi

    # Uninstall MariaDB
    apt remove -y --purge mariadb-server mariadb-client
    # apt remove -y --purge mariadb* mysql*
    echo -e "\nRunning dpkg -l | grep -e mysql -e mariadb "
    dpkg -l | grep -e mysql -e mariadb

    read -rp "Do you want to remove configurations by running apt-get autoremove? (y/n): " confirmation2

    if [[ $confirmation2 != "y" ]]; then
        apt-get autoremove -y
    fi

    # Delete configuration and database files
    # rm -rf /etc/mysql /var/lib/mysql /var/log/mysql

    # Remove MariaDB user and group
    # deluser mysql
    # delgroup mysql

    echo -e "\nMariaDB has been purged from the system. All databases and configuration files have been deleted."
}

# Function to restore a database from a dump
db_restore() {
    local db_name="$1"
    local dump_file="$2"
    # Check if both arguments are provided
    if [ -z "$db_name" ] || [ -z "$dump_file" ]; then
        db_show_databases
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
db_backup() {
    local db_name="$1"
    local save_location="$2"
    local timestamp
    local dump_file
    # Check if both arguments are provided
    if [ -z "$db_name" ] || [ -z "$save_location" ]; then
        db_show_databases
        read -rp "Enter the database name: " db_name
        read -rp "Enter the save Folder (e.g., /path/to/save/): " save_location

        # Check again if they are empty
        if [ -z "$db_name" ] || [ -z "$save_location" ]; then
            echo "Both database name and save folder are required."
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

db_show_databases() {
    # $DB_CMD -e "SHOW DATABASES" | grep -Ev "(Database|information_schema|mysql|performance_schema|phpmyadmin|sys)"
    $DB_CMD -e "SELECT SCHEMA_NAME AS 'DATABASES' FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'phpmyadmin', 'sys');"
}

db_create() {
    local DB_NAME DB_USER DB_USER_PASS
    db_show_databases
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

db_config_read() {
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

    if command -v lynx &>/dev/null; then
        $DB_CMD -e "$grants_commands" --html --silent | lynx -stdin -dump
    else
        $DB_CMD -e "$grants_commands"
    fi

    # List databases
    db_show_databases
}

memcached_manage() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install memcached"
        echo "2. Remove (purge) memcached"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) memcached_install ;;
        2) memcached_remove ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

# Function to install Memcached
memcached_install() {
    # Install Memcached and required dependencies
    apt-get update && apt-get install -y memcached libmemcached-tools || { echo "Failed" && return 1; }

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
memcached_remove() {
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
    apt remove -y --purge memcached

    # Also remove configuration files
    rm -rf /etc/memcached.conf

    echo "Memcached purged and configuration files removed."
}

docker_install() {
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
    apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

docker_remove() {
    # Remove the official docker
    apt purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    # for pkg in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; do apt-get -y remove $pkg; done
    # Remove debian's docker
    # for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do apt-get -y remove $pkg; done
    apt purge -y docker.io docker-doc docker-compose podman-docker containerd runc

}

docker_manage() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install docker"
        echo "2. Remove (purge) docker"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) docker_install ;;
        2) docker_remove ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

wordpress_manage() {
    local choice
    while true; do
        echo "Choose an option:"
        echo "1. Install Wordpress"
        echo "0. Quit"

        read -rp "Enter your choice: " choice
        case $choice in
        1) wordpress_install ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

wordpress_install() {
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

certbot_manage() {
    local choice
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. Install Certbot"
        echo "2. Get/Renew Certificate"
        echo "5. List cloudflare configs"
        echo "6. Create cloudflare config"
        echo "0. Quit"
        echo -e "\033[0m"

        read -rp "Enter your choice: " choice

        case $choice in
        1) certbot_install ;;
        2) certbot_certificate_get ;;
        5) certbot_list_cloudflare_config ;;
        6) certbot_create_cloudflare_config ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

certbot_install() {
    # Check if Certbot is installed
    if ! command -v certbot &>/dev/null; then
        echo "Certbot is not installed. Installing Certbot..."
        # apt-get update && apt-get -y install certbot python3-certbot-dns-cloudflare
        apt-get update && apt-get -y install snapd
        snap install --classic certbot
        ln -s /snap/bin/certbot /usr/bin/certbot
        snap set certbot trust-plugin-with-root=ok
        snap install certbot-dns-cloudflare
    fi
}

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
certbot_certificate_get() {
    local domain_name
    local account_list
    local index
    local chosen_number
    local account
    read -rp "Enter your domain name (e.g., example.com): " domain_name

    # Check if any Cloudflare configurations exist
    local selected_config
    selected_config=$(select_from_dir "${cloudflare_config_dir}")
    echo "Selected file: $selected_config"

    # Get a list of Certbot accounts
    account_list=$(ls -1 /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory)

    if [ -z "$account_list" ]; then
        echo "No Certbot accounts found."
    else
        # Display the list of accounts with numbers
        echo "Available Certbot Accounts:"
        index=1
        for account in $account_list; do
            echo "$index. $account"
            ((index++))
        done
        while true; do
            # Prompt user to choose an account
            read -rp "Enter the number of the account to use: " chosen_number
            # Validate user input
            if ! [[ "$chosen_number" =~ ^[0-9]+$ ]] || [ "$chosen_number" -le 0 ] || [ "$chosen_number" -gt "$index" ]; then
                echo "Invalid input. Please enter a valid account number."
            else
                break
            fi
        done
        # Get the chosen account
        chosen_account=$(echo "$account_list" | awk "NR==$chosen_number")
        echo "Selected Account: $chosen_account"
    fi
    if [ -n "$chosen_account" ]; then
        account="--account ${chosen_account}"
    fi

    read -rp "Press Enter to start..."

    # Request the certificate (For debugging add: --dry-run -vvv)
    if certbot certonly -n --dns-cloudflare -d "${domain_name},*.${domain_name}" --dns-cloudflare-propagation-seconds 20 --dns-cloudflare-credentials "${selected_config}" ${account}; then
        mkdir -p /etc/ssl
        ln -s "/etc/letsencrypt/live/${domain_name}" /etc/ssl/
    fi

    # --account <account-id or URI>

    # For CURL
    # zid 1c2a1aaa99b81e8ecfae3d1e81e52e60
    # curl -X GET "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name=_acme-challenge.domain.com" \
    #   -H "Authorization: Bearer {api_token}" \
    #   -H "Content-Type:application/json" | jq .

}

rsync_manage() {
    local choice
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. Install rsync & add log rotation"
        echo "2. Rsync push letsencrypt"
        echo "3. rsync_push_ssl (guided)"
        echo "4. Install rsync daemon"
        echo "0. Quit"
        echo -e "\033[0m"

        read -rp "Enter your choice: " choice

        case $choice in
        1) rsync_install ;;
        2) rsync_push_letsencrypt ;;
        3) rsync_push_ssl ;;
        4) install_rsync_daemon ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

rsync_install() {
    # Check if the 'rsync' command is available
    if ! command -v rsync >/dev/null 2>&1; then
        echo "The 'rsync' command is not installed. Installing..."
        apt-get update && apt-get install -y rsync
    fi

    mkdir -p /var/log/rsync

    echo -e "\nAdding log rotation.."
    cat >/etc/logrotate.d/rsync <<EOFX
/var/log/rsync/*.log {
    size 20M
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

install_rsync_daemon() {
    # Check if running as root
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root"
        return 1
    fi

    # Install rsync if not already installed
    if ! command -v rsync &> /dev/null; then
        echo "Installing rsync..."
        rsync_install
    fi

    # Prompt for module details
    read -rp "Enter the module name (e.g., downloads): " module_name
    read -rp "Enter the full path for the module (e.g., /root/Downloads): " module_path

    # Check if module path exists
    if [ ! -d "$module_path" ]; then
        echo "Directory $module_path does not exist. Creating it..."
        mkdir -p "$module_path" || {
            echo "Failed to create directory $module_path"
            return 1
        }
        echo "Directory created successfully"
        chmod 777 "$module_path" && echo "Permissions set to 777 for $module_path" || echo "Failed to set permissions for $module_path"
    else
        echo "Directory $module_path already exists"
    fi

    # Create rsync config file
    cat > /etc/rsyncd.conf <<EOF
# Global Settings
uid = nobody
gid = nogroup
use chroot = yes
max connections = 10
timeout = 300
pid file = /var/run/rsyncd.pid
lock file = /var/run/rsync.lock
log file = /var/log/rsync/rsyncd.log
reverse lookup = no

# Module Configuration
[$module_name]
    path = $module_path
    comment = Public files
    read only = yes
    list = yes
    hosts allow = *
    # Or specific IPs/networks 192.168.1.0/24 1.2.3.4
    # hosts deny = *
    transfer logging = no
    # Disables per file transfer logging for speed.
    ignore errors = yes
    # Continue even if there are errors.
    numeric ids = yes
    # Avoids name resolution overhead.
    dont compress = *
    #.zip *.gz *.tgz *.bz2 *.xz *.7z *.rar *.mp3 *.mp4 *.avi *.mkv *.jpg *.jpeg *.png *.gif # Files that are already compressed.
EOF

    # Create systemd service file if systemd is available
    # cat > /etc/systemd/system/rsync.service <<EOF
# [Unit]
# Description=fast remote file copy program daemon
# ConditionPathExists=/etc/rsyncd.conf
# After=network.target
# Documentation=man:rsync(1) man:rsyncd.conf(5)

# [Service]
# ExecStart=/usr/bin/rsync --daemon --no-detach
# RestartSec=1
# Restart=on-failure
# ProtectSystem=full
# #ProtectHome=on|off|read-only
# PrivateDevices=on
# NoNewPrivileges=on

# [Install]
# WantedBy=multi-user.target
# EOF

    # systemctl daemon-reload
    systemctl enable rsync
    systemctl start rsync
    echo "Rsync daemon enabled and started as a systemd service."
    echo "You can edit the configuration at /etc/rsyncd.conf"
}

rsync_push_letsencrypt() {
    local path="$1"
    if [[ -z "$path" ]]; then
        path=$(select_from_dir "/etc/letsencrypt/live/")
    fi
    local domain="${path##*/}"
    local host="$2"
    local port="$3"
    local user="$4"
    if [[ -z "$host" ]]; then
        read -rp "Enter host or IP: " host
    fi
    if [[ -z "$port" ]]; then
        read -rp "Enter port: " port
    fi
    if [[ -z "$user" ]]; then
        read -rp "Enter user (default root): " user
        if [[ -z "$user" ]]; then
            user=root
        fi
    fi
    rsync --log-file="/var/log/rsync/letsencrypt.log" -uahzPL "/etc/letsencrypt/live/${domain}" -e "ssh -p $port" "${user}@${host}":/etc/ssl/
    echo "Log written to '/var/log/rsync/letsencrypt.log'"
}

rsync_push_ssl() {
    local path="$1"
    if [[ -z "$path" ]]; then
        path=$(select_from_dir "/etc/ssl/")
    fi
    path="${path%%+(/)}"
    local domain="${path##*/}"
    local host="$2"
    local port="$3"
    local user="$4"
    if [[ -z "$host" ]]; then
        read -rp "Enter host or IP: " host
    fi
    if [[ -z "$port" ]]; then
        read -rp "Enter port: " port
    fi
    if [[ -z "$user" ]]; then
        read -rp "Enter user (default root): " user
        if [[ -z "$user" ]]; then
            user=root
        fi
    fi
    rsync --log-file="/var/log/rsync/push_ssl.log" -uahzPL "${path}" -e "ssh -p $port" "${user}@${host}":/etc/ssl/
    echo "Log written to '/var/log/rsync/push_ssl.log'"
}

compress() {
    # Validate the availability of compression methods
    local commands=("zip" "tar" "gzip" "bzip2" "xz" "7z")
    for cmd in "${commands[@]}"; do
        validate_command "$cmd" || return 1
    done

    if [ "$#" -ne 2 ]; then
        echo "Insufficient number of arguments. Usage: $0 compress [format] [path]"
        exit 1
    fi
    local format=$1
    local path=$2
    local level

    # Remove quotes if present in the input path
    path=${path//\"/}
    # Remove trailing slash if present in the input path
    path=${path%/}

    # local base_name=$(basename "$path")
    # local dir_name=$(dirname "$path")

    if ! path_exists "$path"; then
        echo "Path doesn't exist"
        return 1
    fi

    # "$base_name.tar" -C "$dir_name" "$base_name"

    # - to backup a directory : tar cf - directory | 7za a -si directory.tar.7z
    # - to restore your backup : 7za x -so directory.tar.7z | tar xf -

    case $format in
    "zip")
        # if [ -d "$path" ]; then
        #     zip -r "$path.zip" "$path"
        # else
        #     zip "$path.zip" "$path"
        # fi
        7z a -tzip -mx=5 "$path.zip" "$path" # mx5 still better and faster than zip -9
        ;;
    "tar") tar -cvf "$path.tar" "$path" ;;
    "gz")
        if [ -d "$path" ]; then
            tar -czvf "$path.tar.gz" "$path"
        else
            gzip -c "$path" >"$path.gz"
        fi
        ;;
    "bz2")
        if [ -d "$path" ]; then
            tar -cjvf "$path.tar.bz2" "$path"
        else
            bzip2 -c "$path" >"$path.bz2"
        fi
        ;;
    "xz")
        if [ -d "$path" ]; then
            tar -cJvf "$path.tar.xz" "$path"
        else
            xz -c "$path" >"$path.xz"
        fi
        ;;
    "7z")
        while true; do
            read -rp "Enter compression level for 7z: [0|1|3|5|7|9]: " level
            case $level in
            0) break ;;
            1) break ;;
            3) break ;;
            5) break ;;
            7) break ;;
            9) break ;;
            *) echo "Invalid choice." ;;
            esac
        done

        7z -mx=$level a "$path.7z" "$path"
        ;;
    *) echo "Invalid compression format." ;;
    esac
}

decompress() {
    # Validate the availability of compression methods
    # Validate the availability of compression methods
    local commands=("unzip" "tar" "gzip" "bzip2" "xz" "7z")
    for cmd in "${commands[@]}"; do
        validate_command "$cmd" || return 1
    done

    if [ "$#" -ne 1 ]; then
        echo "Insufficient number of arguments. Usage: $0 decompress [path]"
        exit 1
    fi
    detect_format() {
        local file_path=$1
        local extension="${file_path##*.}"

        case $extension in
        "zip") echo "zip" ;;
        "tar") echo "tar" ;;
        "gz") echo "gz" ;;
        "bz2") echo "bz2" ;;
        "xz") echo "xz" ;;
        "7z") echo "7z" ;;
        *)
            local file_type=$(file -b "$file_path" | awk '{print $1}')

            case $file_type in
            "Zip") echo "zip" ;;
            "POSIX") echo "tar" ;;
            "gzip") echo "gz" ;;
            "bzip2") echo "bz2" ;;
            "XZ") echo "xz" ;;
            "7-zip") echo "7z" ;;
            *) echo "Unknown" ;;
            esac
            ;;
        esac
    }
    local format path=$1

    if ! file_exists "$path"; then
        echo "File doesn't exist"
        return 1
    fi

    format=$(detect_format "$path")
    if [ "$format" == "Unknown" ]; then
        echo "Unknown compression format. Decompression aborted."
        return 1
    fi

    case $format in
    "zip") unzip "$path" ;;
    "tar") tar -xvf "$path" ;;
    "gz") tar -xzvf "$path" ;;
    "bz2") tar -xjvf "$path" ;;
    "xz") tar -xJvf "$path" ;;
    "7z") 7z x "$path" ;;
    *) echo "Invalid compression format." ;;
    esac
}

comp_manage() {

    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. Compress"
        echo "2. Decompress"
        echo "0. Exit"
        echo -e "\033[0m"
        read -rp "Enter your choice: " choice

        case $choice in
        0) return 0 ;;
        1)
            while true; do
                read -rp "Enter compression format (zip, tar, gz, bz2, xz, 7z): " format
                case $format in
                "zip" | "tar" | "gz" | "bz2" | "xz" | "7z") break ;;
                *)
                    echo "Invalid compression format."
                    ;;
                esac
            done
            read -rp "Enter path to file/directory: " path
            compress "$format" "$path"
            ;;
        2)
            read -rp "Enter path to compressed file: " path
            decompress "$path"
            ;;
        *)
            echo "Invalid choice."
            ;;
        esac
    done
}

net_manage() {
    local choice
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. Enable IP Forward & MASQUERADE"
        echo "2. Tune Kernel"
        echo "3. tailscale_manage"
        echo "4. cloudflared_manage"
        echo "5. Install SoftEther VPN"
        echo "6. Install OpenConnect VPN Client"
        echo "7. Add OpenConnect Client Configs"
        echo "8. Install and configure Squid as HTTP/S proxy"
        echo "9. Install UDP-GRO Service"
        echo "10. Install TinyProxy"

        echo "0. Quit"
        echo -e "\033[0m"
        read -rp "Enter your choice: " choice

        case $choice in
        1) net_enable_ip_forward ;;
        2) net_tune_kernel ;;
        3) tailscale_manage ;;
        4) cloudflared_manage ;;
        5) net_softether_install ;;
        6) net_install_openconnect ;;
        7) net_addConfig_openconnect ;;
        8) setup_squid_https_proxy ;;
        9) setup_gro_service ;;
        10) setup_tinyproxy ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

setup_tinyproxy(){
    local configFile="/etc/tinyproxy/tinyproxy.conf"
    apt update && apt install tinyproxy

    if [ ! -f "${configFile}" ]; then
        echo "Error: Config File was not found"
        return 1
    fi

    config_set 
}
# Function to install and configure GRO settings as a systemd service
setup_gro_service() {
    local service_name="udp-gro"
    local service_file="/etc/systemd/system/${service_name}.service"

    KERNEL_VERSION=$(uname -r | cut -d '-' -f1)
    REQUIRED_VERSION="6.2"
    # Compare versions using sort -V
    if printf "%s\n%s" "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | tail -n1 | grep -q "$KERNEL_VERSION"; then
        echo "Kernel version is $KERNEL_VERSION ."
    else
        echo "Kernel version $KERNEL_VERSION is lower than $REQUIRED_VERSION."
        echo "Abort!"
        return 1
    fi

    # Check if ethtool is installed
    if ! command -v ethtool &>/dev/null; then
        echo "ethtool is not installed. Installing..."
        if command -v apt &>/dev/null; then
            apt update && apt install -y ethtool
        else
            echo "Error: Package manager not supported. Install ethtool manually."
            exit 1
        fi
    else
        echo "ethtool is already installed."
    fi

    if ! command -v ethtool &>/dev/null; then
        echo "ethtool was not installed."
        exit 1
    fi

    # Create the systemd service file
    echo "Creating systemd service file..."
    cat >"${service_file}" <<EOL
[Unit]
Description=Enable rx-udp-gro-forwarding and disable rx-gro-list for primary network interface
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/bash -c 'until ping -c1 google.com &>/dev/null; do sleep 1; done'
ExecStart=/bin/bash -c "\
    NETDEV=\$(ip -o route get 8.8.8.8 | cut -f 5 -d ' '); \
    if [ -n \"\$NETDEV\" ]; then \
        /usr/sbin/ethtool -K \"\$NETDEV\" rx-udp-gro-forwarding on rx-gro-list off; \
        logger -t ${service_name} \"Applied GRO settings for interface \$NETDEV\"; \
    else \
        logger -t ${service_name} \"Failed to determine primary network interface\"; \
        exit 1; \
    fi"
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOL

    echo "Systemd service file created at ${service_file}."

    # Reload systemd, enable, and start the service
    echo "Reloading systemd and enabling the service..."
    systemctl daemon-reload
    systemctl enable "${service_name}"
    systemctl start "${service_name}"
    echo "Service enabled and started."

    # Verify the settings
    echo "Verifying GRO settings..."
    local netdev=$(ip -o route get 8.8.8.8 | cut -f 5 -d " ")
    if [ -n "${netdev}" ]; then
        ethtool -k "${netdev}" | grep -E "rx-udp-gro-forwarding|rx-gro-list"
    else
        echo "Warning: Unable to determine the primary network interface for verification."
    fi

    echo "Setup complete. The GRO settings will be applied automatically on boot."
}

# Function to install and configure Squid as HTTP/S proxy
setup_squid_https_proxy() {
    # Local variables
    local squid_conf="/etc/squid/squid.conf"
    local squid_service="squid"
    local http_port=3128
    local https_port=3129

    # Check if user is root
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: This script must be run as root." >&2
        return 1
    fi

    # Update package list
    echo "Updating package list..."
    if ! apt-get update -qq; then
        echo "Error: Failed to update package list." >&2
        return 1
    fi

    # Install Squid if not already installed
    echo "Installing Squid..."
    if ! apt-get install -y squid; then
        echo "Error: Failed to install Squid." >&2
        return 1
    fi

    # Backup the default squid configuration
    if [ ! -f "${squid_conf}.bak" ]; then
        echo "Backing up default Squid configuration..."
        if ! cp "${squid_conf}" "${squid_conf}.bak"; then
            echo "Error: Failed to backup Squid configuration." >&2
            return 1
        fi
    fi

    # Configure Squid
    echo "Configuring Squid as HTTP/S proxy..."

    # Allow HTTP and HTTPS ports
    cat >"${squid_conf}" <<EOF
# Squid proxy configuration
http_port ${http_port}
https_port ${https_port} cert=/etc/squid/ssl_cert/squid.pem key=/etc/squid/ssl_cert/squid.key

# Allow access from all networks (for production, restrict to specific IP ranges)
acl localnet src 0.0.0.0/0
http_access allow localnet
http_access deny all
EOF

    # Create SSL certificates if not present
    if [ ! -d "/etc/squid/ssl_cert" ]; then
        mkdir -p /etc/squid/ssl_cert
    fi

    if [ ! -f "/etc/squid/ssl_cert/squid.pem" ] || [ ! -f "/etc/squid/ssl_cert/squid.key" ]; then
        echo "Generating SSL certificates for HTTPS support..."
        if ! openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout /etc/squid/ssl_cert/squid.key -out /etc/squid/ssl_cert/squid.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=example.com"
        then
            echo "Error: Failed to generate SSL certificates." >&2
            return 1
        fi
    fi

    # Set proper permissions for the SSL certificates
    chown -R proxy:proxy /etc/squid/ssl_cert
    chmod -R 700 /etc/squid/ssl_cert

    # Restart Squid to apply changes
    echo "Restarting Squid service..."
    if ! systemctl restart "${squid_service}"; then
        echo "Error: Failed to restart Squid service." >&2
        return 1
    fi

    # Enable Squid to start on boot
    if ! systemctl enable "${squid_service}"; then
        echo "Error: Failed to enable Squid service on boot." >&2
        return 1
    fi

    echo "Squid HTTP/S proxy setup completed successfully."
    return 0
}

net_install_openconnect() {
    # https://software.opensuse.org/download.html?project=home%3Abluca%3Aopenconnect%3Arelease&;package=openconnect
    # Use local variables
    local distro version repo_distro repo_url repo_key_url apt_list_path gpg_key_path temp_file

    # Get the distribution name and version number
    distro=$(lsb_release -is)
    version=$(lsb_release -rs | cut -d'.' -f1) # Get major version number

    # Adjust the repository format based on the distribution
    if [[ "$distro" == "Debian" ]]; then
        repo_distro="Debian_${version}"
    elif [[ "$distro" == "Ubuntu" ]]; then
        repo_distro="Ubuntu_${version}.04"
    else
        echo "Unsupported distribution: $distro"
        return 1
    fi

    # Set URLs for the repository and key
    repo_url="http://download.opensuse.org/repositories/home:/bluca:/openconnect:/release/${repo_distro}/"
    repo_key_url="https://download.opensuse.org/repositories/home:bluca:openconnect:release/${repo_distro}/Release.key"
    apt_list_path="/etc/apt/sources.list.d/home:bluca:openconnect:release.list"
    gpg_key_path="/etc/apt/trusted.gpg.d/home_bluca_openconnect_release.gpg"

    # Check if the GPG key is valid
    temp_file=$(mktemp)
    if ! curl -fsSL "$repo_key_url" -o "$temp_file"; then
        echo "Error: Failed to download GPG key from $repo_key_url."
        rm -f "$temp_file"
        return 1
    fi

    if ! gpg --dearmor "$temp_file" >/dev/null; then
        echo "Error: Failed to process GPG key."
        rm -f "$temp_file"
        return 1
    fi

    rm -f "$temp_file"

    # Add the OpenConnect repository
    echo "deb $repo_url /" | tee "$apt_list_path" >/dev/null

    # Add the repository key
    if ! curl -fsSL "$repo_key_url" | gpg --dearmor | tee "$gpg_key_path" >/dev/null; then
        echo "Error: Failed to add the GPG key."
        return 1
    fi

    # Update package list and install OpenConnect
    if ! apt-get update && apt-get install -y openconnect; then
        echo "Error: Failed to update and install openconnect."
        return 1
    fi

    echo "OpenConnect installed successfully."
    return 0
}

net_addConfig_openconnect() {
    # Local variables to avoid global scope issues
    local VPN_SERVER CERT_PATH CERT_PASSWORD SERVICE_NAME SERVICE_FILE

    echo "Please provide the following details for setting up the OpenConnect VPN:"

    read -rp "Service name (e.g., my-vpn): " SERVICE_NAME
    if [[ -z "$SERVICE_NAME" ]]; then
        echo "Error: Service name is required." >&2
        return 1
    fi

    # Service file location
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    if [[ -f "$SERVICE_FILE" ]]; then
        echo "Error: The SERVICE file already exists." >&2
        return 1
    fi

    # Use -rp for concise input with prompt, validate immediately after
    read -rp "VPN Server URL (e.g., https://Server:port): " VPN_SERVER
    if [[ -z "$VPN_SERVER" ]]; then
        echo "Error: VPN server URL is required." >&2
        return 1
    fi

    read -rp "Path to .p12 certificate file: " CERT_PATH
    if [[ ! -f "$CERT_PATH" ]]; then
        echo "Error: The .p12 certificate file does not exist at the specified path." >&2
        return 1
    fi

    read -rsp "Password for the .p12 certificate: " CERT_PASSWORD
    echo ""
    if [[ -z "$CERT_PASSWORD" ]]; then
        echo "Error: Certificate password is required." >&2
        return 1
    fi

    echo "Creating systemd service for OpenConnect VPN..."

    # Create systemd service file, handle error properly
    cat >"${SERVICE_FILE}" <<EOL || {
[Unit]
Description=OpenConnect VPN Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/bash -c '/bin/echo -n "${CERT_PASSWORD}" | /usr/sbin/openconnect --passwd-on-stdin -c "${CERT_PATH}" ${VPN_SERVER}'
KillSignal=SIGINT
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL
        echo "Error: Failed to create service file." >&2
        return 1
    }

    # Validate that service file creation succeeded
    if [[ ! -f "$SERVICE_FILE" ]]; then
        echo "Error: Service file could not be created." >&2
        return 1
    fi

    echo "Systemd service created at: ${SERVICE_FILE}"

    # Reload systemd to recognize new service, error handling
    systemctl daemon-reload || {
        echo "Error: Failed to reload systemd." >&2
        return 1
    }

    # Enable the service to start on boot, with proper error handling
    systemctl enable "${SERVICE_NAME}.service" || {
        echo "Error: Failed to enable VPN service." >&2
        return 1
    }

    # Start the VPN service immediately, with proper error handling
    systemctl start "${SERVICE_NAME}.service" || {
        echo "Error: Failed to start VPN service." >&2
        return 1
    }

    echo "The service '${SERVICE_NAME}' will now automatically start at boot and reconnect on failure."

    # Bonus, monitor connection and restart service using cron
    # * * * * * ping -c 10 10.10.10.1 > /dev/null || systemctl restart "${SERVICE_NAME}.service"
}

# To be developed and tested (not working)
softether_install() {
    ip tuntap add mode tap name soft
    ip link set dev soft up
    ip link delete soft
    ip addr add 192.168.30.1/24 brd + dev soft
    ip addr add 192.168.30.1/24 brd + dev tap0

    cat >'/etc/network/interfaces.d/softether' <<'EOFX'
auto soft0
iface soft0 inet static
    address 192.168.30.1
    netmask 255.255.255.0
    pre-up ip tuntap add mode tap soft0
    up ip link set soft0 up
    down ip link set soft0 down
    post-down ip tuntap del tap soft0
EOFX
    systemctl restart networking
}

net_softether_install() {
    local install_dir="/usr/local/softether"
    local M1
    local M2
    local RTM
    local IFS
    local tmpDIR="/tmp/vpnserver"
    local tmp="/tmp"

    case "$(uname -m)" in
    aarch64)
        M1="_ARM_64bit"
        M2="arm64"
        ;;
    x86_64)
        M1="_Intel_x64_or_AMD64"
        M2="x64"
        ;;
    *)
        echo "Unsupported CPU"
        exit 1
        ;;
    esac

    # Update system & Get build tools
    apt-get update && apt-get -y install build-essential wget curl libreadline-dev libncurses-dev libssl-dev zlib1g-dev

    # Define softether version
    RTM=$(curl http://www.softether-download.com/files/softether/ | grep -o 'v[^"]*e' | grep rtm | tail -1)
    IFS='-' read -ra RTMS <<<"${RTM}"

    # Get softether source
    wget "http://www.softether-download.com/files/softether/${RTMS[0]}-${RTMS[1]}-${RTMS[2]}-${RTMS[3]}-${RTMS[4]}/Linux/SoftEther_VPN_Server/64bit_-${M1}/softether-vpnserver-${RTMS[0]}-${RTMS[1]}-${RTMS[2]}-${RTMS[3]}-linux-${M2}-64bit.tar.gz" -O ${tmp}/softether-vpnserver.tar.gz || exit 1

    # Extract softether source & Remove unused file
    tar -xzvf ${tmp}/softether-vpnserver.tar.gz -C ${tmp} && rm ${tmp}/softether-vpnserver.tar.gz

    # Workaround for 18.04+
    #sed -i 's|OPTIONS=-O2|OPTIONS=-no-pie -O2|' Makefile

    # Build softether (i_read_and_agree_the_license_agreement)
    make -C ${tmpDIR} || {
        echo "Error: failed to compile."
        exit 1
    }

    # Change file permission
    chmod 600 ${tmpDIR}/* && chmod +x ${tmpDIR}/vpnserver && chmod +x ${tmpDIR}/vpncmd
    echo "${RTMS[1]}-${RTMS[2]}-${RTMS[3]}-${RTMS[4]}" >${tmpDIR}/version.txt

    # Link binary files
    # ln -sf /usr/local/softether/vpnserver /usr/local/bin/vpnserver
    # ln -sf /usr/local/softether/vpncmd /usr/local/bin/vpncmd

    # Add systemd service
    cat <<EOF >/usr/lib/systemd/system/vpnserver.service
[Unit]
Description=SoftEther VPN Server
After=network.target auditd.service

[Service]
Type=forking
EnvironmentFile=-${install_dir}/vpnserver 
ExecStart=${install_dir}/vpnserver start
ExecStop=${install_dir}/vpnserver stop
KillMode=process
Restart=on-failure
# Uncomment the below after creating tap_vpn bridge device
ExecStartPost=/usr/bin/sleep 1
ExecStartPost=/sbin/ip addr add 192.168.30.1/24 brd + dev tap_vpn
ExecStartPost=/sbin/ip addr add 192.168.31.1/24 brd + dev tap_uae

# Hardening
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadOnlyDirectories=/
ReadWriteDirectories=-${install_dir}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_BROADCAST CAP_NET_RAW CAP_SYS_NICE CAP_SYS_ADMIN CAP_SETUID

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p ${install_dir} && mv ${tmpDIR}/hamcore.se2 ${tmpDIR}/vpnserver ${tmpDIR}/vpncmd ${tmpDIR}/version.txt ${install_dir} && rm -rf ${tmpDIR:?}/

    # ip tuntap add mode tap name softether
    # ip addr add 192.168.30.1/24 dev softether
    # ip link set dev softether up

    read -rp "Place your 'vpn_server.config' in ${install_dir} and press Enter"

    systemctl daemon-reload && systemctl enable vpnserver && systemctl restart vpnserver
}

net_enable_ip_forward() {
    local NIC
    # Get the "public" interface from the default route
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

    echo "------------- Adding -------------"
    echo "net.ipv4.ip_forward = 1" | tee /etc/sysctl.d/ip_forward.conf
    echo "net.ipv6.conf.all.forwarding = 1" | tee -a /etc/sysctl.d/ip_forward.conf
    echo "------------- Reloading -------------"
    sysctl --system
    echo "------------- Adding iptables rules -------------"

    cat >'/etc/iptables/rules.v4' <<EOFX
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# XRDP
-N XRDP
-A INPUT -p tcp --dport 3389 -j DROP
-I INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-I INPUT -p tcp --dport 3389 -j XRDP

-I FORWARD -m state --state NEW,ESTABLISHED,RELATED -d 192.168.0.0/16 -o ${NIC} -j REJECT
-I FORWARD -m state --state NEW,ESTABLISHED,RELATED -d 172.16.0.0/12 -o ${NIC} -j REJECT
-I FORWARD -m state --state NEW,ESTABLISHED,RELATED -d 10.0.0.0/8 -o ${NIC} -j REJECT
-I FORWARD -m state --state NEW,ESTABLISHED,RELATED -d 100.64.0.0/10 -o ${NIC} -j REJECT

-I OUTPUT -d 192.168.0.0/16 -o ${NIC} -j DROP
-I OUTPUT -d 172.16.0.0/12  -o ${NIC} -j DROP
-I OUTPUT -d 10.0.0.0/8 -o ${NIC} -j DROP
-I OUTPUT -d 100.64.0.0/10  -o ${NIC} -j DROP
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

-A POSTROUTING -o ${NIC} -j MASQUERADE
COMMIT

# iptables -t nat -I POSTROUTING -o ${NIC} -j MASQUERADE
# iptables -t nat -D POSTROUTING -s 192.168.30.0/24 -o ${NIC} -j MASQUERADE
EOFX
    echo
    echo "- Restarting netfilter-persistent..."
    systemctl restart netfilter-persistent
}

net_tune_kernel() {
    apt-get install irqbalance && systemctl enable --now irqbalance

    # Tune Kernel
    echo "------------- Adding -------------"
    # echo "net.ipv4.ip_local_port_range = 1024 65535" | tee /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.ip_local_port_range = 16384 60999" | tee /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_congestion_control = bbr" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.default_qdisc = fq_codel" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_fastopen = 3" | tee -a /etc/sysctl.d/tune_kernel.conf

    echo "net.core.rmem_default = 1048576" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.rmem_max = 16777216" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.wmem_default = 1048576" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.wmem_max = 16777216" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.optmem_max = 16777216" | tee -a /etc/sysctl.d/tune_kernel.conf

    echo "net.ipv4.tcp_rmem = 4096 1048576 16777216" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_wmem = 4096 1048576 16777216" | tee -a /etc/sysctl.d/tune_kernel.conf

    echo "net.ipv4.tcp_mtu_probing = 1" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_no_metrics_save = 1" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_mem = 3145728 4194304 6291456" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_rfc1337 = 1" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.somaxconn = 16384" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.netdev_max_backlog = 16384" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.core.netdev_budget = 1000" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_slow_start_after_idle = 0" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_max_syn_backlog = 4096" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_max_tw_buckets = 1440000" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.netfilter.nf_conntrack_max = 1048576" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.netfilter.nf_conntrack_buckets = 262144" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.ipv4.tcp_fin_timeout = 30" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30" | tee -a /etc/sysctl.d/tune_kernel.conf

    echo "vm.dirty_ratio = 10   " | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "vm.dirty_background_ratio = 5" | tee -a /etc/sysctl.d/tune_kernel.conf
    echo "vm.vfs_cache_pressure = 50" | tee -a /etc/sysctl.d/tune_kernel.conf

    # echo "net.ipv4.tcp_tw_reuse = 1" | tee -a /etc/sysctl.d/tune_kernel.conf
    # echo "net.ipv4.tcp_adv_win_scale = 2" | tee -a /etc/sysctl.d/tune_kernel.conf
    # echo "net.ipv4.tcp_timestamps = 0" | tee -a /etc/sysctl.d/tune_kernel.conf

    echo "------------- Reloading -------------"
    sysctl --system

    echo "------------- Checking settings -------------"
    # sysctl net.core.default_qdisc
    # sysctl net.ipv4.tcp_max_syn_backlog
    # sysctl net.core.rmem_default
    # sysctl net.core.rmem_max
    # sysctl net.core.wmem_default
    # sysctl net.core.wmem_max
    # sysctl net.core.optmem_max
    # sysctl net.ipv4.tcp_tw_reuse
    # sysctl net.ipv4.tcp_rmem
    # sysctl net.ipv4.tcp_wmem
    # sysctl net.ipv4.tcp_timestamps
    # sysctl net.ipv4.tcp_mtu_probing
    # sysctl net.ipv4.tcp_mem
    # sysctl net.ipv4.tcp_rfc1337
    # sysctl net.ipv4.tcp_adv_win_scale
    # sysctl vm.swappiness
    # sysctl net.core.somaxconn
    # sysctl net.core.netdev_max_backlog
    # sysctl net.core.netdev_budget
    # sysctl net.ipv4.tcp_slow_start_after_idle
    # sysctl net.netfilter.nf_conntrack_max
    # sysctl vm.dirty_ratio
    # sysctl vm.dirty_background_ratio
    # sysctl vm.vfs_cache_pressure
    # # sysctl net.ipv4.tcp_tw_recycle
    # sysctl net.ipv4.tcp_window_scaling
    # sysctl net.ipv4.ip_local_port_range
    # sysctl net.ipv4.tcp_fin_timeout
}

tailscale_manage() {
    local choice
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. tailscale_install"
        echo "2. tailscale_configure"

        echo "0. Quit"
        echo -e "\033[0m"
        read -rp "Enter your choice: " choice

        case $choice in
        1) tailscale_install ;;
        2) tailscale_configure ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

tailscale_install() {
    curl -fsSL https://tailscale.com/install.sh | sh
}

# Function to prompt for yes/no question
function prompt_yes_no() {
    local answer
    while true; do
        read -rp "$1 (y/n): " yn
        case $yn in
        [Yy]*)
            echo "yes"
            break
            ;;
        [Nn]*)
            echo "no"
            break
            ;;
        *) echo "Please answer yes or no." ;;
        esac
    done
}

tailscale_configure() {
    local advertise_exit_node
    local advertise_routes_response
    local advertise_routes
    local accept_routes
    # tailscale up --advertise-exit-node --advertise-routes=192.168.10.0/24,192.168.20.0/24 --accept-routes

    # Prompt for advertise-exit-node
    advertise_exit_node=$(prompt_yes_no "Do you want to advertise as exit node?")

    # Prompt for advertise-routes
    advertise_routes_response=$(prompt_yes_no "Do you want to advertise specific routes?")
    if [ "$advertise_routes_response" == "yes" ]; then
        read -rp "Enter the routes to advertise (e.g., 192.168.10.0/24,192.168.20.0/24): " advertise_routes
    else
        advertise_routes=""
    fi

    # Prompt for accept-routes
    accept_routes=$(prompt_yes_no "Do you want to accept routes?")

    # Construct the tailscale command
    local tailscale_cmd="tailscale up"
    if [ "$advertise_exit_node" == "yes" ]; then
        tailscale_cmd+=" --advertise-exit-node"
    fi
    if [ -n "$advertise_routes" ]; then
        tailscale_cmd+=" --advertise-routes=$advertise_routes"
    fi
    if [ "$accept_routes" == "yes" ]; then
        tailscale_cmd+=" --accept-routes"
    fi

    # Execute the tailscale command
    echo "Executing Tailscale command: $tailscale_cmd"
    eval $tailscale_cmd
}

cloudflared_manage() {
    local choice
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. cloudflared_install"
        echo "2. cloudflared_update"

        echo "0. Quit"
        echo -e "\033[0m"
        read -rp "Enter your choice: " choice

        case $choice in
        1) cloudflared_install ;;
        2) cloudflared_update ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

get_cloudflared_arch() {
    local arch
    case "$(get_arch)" in
    amd64) arch="amd64" ;;
    i386) arch="386" ;;
    arm64) arch="arm64" ;;
    arm32) arch="arm" ;;
    Unknown)
        echo "Unsupported system architecture"
        exit 1
        ;;
    esac
    echo "$arch"
}

cloudflared_install() {
    local token
    read -rp "Enter tunnel token: " token
    local arch=$(get_cloudflared_arch)
    curl -L --output cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.deb" &&
        dpkg -i cloudflared.deb &&
        cloudflared service install "${token}" &&
        rm cloudflared.deb
}

cloudflared_update() {
    local arch=$(get_cloudflared_arch)
    curl -L --output cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.deb" &&
        dpkg -i cloudflared.deb &&
        systemctl restart cloudflared.service &&
        rm cloudflared.deb
}

get_arch() {
    # Check the architecture
    arch=$(uname -m)
    case "$arch" in
    x86_64) echo "amd64" ;;
    i386 | i686) echo "i386" ;;
    aarch64) echo "arm64" ;;
    armv7l) echo "arm32" ;;
    *) echo "Unknown" ;;
    esac
    # Check the system bitness
    # if [ "$(getconf LONG_BIT)" == "64" ]; then
    #     bitness="64-bit"
    # else
    #     bitness="32-bit"
    # fi
    # Return the values
    echo "$architecture"
}

sys_manage() {
    local choice
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. List Users"
        echo "2. List Groups"
        echo "3. Clean up (autoremove, autoclean, update)"
        echo "4. Install Standard Packages"
        echo "5. Install & configure SSH (port 4444, enable root)"
        echo "6. Configure terminal and system banners"
        echo "7. Install (build-essential software-properties-common python3)"
        echo "8. Add SWAP memory"
        echo "9. Read APT Config"
        echo "10. Install rsnapshot"
        echo "11. Reload Cron (root profile)"
        echo "12. Install Auto Mount USB"
        echo "0. Quit"
        echo -e "\033[0m"
        read -rp "Enter your choice: " choice

        case $choice in
        1)
            sys_list_users_new
            read -rp "Press Enter to go back " choice
            ;;
        2) sys_list_groups ;;
        3) sys_cleanUp ;;
        4) sys_std_pkg_install ;;
        5) sys_SSH_install ;;
        6) sys_config_setup ;;
        7) sys_more_pkg_install ;;
        8) sys_swap_add ;;
        9) sys_read_apt_config ;;
        10) sys_rsnapshot_install ;;
        11) sys_cron_reload ;;
        12) mount_usb_install ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

sys_init() {
    sys_std_pkg_install
    sys_SSH_install
    sys_config_setup
}

sys_cron_reload() {
    if [ ! -d "$cron_dir_user" ]; then
        echo "Error: Directory $cron_dir_user does not exist."
        return
    fi
    cat "${cron_dir_user}"/* 2>/dev/null | crontab - || {
        echo "Error loading cron jobs"
        return
    }
    echo -e "Loaded cron jobs:\n"
    crontab -l
}

sys_rsnapshot_install() {
    # Check if rsnapshot is installed
    if ! command -v rsnapshot &>/dev/null; then
        echo "rsnapshot is not installed. Installing rsnapshot..."
        apt-get update && apt-get -y install rsnapshot
    fi

    echo -e "\nAdding log rotation.."
    cat >/etc/logrotate.d/rsnapshot <<EOFX
/opt/backup/*/*.log {
    size 20M
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root root
}
EOFX
    mkdir -p /opt/backup
    chown root:root /opt/backup
    chmod 640 /opt/backup
    mkdir -p /root/.config/rsnapshot/

    echo "Writing config into /root/.config/rsnapshot/sample.conf..."
    cat >"/root/.config/rsnapshot/sample.conf" <<'EOFX'
# rsnapshot -c /root/.config/rsnapshot/test.conf sync && rsnapshot -c /root/.config/rsnapshot/test.conf hourly
#################################################
# This file requires tabs between elements      #
# Directories require a trailing slash:         #
#   right: /home/                               #
#   wrong: /home                                #
#################################################
config_version	1.2

snapshot_root	/opt/backup/test

cmd_cp		/bin/cp
cmd_rm		/bin/rm
cmd_rsync	/usr/bin/rsync
cmd_ssh	/usr/bin/ssh
cmd_logger	/usr/bin/logger
cmd_du		/usr/bin/du
#cmd_preexec	/path/to/preexec/script
#cmd_postexec	/path/to/postexec/script

retain	hourly	4
retain	daily	7
retain	weekly	4
retain	monthly	6

verbose		2
loglevel	3
logfile	/opt/backup/test/log.log

lockfile	/var/run/test.pid
rsync_short_args	-ahz
rsync_long_args	--delete --numeric-ids --delete-excluded --info=NAME,COPY,DEL,misc2,flist0 --stats
ssh_args	-p 22
# ssh_args	-o ConnectTimeout=5

#include	???
#exclude	???
#include_file	/path/to/include/file
#exclude_file	/path/to/exclude/file

link_dest	1
sync_first	1
use_lazy_deletes	1
rsync_numtries	20
###############################
backup_exec	/bin/date "+ backup of test started at %c"
# backup_exec	Servo.sh db_backup db_xyz /root/
# backup_exec	ssh -p 22 root@example.com "rm -f /var/www/user/example.com/*.sql.xz;Servo.sh db_backup db_xyz /var/www/user/example.com/"
# backup	root@ip:/root/test/	./
backup_exec	/bin/date "+ backup of test ended at %c"
EOFX

    echo "Writing cron into ${cron_dir}/rsnapshot..."

    cat >"${cron_dir}/rsnapshot" <<'EOFX'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Schedule backup every 6 hours
# 13 */6 * * * root rsnapshot -c /root/.config/rsnapshot/test.conf sync && rsnapshot -c /root/.config/rsnapshot/test.conf hourly

# Schedule backup every day at 1AM
# 12 1 * * * root rsnapshot -c /root/.config/rsnapshot/test.conf daily

# Schedule backup every Monday at 1AM
# 11 1 * * 1 root rsnapshot -c /root/.config/rsnapshot/test.conf weekly

# Schedule backup on the 1st day of every month at 1AM
# 10 1 1 * * root rsnapshot -c /root/.config/rsnapshot/test.conf monthly

#  ┌────────── minute (0 - 59)
#  │ ┌──────── hour (0 - 23)
#  │ │ ┌────── day of month (1 - 31)
#  │ │ │ ┌──── month (1 - 12) OR jan,feb,mar,apr ...
#  │ │ │ │ ┌── day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
#  ↓ ↓ ↓ ↓ ↓
#  * * * * * user-name command to be executed
EOFX
}

sys_swap_add() {
# Turn off swap: swapoff -a && rm /swapfile
    # Ask user for swap size in MB (default: 2048MB)
    read -rp "Enter swap size in MB [2048]: " swap_size
    swap_size=${swap_size:-2048}

    # Ask user for swap file location (default: /swapfile)
    read -rp "Enter swap file location [/swapfile]: " swap_location
    swap_location=${swap_location:-/swapfile}

    # Calculate buffer size for dd (in 2MB blocks)
    buffer_size=$((swap_size / 10))

    # Create swap file
    echo "Creating ${swap_size}MB swap file at ${swap_location}..."
    dd if=/dev/zero of=$swap_location bs=10M count=$buffer_size
    # fallocate -l 1G "$swap_location"

    if [ -e "$swap_location" ]; then
        # Set permissions
        chmod 600 $swap_location

        # Set up swap space
        mkswap $swap_location

        # Activate the swap file
        swapon $swap_location

        # Check if swap was successfully added
        if grep -q "$swap_location" /proc/swaps; then
            echo "Swap file has been created and activated."

            echo "Setting vm.swappiness=10 ..."
            # Set swappiness to 10
            sysctl vm.swappiness=10
            # Make the swappiness setting persistent across reboots
            echo "vm.swappiness = 10" | tee -a  /etc/sysctl.d/tune_kernel.conf

            # Ask user if they want to add entry to /etc/fstab for persistence
            read -rp "Add entry to /etc/fstab for persistence? (Y/n): " add_to_fstab
            add_to_fstab=${add_to_fstab:-Y}
            if [ "$add_to_fstab" == "y" ] || [ "$add_to_fstab" == "Y" ]; then
                # Add entry to /etc/fstab for persistence
                echo "$swap_location none swap sw 0 0" | tee -a /etc/fstab
                echo "Entry added to /etc/fstab for persistence."
            else
                echo "Entry not added to /etc/fstab. Swap file will not be persistent across reboots."
            fi
        else
            echo "Failed to activate swap file. Please check the configuration."
        fi
    else
        echo "Failed to create swap file. Please check if you have necessary permissions and free disk space."
    fi

}

sys_list_users_new() {
    default_users=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "_apt" "systemd-network" "systemd-timesync" "systemd-resolve" "messagebus" "sshd")
    local row_count=0
    # Define colors
    local BG_GRAY='\033[48;5;236m'
    local RED='\033[1;31m'
    local GREEN='\033[1;32m'
    local YELLOW='\033[1;33m'
    local BLUE='\033[1;34m'
    local PURPLE='\033[1;35m'
    local CYAN='\033[1;36m'
    local RESET='\033[0m'

    # Define column widths
    local COL1=30 # Username (UID)
    local COL2=6  # Locked
    local COL3=6  # HasPass
    local COL4=6  # System
    local COL5=30 # Groups
    local COL6=35 # Home

    # Print header
    printf "${CYAN}%-${COL1}s${RESET}" "Username (UID)"
    printf "${CYAN}%-${COL2}s${RESET}" "Lock"
    printf "${CYAN}%-${COL3}s${RESET}" "Pass"
    printf "${CYAN}%-${COL4}s${RESET}" "Sys"
    printf "${CYAN}%-${COL5}s${RESET}" "Groups"
    printf "${CYAN}%-${COL6}s${RESET}\n" "Home"

    # Print separator line
    printf "%.0s-" {1..105}
    printf "\n"

    # Process each user
    # while IFS=: read -r username password uid gid info home shell; do
    while IFS=: read -r username password uid gid _ home _; do
        # Skip if username is empty
        [ -z "$username" ] && continue
        if [[ " ${default_users[*]} " =~  ${username}  ]]; then continue; fi

        # Check if system user (UID < 1000)
        local is_system="NO"
        if [ "$uid" -lt 1000 ]; then
            is_system="YES"
        fi

        # Check password status
        local has_pass="NO"
        local is_locked="NO"
        if [ -f "/etc/shadow" ]; then
            local shadow_line
            shadow_line=$(sudo grep "^${username}:" /etc/shadow)
            if [ -n "$shadow_line" ]; then
                local pass_field
                pass_field=$(echo "$shadow_line" | cut -d: -f2)
                if [ "$pass_field" != "*" ] && [ "$pass_field" != "!" ]; then
                    has_pass="YES"
                fi
                if [[ "$pass_field" == *'!'* ]]; then
                    is_locked="YES"
                fi
            fi
        fi

        # Get groups
        local groups
        groups=$(groups "$username" 2>/dev/null | cut -d: -f2 | sed 's/^ //')
        if [ -z "$groups" ]; then
            groups=$(id -Gn "$username" 2>/dev/null)
        fi
        groups="${groups// /, }"

        # Format username with UID
        local username_uid="${username} (${uid})"

        if ((row_count % 2 == 1)); then printf "%b" "$BG_GRAY"; fi

        # Print user information with colors
        printf "${YELLOW}%-${COL1}s${RESET}" "${username_uid}"

        if ((row_count % 2 == 1)); then printf "%b" "$BG_GRAY"; fi

        if [ "$is_locked" = "YES" ]; then
            printf "${RED}%-${COL4}s${RESET}" "Y"
        else
            printf "${GREEN}%-${COL4}s${RESET}" "N"
        fi

        if ((row_count % 2 == 1)); then printf "%b" "$BG_GRAY"; fi

        # Fixed color output for status fields
        if [ "$has_pass" = "YES" ]; then
            printf "${GREEN}%-${COL2}s${RESET}" "Y"
        else
            printf "${RED}%-${COL2}s${RESET}" "N"
        fi

        if ((row_count % 2 == 1)); then printf "%b" "$BG_GRAY"; fi

        if [ "$is_system" = "YES" ]; then
            printf "${BLUE}%-${COL3}s${RESET}" "Y"
        else
            printf "${PURPLE}%-${COL3}s${RESET}" "N"
        fi

        if ((row_count % 2 == 1)); then printf "%b" "$BG_GRAY"; fi

        printf "${PURPLE}%-${COL5}s${RESET}" "${groups}"

        if ((row_count % 2 == 1)); then printf "%b" "$BG_GRAY"; fi

        printf "${CYAN}%-${COL6}s${RESET}\n" "${home}"

        row_count=$((row_count + 1))
    done </etc/passwd
}

sys_list_users() {
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

sys_list_groups() {
    # Check if the 'members' command is available
    validate_command "members" || return 1

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

sys_cleanUp() {
    apt-get autoremove -y
    apt-get autoclean
    apt-get update
    apt-get clean
}

sys_read_apt_config() {
    apt-config dump | grep -we Recommends -e Suggests
}

sys_std_pkg_install() {
    local confirmation
    # Disable Install Recommends & Suggests
    # apt-config dump | grep -we Recommends -e Suggests | sed s/1/0/ | tee /etc/apt/apt.conf.d/99no-recommends

    # Install the "standard" task automatically
    # apt-get install -y tasksel
    # echo "standard" | tasksel install
    # Hetzner disables InstallRecommends using this:
    # /etc/apt/apt.conf.d/00InstallRecommends
    apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        iptables-persistent \
        bash-completion \
        curl \
        wget \
        git \
        nano \
        zip \
        unzip \
        p7zip-full \
        bzip2 \
        gzip \
        htop \
        net-tools \
        nftables \
        bind9-dnsutils \
        cron \
        logrotate \
        ncurses-term \
        mailcap \
        iproute2 \
        pciutils \
        bc \
        jq \
        dmidecode \
        members \
        xz-utils \
        ca-certificates \
        lynx

    if dpkg -l | grep -q "exim4"; then
        read -rp "Remove Exim4? (y/n) " confirmation
        if [[ "$confirmation" == "y" ]]; then
            echo -e "\nRunning apt purge exim4-*\n"
            apt purge -y exim4-*
        fi
    fi
    # Clean up
    apt-get autoremove -y
    apt-get clean

    echo "Standard packages installation complete."
}

config_set() {
    local key="$1"
    local val="$2"
    local file="$3"
    awk -v key="$key" -v val="$val" '{gsub("^#*[[:space:]]*" key "[[:space:]]+.*", key " " val); print}' "$file" | awk '{if (NF > 0) {if (!seen[$0]++) print} else {print}}' >"${file}.tmp" && mv "${file}.tmp" "$file"
}

sys_SSH_install() {
    local sshd_config="/etc/ssh/sshd_config"
    local sshd_config_dir="/etc/ssh/sshd_config.d"

    if ! dpkg -l | grep -q "^ii\s*openssh-server\s"; then
        # Update package lists & Install SSH server
        apt-get update && apt-get install -y openssh-server || return 1
    fi

    # Backup the original configuration
    if [ -e "${sshd_config}_backup" ]; then
        echo "Backup file '${sshd_config}_backup' already exists."
    else
        cp "$sshd_config" "${sshd_config}_backup"
    fi

    # Enable root login (not recommended for production)
    # sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' "$sshd_config"
    # sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' "$sshd_config"
    config_set PermitRootLogin yes "$sshd_config"

    # Enable ClientAliveInterval
    config_set ClientAliveInterval 120 "$sshd_config"

    # Disable root's ability to use password-based authentication
    # sed -i 's/PermitRootLogin yes/PermitRootLogin without-password/' "$sshd_config"

    # Set SSH port to 4444
    config_set Port 4444 "$sshd_config"
    # sed -i 's/#Port 22/Port 4444/' "$sshd_config"

    # Disable password authentication (use key-based authentication)
    # sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$sshd_config"

    # Enable PasswordAuthentication
    # sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' "$sshd_config"
    # sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' "$sshd_config"
    # sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' "$sshd_config"

    config_set PasswordAuthentication yes "$sshd_config"

    # Allow only specific users or groups to log in via SSH (replace with your username)
    # echo "AllowUsers your_username" >> "$sshd_config"

    if [ -f "/etc/ssh/sshd_config.d/50-cloud-init.conf" ]; then
        mv "/etc/ssh/sshd_config.d/50-cloud-init.conf" "/etc/ssh/sshd_config.d/50-cloud-init.conf.disabled" >/dev/null
    fi

    # Check if directory exists and is readable
    if [ -d "$sshd_config_dir" ] && [ -r "$sshd_config_dir" ]; then
        # Check if sshd_config_dir contains any files (excluding . and ..)
        if find "$sshd_config_dir" -maxdepth 1 -type f | read -r; then
            # Warning message in yellow color
            echo -e "\033[1;33mWARNING: Files detected in $sshd_config_dir"
            echo -e "These may override SSH configuration. Please review them.\033[0m"
        fi
    fi

    local AUTH_KEYS="/root/.ssh/authorized_keys"
    local SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICBZHBIqC2RMXrqf94kDvAzqLB0ymgPn4eU/VTSMgtTy"
    local SSH_KEY2="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJA3sRPDekFDYji0tObnDQgteucMQbPr7EhtGvIYnGbG solaris"


    # Check if authorized_keys exists
    if [ -f "$AUTH_KEYS" ]; then
        # Create a temporary file
        local TEMP_FILE=$(mktemp)
        
        # Remove lines containing "Please login as the user" and store other lines
        grep -v "Please login as the user" "$AUTH_KEYS" > "$TEMP_FILE"
        
        # Add the new SSH key at the top of the file
        echo "$SSH_KEY" > "$AUTH_KEYS"
        echo "$SSH_KEY2" >> "$AUTH_KEYS"
        cat "$TEMP_FILE" >> "$AUTH_KEYS"
        
        # Remove temporary file
        rm "$TEMP_FILE"
        
        # Set proper permissions
        chmod 600 "$AUTH_KEYS"
        
        echo -e "\033[32mSSH key has been updated in $AUTH_KEYS\033[0m"
    else
        # If file doesn't exist, create it with proper permissions
        mkdir -p "$(dirname "$AUTH_KEYS")"
        echo "$SSH_KEY" > "$AUTH_KEYS"
        echo "$SSH_KEY2" >> "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"
        echo "Created new $AUTH_KEYS file with SSH key"
    fi

    # Restart SSH service (for changes to take effect immediately)

    # Check if the ssh.socket unit is active and enabled.
    if systemctl is-active --quiet ssh.socket || systemctl is-enabled --quiet ssh.socket; then
        echo "SSH is running as a socket. Reloading and restarting."
        systemctl daemon-reload && systemctl restart ssh.socket
    elif systemctl is-active --quiet ssh || systemctl is-enabled --quiet ssh; then
        echo "SSH is running as a service (ssh). Restarting."
        systemctl restart ssh
    else
        echo "Attempting to restart sshd service as a fallback."
        systemctl restart sshd
    fi

    # Verify the status after attempting a restart.
    if systemctl is-active --quiet ssh.socket; then
        echo "ssh.socket is active."
    elif systemctl is-active --quiet ssh; then
        echo "ssh service is active."
    elif systemctl is-active --quiet sshd; then
        echo "sshd service is active."
    else
        echo "Warning: SSH server does not appear to be active after restart attempt."
    fi

}

sys_set_grub_timeout() {
    local TIMEOUT=3

    [ ! -f "/etc/default/grub" ] && {
        echo "Grub configuration file not found."
        return 1
    }

    sed -i "s/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=$TIMEOUT/" /etc/default/grub || {
        echo "Error: Failed to set Grub timeout."
        return 1
    }
    update-grub || {
        echo "Error: Failed to update Grub."
        return 1
    }

    echo "Grub timeout has been set to $TIMEOUT seconds."
}

sys_config_setup() {
    local restore_choice
    local bashrc="/etc/bash.bashrc"

    echo "Updating Grub timeout.."
    sys_set_grub_timeout

    echo "Setting server's timezone to Asia/Dubai"
    timedatectl set-timezone Asia/Dubai || echo "Failed to set timezone"
    echo ""

    # Check if Backup exist
    if [ -e "${bashrc}.backup" ]; then
        read -rp "Do you want to restore the original configuration from the backup? (y/n): " restore_choice
        if [ "$restore_choice" == "y" ]; then
            if cp ${bashrc}.backup ${bashrc}; then
                echo "Original configuration has been restored."
            else
                echo "Failed to restore original configuration."
            fi
            return
        fi
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

    if [ -e "/etc/issue.backup" ]; then
        echo "Skipping Backup (already exists) '/etc/issue.backup'."
    else
        echo -e "Creating backup (/etc/issue.backup)...\n"
        cp /etc/issue /etc/issue.backup
    fi
    cat >"/etc/issue" <<EOFX
\e{lightblue}\s \m \r (Server Time: \t\e{reset})
\e{lightblue}\S{PRETTY_NAME} \v\e{reset}
\e{lightgreen}\n.\o : \4\e{reset}
EOFX

    # Backup the original configuration
    if [ -e "/etc/motd.backup" ]; then
        echo "Skipping Backup (already exists) '/etc/motd.backup'."
    else
        echo -e "Creating backup (/etc/motd.backup)...\n"
        cp /etc/motd /etc/motd.backup
    fi
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
# lshw -C display

# Get RAM information
ram_info=$(free -h | grep "Mem:" | awk '{print $3 " / " $2}')

# Get Machine information
machine_info="Supper User Required"
if [[ $EUID -eq 0 ]]; then
    machine_info=$(dmidecode -t system | grep -E "Manufacturer:|Product Name:" | awk -F': ' '{print $2}' | tr -d '\0' | tr '\n' ' ')

    if [ -z "$machine_info" ]; then
        if [ -e "/sys/firmware/devicetree/base/model" ]; then
            machine_info=$(tr -d '\0' < /sys/firmware/devicetree/base/model)
        fi
    fi
fi

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

media_manage() {
    while true; do
        echo "Choose an option:"
        echo "1. Install FFMPEG"
        echo "2. Install go-chromecast"
        echo "3. Install catt (Cast All The Things) using pipx for the current user"
        echo "4. Install mkvtoolnix"
        echo "5. Install GG Bot Upload Assistant in the current dir"
        echo "6. Install mediainfo"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) media_ffmpeg_install ;;
        2) media_go_chromecast_install ;;
        3) pipx install catt ;;
        4) media_mkvtoolnix_install ;;
        5) gg_bot_upload_assistant_setup ;;
        6) media_mediainfo_install ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

media_mediainfo_install() {
    # Determine the system architecture
    arch=$(dpkg --print-architecture)
    echo "Detected architecture: $arch"

    if [ "$arch" = "amd64" ] || [ "$arch" = "i386" ]; then
        echo "Setting up MediaArea repository for x86..."

        # Download the repository package for x86 systems
        wget https://mediaarea.net/repo/deb/repo-mediaarea_1.0-26_all.deb || {
            echo "Error: Failed to download repository package for x86."
            return 1
        }

        # Install the downloaded package
        dpkg -i repo-mediaarea_1.0-26_all.deb || {
            echo "Error: Failed to install the repository package."
            rm -f repo-mediaarea_1.0-26_all.deb
            return 1
        }
        # Clean up the downloaded file
        rm -f repo-mediaarea_1.0-25_all.deb

    elif [ "$arch" = "arm64" ] || [ "$arch" = "armhf" ]; then
        echo "Setting up MediaArea repository for ARM (arm64/armhf)..."

        # Download and install the repository key
        wget "https://mediaarea.net/repo/deb/debian/keyring.gpg" -O /etc/apt/trusted.gpg.d/mediaarea.gpg || {
            echo "Error: Failed to download the repository key."
            return 1
        }

        # Write the repository entry for ARM architectures
        echo "deb https://mediaarea.net/repo/deb/raspbian bookworm main" > /etc/apt/sources.list.d/mediaarea.list || {
            echo "Error: Failed to write repository list."
            return 1
        }

    else
        echo "Error: Unsupported architecture: $arch"
        return 1
    fi

    # Update package lists
    apt-get update || {
        echo "Error: apt-get update failed."
        return 1
    }

    # Install mediainfo
    apt-get install -y mediainfo || {
        echo "Error: Installation of mediainfo failed."
        return 1
    }

    echo "Mediainfo installation completed successfully."
}


media_go_chromecast_install() {
    local arch
    case "$(get_arch)" in
    amd64) arch="amd64" ;;
    i386) arch="386" ;;
    arm64) arch="arm64" ;;
    arm32) arch="armv7" ;;
    Unknown)
        echo "Unsupported system architecture"
        exit 1
        ;;
    esac
    echo "$arch"

    wget https://github.com/vishen/go-chromecast/releases/download/v0.3.1/go-chromecast_0.3.1_linux_${arch}.tar.gz
    tar -xzf go-chromecast_0.3.1_linux_${arch}.tar.gz go-chromecast
    install ./go-chromecast /usr/bin/
    rm -f ./go-chromecast go-chromecast_0.3.1_linux_${arch}.tar.gz

}

media_ffmpeg_install() {
    # local confirm
    # if command -v ffmpeg >/dev/null 2>&1; then
    #     read -rp "FFMPEG is already installed, are you sure you want to continue? (y/n)" confirm
    #     if [[ $confirm != "y" ]]; then
    #         echo "Aborting."
    #         return 0
    #     fi
    # fi

    # if [ ! -f "/etc/apt/sources.list.d/deb-multimedia.list" ]; then
    #     # Add Deb Multimedia repository
    #     echo "Adding Deb Multimedia repository..."
    #     echo "deb http://www.deb-multimedia.org $(lsb_release -sc) main non-free" | tee /etc/apt/sources.list.d/deb-multimedia.list >/dev/null
    #     # echo "deb-src http://www.deb-multimedia.org $(lsb_release -sc) main non-free" | tee -a /etc/apt/sources.list.d/deb-multimedia.list > /dev/null
    # fi
    # # Install Deb Multimedia keyring
    # echo "Installing Deb Multimedia keyring..."
    # apt-get update -oAcquire::AllowInsecureRepositories=true
    # apt-get install -y deb-multimedia-keyring --allow-unauthenticated

    # # Install ffmpeg non-free
    # echo "Installing ffmpeg..."
    # apt-get install -y ffmpeg
    local repo_url="https://github.com/fa1rid/FFmpeg-Builds/releases/download/latest"
    local arch=$(uname -m)
    local file=""

    if [[ "$arch" == "x86_64" ]]; then
        file="ffmpeg-master-latest-linux64-nonfree.tar.xz"
    elif [[ "$arch" == "aarch64" ]]; then
        file="ffmpeg-master-latest-linuxarm64-nonfree.tar.xz"
    else
        echo "Unsupported architecture: $arch"
        return 1
    fi

    echo "Downloading $file..."
    wget -q --show-progress "$repo_url/$file" -O "$file"

    if [[ ! -f "$file" ]]; then
        echo "Download failed!"
        return 1
    fi

    echo "Extracting $file..."
    tar -xJf "$file" --strip-components=2 -C /usr/local/bin ${file%.tar.xz}/bin || echo "Failed to extract!" && ffmpeg -version | grep "ffmpeg version"
}

media_mkvtoolnix_install() {
    wget -O /usr/share/keyrings/gpg-pub-moritzbunkus.gpg https://mkvtoolnix.download/gpg-pub-moritzbunkus.gpg || { echo "Failed to add GPG key" && return 1; }
    echo "deb [signed-by=/usr/share/keyrings/gpg-pub-moritzbunkus.gpg] https://mkvtoolnix.download/debian/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/mkvtoolnix.list
    apt-get update && apt-get install -y mkvtoolnix
}

gg_bot_upload_assistant_setup() {
    local REPO_URL="https://gitlab.com/NoobMaster669/gg-bot-upload-assistant.git"
    local PROJECT_DIR="gg-bot-upload-assistant"
    local TAG="3.1.5"
    local VENV_DIR="venv"
    local REQUIREMENTS_FILE="requirements/requirements.txt"
    local CONFIG_SAMPLE="samples/assistant/config.env"
    local CONFIG_FILE="config.env"
    local LOG_FILE="install_log.txt"

    # Log function
    log() {
        echo "$(date +"%Y-%m-%d %T") - $1" | tee -a "$LOG_FILE"
    }

    # Error handling function
    handle_error() {
        log "ERROR: $1"
        exit 1
    }

    # Update and upgrade system silently and unattended
    log "Updating system packages..."
    apt-get update -y && apt-get upgrade -y || handle_error "Failed to update system."

    # Install necessary system packages for Python, Git, and dependencies
    log "Installing required system packages..."
    apt-get install -y python3 python3-pip python3-venv python3-dev build-essential git || handle_error "Failed to install required packages."

    # Clone the repository if it doesn't exist
    if [ -d "$PROJECT_DIR" ]; then
        log "Project directory already exists. Skipping cloning."
    else
        log "Cloning repository..."
        git clone "$REPO_URL" || handle_error "Failed to clone repository."
    fi

    cd "$PROJECT_DIR" || handle_error "Failed to enter project directory."

    # Checkout the specific tag
    log "Checking out tag $TAG..."
    git checkout tags/"$TAG" || handle_error "Failed to checkout tag $TAG."

    # Set up Python virtual environment
    log "Setting up Python virtual environment..."
    python3 -m venv "$VENV_DIR" || handle_error "Failed to create virtual environment."

    # Activate virtual environment
    log "Activating virtual environment..."

    source "$VENV_DIR/bin/activate" || handle_error "Failed to activate virtual environment."

    # Upgrade pip and install wheel for modern package installations
    log "Upgrading pip and installing wheel..."
    pip install --upgrade pip wheel || handle_error "Failed to upgrade pip or install wheel."

    # Install Python dependencies
    log "Installing Python dependencies from $REQUIREMENTS_FILE..."
    pip install -r "$REQUIREMENTS_FILE" || handle_error "Failed to install dependencies."

    # Make the main script executable
    log "Making auto_upload.py executable..."
    chmod u+x auto_upload.py || handle_error "Failed to make auto_upload.py executable."

    # Set up the configuration file if it does not exist
    if [ -f "$CONFIG_FILE" ]; then
        log "Configuration file $CONFIG_FILE already exists. Skipping copying."
    else
        log "Copying configuration sample to project root..."
        cp "$CONFIG_SAMPLE" "$CONFIG_FILE" || handle_error "Failed to copy configuration file."
        log "Please edit $CONFIG_FILE to fill out required values."
    fi

    # Completion message
    log "Setup completed successfully. You can now run the script using:"
    log "python3 auto_upload.py -t <TRACKERS> -p \"<FILE_OR_FOLDER_TO_BE_UPLOADED>\" [OPTIONAL ARGUMENTS]"

    # Deactivate the virtual environment
    deactivate
    log "Virtual environment deactivated."

    log "Installation process completed."
}

rr_manage() {
    while true; do
        echo -e "\033[33m"
        echo "Choose an option:"
        echo "1. Install Autobrr (root)"
        echo "2. Upgrade Autobrr"
        echo "3. Manage qBittorrent"
        echo "4. Install cross-seed"
        echo "5. Install Prowlarr (prowlarr)"
        echo "6. Upgrade Prowlarr"
        echo "0. Quit"
        echo -e "\033[0m"
        read -rp "Enter your choice: " choice

        case $choice in
        1) autobrr_install ;;
        2) autobrr_upgrade ;;
        3) qBittorrent_manage ;;
        4) cross_seed_install ;;
        5) prowlarr_install ;;
        6) prowlarr_upgrade ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

cross_seed_install() {
    # Check if node is installed
    if ! command -v node &> /dev/null; then
        echo "Error: Node.js is not installed. Please install Node.js first."
        return 1
    fi

    # Check if npm is installed
    if ! command -v npm &> /dev/null; then
        echo "Error: npm is not installed. Please install npm (it usually comes with Node.js)."
        return 1
    fi

    echo "Installing cross-seed..."
    npm install -g cross-seed
    
    # Verify installation was successful
    if command -v cross-seed &> /dev/null; then
        cross-seed --version
    else
        echo "Error: cross-seed installation failed."
        return 1
    fi

    echo -e "\nPut config in /root/.cross-seed/ [config.js] [cross-seed.db] [torrent_cache] and press Enter..."
    read -r

    cat <<EOF | tee /etc/systemd/system/cross-seed.service >/dev/null
[Unit]
Description=cross-seed daemon
After=syslog.target network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=cross-seed daemon

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemctl daemon
    systemctl daemon-reload || error_exit "Failed to reload systemd daemon."

    systemctl enable --now cross-seed.service && systemctl status cross-seed.service || error_exit "Failed to enable and start the service."

}

autobrr_install() {
    local subdomain

    mkdir -p /opt/autobrr/config
    wget "$(curl -s https://api.github.com/repos/autobrr/autobrr/releases/latest | grep download | grep "linux_$(uname -m | sed 's/aarch64/arm64/').tar.gz" | cut -d\" -f4)" && tar -C /opt/autobrr -xzf autobrr*.tar.gz && rm autobrr*.tar.gz
    cat <<EOF | tee /etc/systemd/system/autobrr.service >/dev/null
[Unit]
Description=autobrr service
After=syslog.target network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/autobrr/autobrr --config=/opt/autobrr/config/

[Install]
WantedBy=multi-user.target
EOF

    echo "Creating nginx vHost"
    mkdir -p "/etc/nginx/sites-available/"
    
    read -rp "Enter subdomain for nginx: " subdomain

    cat >"/etc/nginx/sites-available/autobrr.conf" <<EOF
server {
    listen 443 ssl;
    http2 on;
    server_name $subdomain;
    include /etc/nginx/snippets/ssl.conf;
    include /etc/nginx/snippets/common.conf;
    access_log off;
    log_not_found off;

    # error_page 404 /404.html;

    client_max_body_size 10M;

    add_header X-Robots-Tag "noindex, nofollow";

    location / {
        proxy_pass http://127.0.0.1:7474/;
        proxy_http_version 1.1;
        proxy_set_header Host \$proxy_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$http_connection;
    }

}
EOF
    nginx_cert_install
    systemctl daemon-reload || error_exit "Failed to reload systemd daemon."
    systemctl enable --now autobrr.service && systemctl status autobrr.service || error_exit "Failed to enable and start the service."
    nginx -t && systemctl reload nginx
}

autobrr_upgrade() {
    systemctl stop autobrr.service
    wget "$(curl -s https://api.github.com/repos/autobrr/autobrr/releases/latest | grep download | grep "linux_$(uname -m | sed 's/aarch64/arm64/').tar.gz" | cut -d\" -f4)" && tar -C /opt/autobrr -xzf autobrr*.tar.gz && rm autobrr*.tar.gz
    systemctl start autobrr.service && systemctl status autobrr.service
}

prowlarr_install() {
    mkdir -p /opt/Prowlarr/data
    useradd -Nm -g media -s /bin/bash prowlarr

    wget "$(curl -s https://api.github.com/repos/Prowlarr/Prowlarr/releases/latest | grep download | grep "linux-core-$(uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/x64/').tar.gz" | cut -d\" -f4)" && tar -C /opt/Prowlarr/app -xzf Prowlarr*.tar.gz && chown prowlarr:media -R /opt/Prowlarr && rm Prowlarr*.tar.gz

    cat << EOF | tee /etc/systemd/system/prowlarr.service > /dev/null
[Unit]
Description=Prowlarr Daemon
After=syslog.target network.target
[Service]
User=prowlarr
Group=media
Type=simple

ExecStart=/opt/Prowlarr/app/Prowlarr -nobrowser -data=/opt/Prowlarr/data/
TimeoutStopSec=20
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || error_exit "Failed to reload systemd daemon."
    systemctl enable --now prowlarr.service && systemctl status prowlarr.service || error_exit "Failed to enable and start the service."
}

prowlarr_upgrade() {
    systemctl stop prowlarr.service
    wget "$(curl -s https://api.github.com/repos/Prowlarr/Prowlarr/releases/latest | grep download | grep "linux-core-$(uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/x64/').tar.gz" | cut -d\" -f4)" && tar -C /opt/Prowlarr/app -xzf Prowlarr*.tar.gz && chown prowlarr:media -R /opt/Prowlarr && rm Prowlarr*.tar.gz

    systemctl start prowlarr.service && systemctl status prowlarr.service
}

qBittorrent_manage() {
    # https://github.com/userdocs/qbittorrent-nox-static/releases?q=4.6.7&expanded=true
    # Function to display error message and exit
    error_exit() {
        echo "Error: $1" >&2
        exit 1
    }

    # Create Systemd service for current user
    # local service_dir="$HOME/.config/systemd/user"
    local service_file="/etc/systemd/system/qbittorrent.service"
    local install_dir="/opt/qBit"
    local config_dir="/opt/qBit/qBittorrent/config"

    # Function to hash the password using PBKDF2
    create_pass() {
        local pass="$1"
        local salt_b64=$(openssl rand -base64 16)
        local salt_hex=$(echo -n "$salt_b64" | openssl base64 -d -A | od -An -t x1 | tr -d ' ')
        local hash_b64=$(openssl kdf -binary -keylen 64 -kdfopt digest:SHA512 -kdfopt pass:"${pass}" -kdfopt hexsalt:${salt_hex} -kdfopt iter:100000 PBKDF2 | openssl base64 -A)
        local passLine="\"@ByteArray($salt_b64:$hash_b64)\""
        echo "$passLine"
    }
    upgrade_qbittorrent() {
        local download_url
        local version=$(curl -sL https://github.com/userdocs/qbittorrent-nox-static/releases/latest/download/dependency-version.json | jq -r '. | "release-\(.qbittorrent)_v\(.libtorrent_1_2)"') || error_exit "Failed to get latest version."
        local arch=$(uname -m)
        case "$arch" in
        x86_64)
            download_url="https://github.com/userdocs/qbittorrent-nox-static/releases/download/$version/x86_64-qbittorrent-nox"
            ;;
        aarch64)
            download_url="https://github.com/userdocs/qbittorrent-nox-static/releases/download/$version/aarch64-qbittorrent-nox"
            ;;
        *)
            error_exit "Unsupported architecture: $arch"
            ;;
        esac

        # Download qBittorrent
        wget -qO "$install_dir/qbittorrent-nox" "$download_url" || error_exit "Failed to download qBittorrent."
        chmod +x "$install_dir/qbittorrent-nox" || error_exit "Failed to set permissions for qBittorrent."
        chown qbittorrent:media -R "$install_dir"
        systemctl restart qbittorrent.service && systemctl status qbittorrent.service
    }
    # Function to install qBittorrent
    install_qbittorrent() {
        local choice
        local download_url
        local arch
        echo "1. Latest"
        echo "2. v4.6.7"
        echo "3. v5.1.2"
        while true; do
            read -rp "Which version you want to install? " choice
            case "$choice" in
            1)
                # Get latest version
                local version=$(curl -sL https://github.com/userdocs/qbittorrent-nox-static/releases/latest/download/dependency-version.json | jq -r '. | "release-\(.qbittorrent)_v\(.libtorrent_1_2)"') || error_exit "Failed to get latest version."
                break
                ;;
            2)
                local version="release-4.6.7_v1.2.19"
                break
                ;;
            3)
                local version="release-5.1.2_v1.2.20"
                break
                ;;
            *)
                echo "Invalid choice."
                ;;
            esac
        done

        # Download latest version that matches current system arch
        arch=$(uname -m)
        case "$arch" in
        x86_64)
            download_url="https://github.com/userdocs/qbittorrent-nox-static/releases/download/$version/x86_64-qbittorrent-nox"
            ;;
        aarch64)
            download_url="https://github.com/userdocs/qbittorrent-nox-static/releases/download/$version/aarch64-qbittorrent-nox"
            ;;
        *)
            error_exit "Unsupported architecture: $arch"
            ;;
        esac

        if ! getent group "media" >/dev/null 2>&1; then
            groupadd "media"
        fi
        if ! id "qbittorrent" &>/dev/null; then
            useradd -Nm -g media -s /bin/bash qbittorrent
        fi
        mkdir -p "$config_dir"

        # Download qBittorrent
        wget -qO "$install_dir/qbittorrent-nox" "$download_url" || error_exit "Failed to download qBittorrent."
        chmod +x "$install_dir/qbittorrent-nox" || error_exit "Failed to set permissions for qBittorrent."

        # Ask for port and validate
        read -rp "Enter port for qBittorrent WebUI: " port
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            error_exit "Port must be a valid number."
        fi

        # Ask for username and password
        read -rp "Enter username for qBittorrent WebUI: " username
        read -rsp "Enter password for qBittorrent WebUI: " password
        echo # Newline after password input

        # Hash the password
        password_hash=$(create_pass "$password")

        # Create Config File
        cat <<EOF >"$config_dir/qBittorrent.conf"
[LegalNotice]
Accepted=true

[BitTorrent]
Session\DHTEnabled=false
Session\MaxActiveDownloads=20
Session\MaxActiveTorrents=500
Session\MaxActiveUploads=500
Session\MaxUploads=400
Session\MaxUploadsPerTorrent=200
Session\BTProtocol=TCP
; Session\CoalesceReadWrite=true
; Session\ConnectionSpeed=150
; Session\IDNSupportEnabled=true
; Session\MultiConnectionsPerIp=true
; Session\PeerToS=128
; Session\PeerTurnover=10
; Session\PieceExtentAffinity=true
; Session\Preallocation=true
; Session\SendBufferLowWatermark=1048
; Session\SendBufferWatermark=5120
; Session\SendBufferWatermarkFactor=200
; Session\SocketBacklogSize=300
; Session\StopTrackerTimeout=5
; Session\SuggestMode=true

[Network]
PortForwardingEnabled=false
Proxy\HostnameLookupEnabled=false

[Preferences]
General\DeleteTorrentsFilesAsDefault=true
WebUI\Port=$port
WebUI\Username=$username
WebUI\Password_PBKDF2=$password_hash
EOF

        # Create Systemd service for current user
        # mkdir -p "$service_dir" || error_exit "Failed to create systemd user service directory."
        cat <<EOF >"$service_file"
[Unit]
Description=qBittorrent-nox service
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=exec
PrivateTmp=false
ExecStart="$install_dir/qbittorrent-nox" --profile="$install_dir"
Restart=on-failure
SyslogIdentifier=qbittorrent-nox
User=qbittorrent
Group=media

[Install]
WantedBy=default.target
EOF

        chown qbittorrent:media -R "$install_dir"

        # Reload systemctl daemon
        systemctl daemon-reload || error_exit "Failed to reload systemd daemon."

        # Enable and start service
        systemctl enable --now qbittorrent.service && systemctl status qbittorrent.service || error_exit "Failed to enable and start the service."

        # Check service status
        # systemctl --user status qbittorrent

        # Keep services running always
        # loginctl enable-linger
        # Check if linger is enabled:  loginctl show-user username | grep Linger

        echo "qBittorrent installed and configured successfully!"

        cat <<EOF
Nginx proxy configuration:
location / {
    proxy_pass               http://127.0.0.1:$port/;
    proxy_http_version       1.1;
    proxy_set_header   Host               \$proxy_host;
    proxy_set_header   X-Forwarded-For    \$proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Host   \$http_host;
    proxy_set_header   X-Forwarded-Proto  \$scheme;
    proxy_cookie_path / "/; Secure";
}
EOF
    }

    uninstall_qbittorrent() {
        read -rp "Are you sure you want to uninstall? (y/n)" confirm
        if [[ $confirm != "y" ]]; then
            echo "Aborting."
            return 0
        fi
        systemctl stop qbittorrent.service
        rm "$service_file"
        systemctl daemon-reload
        rm -rf "$install_dir"

    }

    config_set() {
        local key="$1"
        local val="$2"
        local file="$3"
        awk -v key="$key" -v val="$val" '{gsub("^#*[[:space:]]*" key "[[:space:]]*.*", key val); print}' "$file" | awk '{if (NF > 0) {if (!seen[$0]++) print} else {print}}' >"${file}.tmp" && mv "${file}.tmp" "$file"
    }

    # Function to reset username and password for the web UI
    reset_username_password() {
        # Ask for new username and password
        read -rp "Enter new username for qBittorrent WebUI: " new_username
        read -rsp "Enter new password for qBittorrent WebUI: " new_password
        echo # Newline after password input

        # Hash the password
        new_password_hash=$(create_pass "$new_password")
        echo
        echo "New Hash: $new_password_hash"
        echo

        # Update Config File with new username and password
        if [[ -f "$config_dir/qBittorrent.conf" ]]; then

            systemctl stop qbittorrent.service || error_exit "Failed to stop qbittorrent.service"

            config_set 'WebUI\\\\Username=' "$new_username" "$config_dir/qBittorrent.conf" || error_exit "Failed to find Username line"
            config_set 'WebUI\\\\Password_PBKDF2=' "$new_password_hash" "$config_dir/qBittorrent.conf" || error_exit "Failed to find Password line"
            echo "Username and password updated successfully!"

            echo "Value from config file:"
            cat "$config_dir/qBittorrent.conf" | grep "Password_PBKDF2"

            systemctl start qbittorrent.service || error_exit "Failed to start qbittorrent.service"

        else
            error_exit "qBittorrent configuration file not found. Please install qBittorrent first."
        fi
    }

    # Menu
    echo -e "\033[33m"
    echo "Welcome to qBittorrent Setup"
    echo "1. Install qBittorrent"
    echo "2. Upgrade qBittorrent"
    echo "3. Uninstall qBittorrent"
    echo "4. Reset username and password for the web UI"
    echo -e "\033[0m"
    read -rp "Enter your choice: " choice

    case "$choice" in
    1)
        install_qbittorrent
        ;;
    2)
        upgrade_qbittorrent
        ;;
    3)
        uninstall_qbittorrent
        ;;
    4)
        reset_username_password
        ;;
    *)
        error_exit "Invalid choice. Exiting."
        ;;
    esac
}

nodejs_manage() {
    while true; do
        echo "Choose an option:"
        echo "1. Install Node.js"
        echo "2. Remove (purge) Node.js"
        echo "3. Create Node.js Service"
        echo "0. Quit"

        read -rp "Enter your choice: " choice

        case $choice in
        1) nodejs_install ;;
        2) nodejs_remove ;;
        3) nodejs_create_service ;;
        0) return 0 ;;
        *) echo "Invalid choice." ;;
        esac
    done
}

nodejs_remove() {
    local confirm
    read -rp "This will purge Node.js.. Are you sure? (y/n): " confirm

    if [[ $confirm != "y" ]]; then
        echo "Aborting."
        return 0
    fi
    # Purge PHP packages
    apt purge -y nodejs && apt-get autoremove -y && echo "nodejs has been purged."
}

nodejs_install() {
    local confirm
    local VERSION
    if command -v node >/dev/null 2>&1 || [ -f "/etc/apt/sources.list.d/nodesource.list" ]; then
        read -rp "node/repo is already installed, are you sure you want to continue? (y/n)" confirm
        if [[ $confirm != "y" ]]; then
            echo "Aborting."
            return 0
        fi
    fi

    echo "Available Node.js versions:"
    echo "1. Node 18x"
    echo "2. Node 20x"
    echo "3. Node 22x"
    # Prompt user for version choice
    read -rp "Enter the number corresponding to the Node.js version you want to install: " choice
    case $choice in
    1) VERSION="18" ;;
    2) VERSION="20" ;;
    3) VERSION="22" ;;
    *)
        echo "Invalid choice!"
        nodejs_install
        ;;
    esac
    # Add NodeSource repository
    curl -fsSL https://deb.nodesource.com/setup_$VERSION.x | bash -s -- || {
        echo "Failed adding repo"
        return 1
    }
    # Install Node.js and npm
    apt-get install -y nodejs && echo "Node.js version $VERSION.x has been installed."
}

sys_more_pkg_install() {
    apt-get update && apt-get install -y build-essential software-properties-common python3-full python3 python3-pip python3-venv

    echo "More Packages installation complete."
}

mount_usb_install() {
    # Update package lists and install necessary packages
    apt-get update && apt-get install -y udiskie udisks2

    # Create the udiskie configuration directory
    mkdir -p /root/.config/udiskie

    # Create the udiskie configuration file
    cat <<EOL >/root/.config/udiskie/config.yml
device_config:
  - options:
    - umask=000
EOL

    cat <<EOL >/etc/polkit-1/localauthority/50-local.d/consolekit.pkla
[udiskie]
Identity=unix-group:root
Action=org.freedesktop.udisks.*
ResultAny=yes
EOL

    cat <<EOL >/etc/udev/rules.d/99-udisks2.rules
ENV{ID_FS_USAGE}=="filesystem|other|crypto", ENV{UDISKS_FILESYSTEM_SHARED}="1"
EOL

    # Create a systemd service file for udiskie
    cat <<EOL >/etc/systemd/system/udiskie.service
[Unit]
Description=Udiskie Automounter
After=local-fs.target
Before=multi-user.target

[Service]
ExecStart=/usr/bin/udiskie -F -N -T
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL

    udevadm control --reload-rules
    udevadm trigger

    systemctl daemon-reload
    systemctl enable udiskie
    systemctl restart udiskie
}

# Function to check for updates
update_check() {
    local github_repo="fa1rid/linux-setup"
    local script_name="Servo.sh"
    local script_folder="setup_menu"
    local SCRIPT_URL="https://raw.githubusercontent.com/$github_repo/main/${script_folder}/$script_name"
    local TMP_SCRIPT="/tmp/${script_name}"
    local BACKUP_SCRIPT="$0.bak"
    local new_version
    local answer

    if ! command -v wget &>/dev/null; then
        apt-get update && apt-get install -y wget
    fi

    echo "Checking for updates..."
    if ! wget --quiet -O "$TMP_SCRIPT" "$SCRIPT_URL"; then
        echo "Failed to download the latest version."
        rm -f "$TMP_SCRIPT"
        echo "Cleanup done."
        return 1
    fi

    new_version=$(grep -o 'servo_version="[0-9.]*"' "$TMP_SCRIPT" | cut -d '"' -f 2)

    if [ "$new_version" != "$servo_version" ]; then
        echo "New version available (v$new_version)."
        read -rp "Do you want to update? (Y/n): " answer
        answer=${answer:-Y}
        if [ "$answer" == "y" ] || [ "$answer" == "Y" ]; then
            echo "Updating to version $new_version..."
            mv "$0" "$BACKUP_SCRIPT"
            mv "$TMP_SCRIPT" "$0"
            chmod +x "$0"
            echo "Update complete. Please run the script again."
            exit 0
        else
            echo "Skipping update."
        fi
    else
        echo "No updates available."
    fi
}

version() {
    echo ${servo_version}
}

main() {
    if [[ $EUID -eq 0 ]]; then
        if [[ ! -d "$cron_dir_user" ]]; then
            mkdir -p "${cron_dir_user}"
        fi
    fi

    if [ $# -ge 1 ]; then
        local function_name="$1"
        shift # Remove the function name from the argument list
        "$function_name" "$@"
    else
        # Define an array where each element contains "function|option"
        local menu=(
            "exit                       | Exit"
            "update_check               | Update Script"
            "sys_manage                 | System"
            "net_manage                 | Network"
            "comp_manage                | Compression"
            "wordpress_manage           | Wordpress"
            "nginx_manage               | Nginx"
            "mariadb_manage             | Database"
            "php_manage                 | PHP"
            "certbot_manage             | Certbot"
            "rsync_manage               | Rsync"
            "memcached_manage           | Memcached"
            "docker_manage              | Docker"
            "nodejs_manage              | Node.js"
            "media_manage               | Media"
            "perm_set                   | Files/Folders Permissions"
            "rr_manage                    | Manage *rr apps"
        )
        # Alternative way of spliting menu
        # awk -F '|' '{print $2}' | sed 's/^[[:space:]]*//'
        # awk -F '|' '{print $1}' | sed 's/[[:space:]]*$//'

        # Display the menu
        while true; do
            clear # Clear the screen
            if [[ $EUID -ne 0 ]]; then
                echo -e "\033[91m===== Warning: running as non root =====\033[0m"
            fi
            echo -e "\033[93m===== Farid's Setup Menu v${servo_version} =====\033[92m"

            # Iterate through the menu array and display menu options with numbers
            local index
            for index in "${!menu[@]}"; do
                option_description=$(echo "${menu[index]}" | sed -E 's/ +\| */\t/g' | cut -f 2)
                echo "$((index)). $option_description"
            done

            echo -e "\033[93mAvailable functions:\033[94m"
            echo "  db_backup [database_name] [save_location]"
            echo "  db_restore [database_name] [db_filename]"
            echo "  decompress [filename]"
            echo "  compress [7z   bz2  gz   tar  xz   zip] [filename]"
            echo "  gen_pass [length] [min_numbers] [min_special_chars]"
            echo "  perm_set <target> <user> <group>"
            echo "  rsync_push_letsencrypt <path> <host> <port> <user>"
            echo "  rsync_push_ssl <path> <host> <port> <user>"
            echo "  sys_init"
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

##########################
# APT
##########################
# apt policy package # to show available versions and their repos
# apt list --installed
# dpkg -s package_name
# apt list package_name
# apt show package_name
# --no-install-recommends
# apt-config dump | grep Install-Recommends
# zgrep 'install iptables' /var/log/dpkg.log*

# dpkg-query -f '${binary:Package}\n' -W > packages_list.txt
# xargs -a packages_list.txt apt-get install

# dpkg --purge $(dpkg -l | awk '/^rc/ { print $2 }')
# dpkg -l | grep '^rc' | awk '{print $2}' | xargs dpkg --purge
# ii: The package is installed and has all its files.
# rc: The package was removed, but its configuration files are still present on the system.
# rc stands for "removed, configuration files"

# package_name="$1"
# # Use dpkg to query the package status
# if dpkg -l | grep -q "^ii\s*$package_name\s"; then
#     echo "$package_name is installed."
# else
#     echo "$package_name is not installed."
# fi

##########################
# Wordpress
##########################
# wp user update admin --user_pass=newpassword
# wp plugin list
# wp plugin deactivate --all
# wp plugin deactivate [plugin_name]
# wp theme activate twentynineteen
# "plugins" folder change the folder name to something like "plugins_disabled"
# To identify the problematic plugin, (e.g., plugin-name to _plugin-name)
# define('WP_MEMORY_LIMIT', '256M');
# define('WP_DEBUG', true);
# define('WP_DEBUG_LOG', true);
# define('WP_DEBUG_DISPLAY', false);
# @ini_set('display_errors',0);

##########################
# grep
##########################
# grep -- (`--` tells grep that there are no more options following it)
# -E,    PATTERNS are extended regular expressions
# -F,    PATTERNS are strings
# -w,    match only whole words
# -x,    match only whole lines
# -v,    select non-matching lines

##########################
# Users & sudo
##########################
# useradd -m -s /bin/bash rootuser
# passwd rootuser
# usermod -aG sudo rootuser
# visudo
# rootuser ALL=(ALL) NOPASSWD: ALL

# useradd -N -m -s "/usr/sbin/nologin" username
# usermod -s "/usr/bin/bash" username

# Lock a User Account: passwd -l username
# Unlock a User Account: passwd -u username
##########################
# Networking
##########################
# To find out which process is using port 8888, run:
# lsof -i :8888

# Monitor real-time network:
# apt install nethogs
# nethogs eth0

# iptables-save > /etc/iptables/rules.v4
# ip rule add from 10.5.4.0/24 table 100
# ip route add default via 10.0.0.1 proto static table 100
# ip .. del ..
# Identify the Custom Tables
# ip route show table all | grep 'table' | grep -vE 'table (local|main|default)'
### IP Forward ###
# iface=eth0
# PORT=
# CLIENT_IP=
# iptables -t nat -I PREROUTING -i ${iface} -p tcp --dport ${PORT} -j DNAT --to-destination ${CLIENT_IP}:${PORT}
# iptables -t nat -I PREROUTING -i ${iface} -p udp --dport ${PORT} -j DNAT --to-destination ${CLIENT_IP}:${PORT}
# iptables -I FORWARD -d ${CLIENT_IP} --dport ${PORT} -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# List tables, -n numeric output of addresses and ports
# iptables --line-numbers -nvL
# iptables --line-numbers -nvLt nat
# iptables --line-numbers -nvLt mangle

# Delete iptables Rules
# iptables -D OUTPUT 1 # Delete first rule from OUTPUT chain in filter table
# iptables -t nat -D POSTROUTING 4 # Delete 4th rule from POSTROUTING chain in nat table

# occtl -s /var/run/occtl5 show users
# occtl -s /var/run/occtl4 show users
# occtl -s /var/run/occtl3 show users
# occtl -s /var/run/occtl2 show users
# occtl -s /var/run/occtl show users

# Enable offloading
# ethtool -K eth0 tx-checksum-ip-generic on
# ethtool -K eth0 sg on
# ethtool -K eth0 gro on
# ethtool -K eth0 tso on
# ethtool -K eth0 gso on
# ethtool -G eth0 rx 4096 tx 4096

# traceroute -nm 2 1.1.1.1
##########################
# Change System local/keyboard
##########################
# localectl # check locale
# nano /etc/default/keyboard
# nano /etc/default/locale
# source /etc/default/locale
# setupcon
# ----------OR----------
# dpkg-reconfigure keyboard-configuration
# dpkg-reconfigure locale

##########################
# Rsync
##########################
## Commands to Migrate Solaris Server
# rsync --log-file="/var/log/rsync/letsencrypt.log" --stats -uavhzPL "/root/.ssh/id_ed25519.pub" "/root/.ssh/id_ed25519" -e "ssh -p 4444" "root@${ip}:/root/.ssh/"
# rsync --log-file="/var/log/rsync/letsencrypt.log" --stats -uavhzPL "/etc/cloudflare/" -e "ssh -p 4444" "root@${ip}:/etc/cloudflare/"
# rsync --log-file="/var/log/rsync/letsencrypt.log" --stats -uavhzPL "/root/.config/rsnapshot/" -e "ssh -p 4444" "root@${ip}:/root/.config/rsnapshot/"
# rsync --log-file="/var/log/rsync/letsencrypt.log" --stats -uavhzPL "/etc/letsencrypt/" -e "ssh -p 4444" "root@${ip}:/etc/letsencrypt/"
# rsync --log-file="/var/log/rsync/letsencrypt.log" --stats -uavhzPL "/var/www/solaris/solarissolutions.co/" -e "ssh -p 4444" "root@${ip):/var/www/solaris/solarissolutions.co/"
# rsync -ahPL -e "ssh -p 4444" "root@10.0.0.3:/root/Downloads/" "."
# rsync -ahPL "/usr/local/softether/vpn_server.config" -e "ssh -p 4444" "root@10.0.0.4:/usr/local/softether/vpn_server.config"
# -u         skip files that are newer on the receiver
# -a         archive mode is -rlptgoD (no -A,-X,-U,-N,-H)
# -r           recurse into directories
# -l           copy symlinks as symlinks
# -t           preserve modification times
# -g           preserve group
# -o           preserve owner (super-user only)
# -D           same as --devices --specials
# -v         increase verbosity
# -h         output numbers in a human-readable format
# -z         compress file data during the transfer
# -p         preserve permissions
# -P         same as --partial --progress (show progress during transfer)
# -L         transform symlink into referent file/dir
#-----------------------------------
# Rsync daemon "/etc/rsyncd.conf"
# Example Usage: 
# rsync rsync://server.net/
# rsync -ahPL "rsync://server.net/downloads/video.mkv" ./folder/
# (uses port 873)
##########################
# NGINX
##########################
# Install RTMP (first add sury's repo and add priorty)
# apt-get install libnginx-mod-rtmp
# gunzip -c /usr/share/doc/libnginx-mod-rtmp/examples/stat.xsl.gz > /var/www/stat.xsl

# *** Combining Basic Authentication with Access Restriction by IP Address ***

# apt-get install apache2-utils
# htpasswd -c /etc/nginx/.htpasswd user1
#     auth_basic           "Enter Password";
#     auth_basic_user_file "/etc/nginx/.htpasswd";
# satisfy all; # If you set the directive to to all, access is granted if a client satisfies both conditions
# satisfy any;  # If you set the directive to any, access is granted if if a client satisfies at least one condition
# deny  192.168.1.2;
# allow 192.168.1.1/24;
# allow 127.0.0.1;
# deny  all;

##########################
# Install VMware tools package: open-vm-tools
##########################

##########################
# base64/hex
##########################
# echo -n 123 | xxd -p | tr -d '\n'
# echo -n 123 | od -An -t x1 | tr -d ' \n'
# echo -n 123 | hexdump --no-squeezing --format '/1 "%02x"'

## hex to string
# echo -n 313233 | sed 's/\([0-9A-F]\{2\}\)/\\\\\\x\1/gI' | xargs printf
# echo -n 313233 | xxd -r -p
# echo -n 313233 | perl -pe 's/(..)/chr(hex($1))/ge'

## string to base64
# echo -n 123 | base64
# echo -n 123 | openssl enc -base64 -A
# echo -n 123 | openssl base64 -A

## base64 to string
# echo -n MTIz | base64 -d
# echo -n MTIz | openssl base64 -d -A
# echo -n MTIz | openssl enc -base64 -d -A

##########################
# Disks & USB Devices
##########################
# blkid
# lsblk
# lsblk -o name,label,size,type,FSROOTS,FSTYPE,FSSIZE,FSAVAIL,FSUSED,FSUSE%,MOUNTPOINT

# apt-get install -y acl
# mkdir -p /mnt/media
# chown root:media /mnt/media
# chmod 2775 /mnt/media
# setfacl -d -m g::rwx /mnt/media
# mkfs.ext4 -m 0 -i 325040 -T big -L 'media' /dev/sdb && mount -o discard,defaults /dev/sdb /mnt/media
# echo "LABEL=media /mnt/media ext4 discard,nofail,defaults 0 0" | tee -a /etc/fstab
# umount /mnt/media

# Mount after adding fstab without reboot
# systemctl daemon-reload
# mount -a 

# tune2fs -m 0 /dev/sdb # change reserved space (not needed if -m is used in mkfs.ext4)
# findmnt /mnt/media

# Explaination:
# By default, ext4 allocates 1 inode per 16 KiB of space (or 1 inode per 16384 bytes).
# The default inode ratio is -i 16384, meaning one inode is created for every 16 KB of storage.
# The default inode size (individual inode metadata) is usually 256 bytes, but this can be 128 bytes on older systems.

# -i 325040 means one inode per 325040 bytes (~317 KB).
# Higher values = fewer inodes = more available storage but worse handling of many small files.

# By default, ext4 reserves 5% of the total disk space for privileged (root) use. This helps prevent system failures when the disk is nearly full, ensuring root/system processes can continue operating.

#  How to Check Current Reserved Space?
# tune2fs -l /dev/sda1 | grep 'Reserved block count'

# To check how much space is reserved in megabytes (MB):
# tune2fs -l /dev/sda1 | awk '/Block size|Reserved block count/ {print $NF}' | paste - - | awk '{printf "%.2f MB\n", ($1 * $2) / 1024 / 1024}'

# To reduce reserved space to 1% (safer option for system stability):
# tune2fs -m 1 /dev/sda1

# Optimize Storage for seeding:
# UUID=xxxxxxxx / ext4 defaults,noatime,commit=60,errors=remount-ro 0 1
# ___________________________
# setfacl: The command to set a File Access Control List.
# -d: This is the most important flag here. It means default. This command doesn't change the permissions on the directory itself, but sets a default ACL for any new files or directories created inside it.
# -m: This means modify the ACL.
# g::rwx: This is the permission being set.
# g stands for group.
# The empty space between the colons (::) means the owning group of the file.
# rwx means read, write, and execute.
# In plain English, the command means: "For this directory, set a default rule that any new item created inside it will automatically grant read, write, and execute permissions to the item's primary group."
# In your case, you are already achieving this with the file_mode=0660 and dir_mode=0770 options in your fstab, so you don't need to run this command.
##########################
# RPI WiFi
##########################
## Disable the specific connection:
# nmcli connection down preconfigured

## Re-enable the specific connection:
# nmcli connection up preconfigured

## Turn off WiFi entirely:
# nmcli radio wifi off

## Turn on WiFi entirely:
# nmcli radio wifi on

##########################
# MariaDB
##########################
# DROP USER 'username'@'localhost';
# DROP DATABASE database_name;

##########################
# Shares
##########################
## SMB
# //192.168.20.15/M /mnt/M cifs credentials=/etc/smb_credentials,iocharset=utf8,nofail,noauto,x-systemd.automount,x-systemd.mount-timeout=30,_netdev,gid=media,file_mode=0660,dir_mode=0770,noperm 0 0

# cat >"/etc/smb_credentials" <<EOF
# username=user
# password=pass
# EOF

##########################
# journald
##########################
# journalctl --disk-usage

# one-time operation, delete older logs
# journalctl --vacuum-time=2weeks
# journalctl --vacuum-size=100M

# Configure persistent and volatile limits
# echo "SystemMaxUse=500M" | tee -a /etc/systemd/journald.conf
# echo "RuntimeMaxUse=200M" | tee -a /etc/systemd/journald.conf
# systemctl restart systemd-journald
##########################
# makemkv
##########################
# wget https://apt.benthetechguy.net/benthetechguy-archive-keyring.gpg -O /usr/share/keyrings/benthetechguy-archive-keyring.gpg
# echo "deb [signed-by=/usr/share/keyrings/benthetechguy-archive-keyring.gpg] https://apt.benthetechguy.net/debian bookworm non-free" > /etc/apt/sources.list.d/benthetechguy.list
# apt update
# apt install makemkv
##########################
# RAM
##########################
# Check how many memory slots are installed and how much RAM is in each slot on a Debian
# apt install dmidecode
# dmidecode --type memory
# dmidecode --type memory | grep -E 'Memory Device|Size'
##########################
# curl
##########################
# Bind to an Interface
# curl --interface enp7s0 ipinfo.io/ip
# Bind to a Source IP
# curl --interface 192.168.1.100 http://example.com

# test and view your HTTP headers
# curl  https://httpbin.org/headers
##########################
# wget
##########################
# HTTP/HTTPS Proxy with wget
# wget -e use_proxy=yes -e http_proxy=http://<proxy-ip>:<proxy-port> http://example.com
# wget -e use_proxy=yes -e http_proxy=http://<username>:<password>@<proxy-ip>:<proxy-port> http://example.com
# wget -e use_proxy=yes -e https_proxy=http://<username>:<password>@<proxy-ip>:<proxy-port> https://example.com

# If you want to use the proxy for all wget commands in the current session:
# export http_proxy=http://<username>:<password>@<proxy-ip>:<proxy-port>
# export https_proxy=http://<username>:<password>@<proxy-ip>:<proxy-port>
# To make the proxy settings permanent, add these export lines to your ~/.bashrc or ~/.bash_profile file.
##########################
# Cron / crontab 
##########################
# For a specific user, the cron entries from crontab -l are stored in a file called
# /var/spool/cron/crontabs/<username>
##########################
# Query Time server
##########################
# apt install ntpsec-ntpdate
# ntpdate -q time.android.com
##########################
#
##########################
