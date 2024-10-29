<?php

namespace antihacker_BillDiagnose;
// 2023-08 upd: 2023-10-17 2024-06=21
if (!defined('ABSPATH')) {
    die('Invalid request.');
}
if (function_exists('is_multisite') and is_multisite()) {
    return;
}

/*
// >>>>>>>>>>>>>>>> call
function recaptcha_for_all_bill_hooking_diagnose()
{
    if (function_exists('is_admin') && function_exists('current_user_can')) {
        if(is_admin() and current_user_can("manage_options")){
            $notification_url = "https://wpmemory.com/fix-low-memory-limit/";
            $notification_url2 =
                "https://wptoolsplugin.com/site-language-error-can-crash-your-site/";
            require_once dirname(__FILE__) . "/includes/diagnose/class_bill_diagnose.php";
        }
    }
}
add_action("plugins_loaded", "recaptcha_for_all_bill_hooking_diagnose");
// end >>>>>>>>>>>>>>>>>>>>>>>>>
*/


$plugin_file_path = ABSPATH . 'wp-admin/includes/plugin.php';
if (file_exists($plugin_file_path)) {
    include_once($plugin_file_path);
}



if (function_exists('is_plugin_active')) {
    $bill_plugins_to_check = array(
        'wptools/wptools.php',
    );


    foreach ($bill_plugins_to_check as $plugin_path) {
        if (is_plugin_active($plugin_path)) {
            return;
        }
    }
}

$logErrors = ini_get('log_errors');
$errorLog = ini_get('error_log');
if ($logErrors) {
    if (!$errorLog) {
        ini_set('error_log', ABSPATH . 'error_log');
    }
} else {
    ini_set('log_errors', 'On');
}

class ErrorChecker
{

    public function bill_check_errors_today($num_days, $filter = null)
    {
        $bill_count = 0;
        $bill_folders = [];

        //$bill_themePath = get_theme_root();

        $error_log_path = trim(ini_get("error_log"));
        if (!is_null($error_log_path) and $error_log_path != trim(ABSPATH . "error_log")) {
            $bill_folders[] = $error_log_path;
        }


        $bill_folders[] = ABSPATH . "error_log";
        $bill_folders[] = ABSPATH . "php_errorlog";
        $bill_folders[] = plugin_dir_path(__FILE__) . "/error_log";
        $bill_folders[] = plugin_dir_path(__FILE__) . "/php_errorlog";
        $bill_folders[] = get_theme_root() . "/error_log";
        $bill_folders[] = get_theme_root() . "/php_errorlog";
        // Adicionar caminhos específicos de administração se existirem
        $bill_admin_path = str_replace(
            get_bloginfo("url") . "/",
            ABSPATH,
            get_admin_url()
        );
        $bill_folders[] = $bill_admin_path . "/error_log";
        $bill_folders[] = $bill_admin_path . "/php_errorlog";
        $bill_folders[] = WP_CONTENT_DIR . "/debug.log";

        // Adicionar diretórios de plugins
        $bill_plugins = array_slice(scandir(plugin_dir_path(__FILE__)), 2);
        foreach ($bill_plugins as $bill_plugin) {
            if (is_dir(plugin_dir_path(__FILE__) . "/" . $bill_plugin)) {
                $bill_folders[] = plugin_dir_path(__FILE__) . "/" . $bill_plugin . "/error_log";
                $bill_folders[] = plugin_dir_path(__FILE__) . "/" . $bill_plugin . "/php_errorlog";
            }
        }
        $bill_themes = array_slice(scandir(get_theme_root()), 2);
        foreach ($bill_themes as $bill_theme) {
            if (is_dir(get_theme_root() . "/" . $bill_theme)) {
                $bill_folders[] = get_theme_root() . "/" . $bill_theme . "/error_log";
                $bill_folders[] = get_theme_root() . "/" . $bill_theme . "/php_errorlog";
            }
        }



        foreach ($bill_folders as $bill_folder) {
            // if (!empty($bill_folder) && file_exists($bill_folder)) {
            if (!empty($bill_folder) && file_exists($bill_folder) && filesize($bill_folder) > 0) {



                //var_dump($bill_folder);



                $bill_count++;
                //$marray = $bill_read_file($bill_folder, 20);
                $marray = $this->bill_read_file($bill_folder, 20);

                //var_dump($marray);
                //die();


                if (is_array($marray) && !empty($marray)) {
                    // Iterar sobre as linhas do log
                    foreach ($marray as $line) {
                        // javascript...
                        if ($filter !== null && stripos($line, $filter) === false) {
                            continue;
                        }


                        //echo $line;
                        //echo '<br>';


                        $date_formats = [
                            'Y-m-d',
                            'Y/m/d',
                            'Y-d-m',
                            'Y/d/m',
                            'd-M-Y',
                            'd/M/Y',
                            'M d Y',
                            'd/m/Y',  // Formato para '16/06/2024'
                            'd-m-Y',  // Formato para '16-06-2024'
                        ];

                        $valid_date = false;


                        $first_space_pos = strpos($line, ' ');
                        $date_string = substr($line, 0, $first_space_pos);

                        if ($first_space_pos === false) {
                            continue;
                        }
                        $date_string = substr($date_string, 1);


                        // $date_string = preg_replace('/[^0-9\/\-]/', '', $date_string);
                        //$date_string = preg_replace('/[^0-9\/-]/', '', $date_string);
                        //$date_string = preg_replace('/[^\d\/]+/', '', $date_string);
                        // $date_string = preg_replace('/[^0-9\-]/', '', $date_string);
                        //$date_string = preg_replace('/[^0-9\/\-]/', '', $date_string);
                        //$date_string = preg_replace('/[^0-9\/\-a-zA-Z]/', '', $date_string);
                        //$date_string = preg_replace('/[^0-9a-zA-Z\-]/', '', $date_string);
                        // $date_string = preg_replace('/[^0-9a-zA-Z\-\/]/', '', $date_string);
                        $date_string = preg_replace('/[^0-9a-zA-Z\/\-\s]/', '', $date_string);


                        $valid_date = false;
                        foreach ($date_formats as $format) {
                            $date = \DateTime::createFromFormat($format, $date_string);
                            if ($date !== false && $date->format($format) === $date_string) {
                                $valid_date = true;
                                break;
                            }
                        }
                        if (!$valid_date) {
                            continue;
                        }
                        $log_date = $date->getTimestamp();
                        $days_diff = floor((time() - $log_date) / (60 * 60 * 24));
                        if ($days_diff <= $num_days) {
                            return true; // Se encontrar uma correspondência, retorna true
                        }
                    }
                }
            }
        }
        return false;
    }

    /*
     public function bill_read_file($file, $lines)
    {
        try {
            $handle = fopen($file, "r");
        } catch (Exception $e) {
            return "";
        }
        if (!$handle) {
            return "";
        }
        $linecounter = $lines;
        $pos = -2;
        $beginning = false;
        $text = [];
        while ($linecounter > 0) {
            $t = " ";
            // acha ultima quebra de linha indo para traz... 
            // partindo da ultima posicao menos 1.
            while ($t != "\n") {
                if (fseek($handle, $pos, SEEK_END) == -1) {
                    // chegou no inicio?
                    $beginning = true;
                    break;
                }
                $t = fgetc($handle);
                $pos--;
            }
            $linecounter--;
            // chegou no inicio?
            if ($beginning) {
                rewind($handle);
            }
            $line = fgets($handle);
            if ($line === false) {
                break; // Não há mais linhas para ler
            }
            $text[] = $line;
            if ($beginning) {
                break;
            }
        }
        fclose($handle);
        return $text;
    }
    */

    public function bill_read_file_old($file, $lines)
    {
        $handle = fopen($file, "r");

        //die(var_dump($handle));

        if (!$handle) {
            return "";
        }

        $bufferSize = 8192; // Tamanho do bloco de leitura (8KB)
        $text = [];
        $currentChunk = '';
        $linecounter = 0;

        // Move para o final do arquivo e começa a leitura para trás
        fseek($handle, 0, SEEK_END);
        $filesize = ftell($handle);
        $pos = $filesize - $bufferSize;

        die(var_dump($pos));

        while ($pos >= 0 && $linecounter < $lines) {
            // Se pos é menor que zero, ajusta para 0
            if ($pos < 0) {
                $pos = 0;
            }

            // Mover o ponteiro para a posição
            fseek($handle, $pos);



            // Ler o bloco
            $chunk = fread($handle, $bufferSize);
            $currentChunk = $chunk . $currentChunk;

            //die(var_dump($chunk));


            // Dividir o bloco em linhas
            $linesInChunk = explode("\n", $currentChunk);

            // O primeiro elemento pode ser uma linha parcial (incompleta)
            $currentChunk = array_shift($linesInChunk);

            // Adiciona as linhas ao texto
            foreach (array_reverse($linesInChunk) as $line) {
                $text[] = $line;
                $linecounter++;
                if ($linecounter >= $lines) {
                    break 2; // Sai dos dois loops
                }
            }

            // Move a posição para o próximo bloco
            $pos -= $bufferSize;
        }

        // Adiciona a última linha parcial (se houver)
        if (!empty($currentChunk)) {
            $text[] = $currentChunk;
        }

        fclose($handle);

        // Reverte o array para retornar as linhas na ordem correta
        // return array_reverse($text);
        return $text;
    }




    public function bill_read_file($file, $lines)
    {
        $handle = fopen($file, "r");

        if (!$handle) {
            return "";
        }

        $bufferSize = 8192; // Tamanho do bloco de leitura (8KB)
        $text = [];
        $currentChunk = '';
        $linecounter = 0;

        // Move para o final do arquivo e começa a leitura para trás
        fseek($handle, 0, SEEK_END);
        $filesize = ftell($handle); // Tamanho do arquivo

        // Ajustar bufferSize para o tamanho do arquivo se for menor que 8KB
        if ($filesize < $bufferSize) {
            $bufferSize = $filesize;
        }

        $pos = $filesize - $bufferSize;

        while ($pos >= 0 && $linecounter < $lines) {
            if ($pos < 0) {
                $pos = 0;
            }

            fseek($handle, $pos);

            $chunk = fread($handle, $bufferSize);
            $currentChunk = $chunk . $currentChunk;

            $linesInChunk = explode("\n", $currentChunk);
            $currentChunk = array_shift($linesInChunk);

            foreach (array_reverse($linesInChunk) as $line) {
                $text[] = $line;
                $linecounter++;
                if ($linecounter >= $lines) {
                    break 2;
                }
            }

            $pos -= $bufferSize;
        }

        if (!empty($currentChunk)) {
            $text[] = $currentChunk;
        }

        fclose($handle);

        return $text;
    }
} // end class error checker












class MemoryChecker
{

    public function check_memory()
    {
        try {
            // Check if ini_get function exists
            if (!function_exists('ini_get')) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            } else {
                // Get the PHP memory limit
                $wpmemory["limit"] = (int) ini_get("memory_limit");
            }

            // Check if the memory limit is numeric
            if (!is_numeric($wpmemory["limit"])) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            }

            // Convert the memory limit from bytes to megabytes if it is excessively high
            if ($wpmemory["limit"] > 9999999) {
                $wpmemory["limit"] = $wpmemory["limit"] / 1024 / 1024;
            }

            // Check if memory_get_usage function exists
            if (!function_exists('memory_get_usage')) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            } else {
                // Get the current memory usage
                $wpmemory["usage"] = memory_get_usage();
            }

            // Check if the memory usage is valid
            if ($wpmemory["usage"] < 1) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            } else {
                // Convert the memory usage to megabytes
                $wpmemory["usage"] = round($wpmemory["usage"] / 1024 / 1024, 0);
            }

            // Check if the usage value is numeric
            if (!is_numeric($wpmemory["usage"])) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            }

            // Check if WP_MEMORY_LIMIT is defined
            if (!defined("WP_MEMORY_LIMIT")) {
                $wpmemory["wp_limit"] = 40; // Default value of 40M
            } else {
                $wp_memory_limit = WP_MEMORY_LIMIT;
                $wpmemory["wp_limit"] = (int) $wp_memory_limit;
            }

            // Calculate the percentage of memory usage
            $wpmemory["percent"] = $wpmemory["usage"] / $wpmemory["wp_limit"];
            $wpmemory["color"] = "font-weight:normal;";
            if ($wpmemory["percent"] > 0.7) {
                $wpmemory["color"] = "font-weight:bold;color:#E66F00";
            }
            if ($wpmemory["percent"] > 0.85) {
                $wpmemory["color"] = "font-weight:bold;color:red";
            }

            // Calculate the available free memory
            $wpmemory["free"] = $wpmemory["wp_limit"] - $wpmemory["usage"];
            $wpmemory["msg_type"] = "ok";
        } catch (Exception $e) {
            $wpmemory["msg_type"] = "notok";
            return $wpmemory;
        }
        return $wpmemory;
    }
}


class recaptcha_for_all_Bill_Diagnose
{
    private static $instance = null;

    private $notification_url;
    private $notification_url2;
    private $global_variable_has_errors;
    private $global_variable_memory;

    public function __construct(
        $notification_url,
        $notification_url2
    ) {
        $this->setNotificationUrl($notification_url);
        $this->setNotificationUrl2($notification_url2);


        //$this->global_variable_has_errors = $this->bill_check_errors_today();
        $errorChecker = new ErrorChecker(); //
        //
        $this->global_variable_has_errors  = $errorChecker->bill_check_errors_today(1);


        // die(var_dump($this->global_variable_has_errors));

        //





        // $this->global_variable_has_errors = true;
        // >>>>>>>>>>>>>>>>>>>




        // same class
        //  $this->global_variable_memory = $this->check_memory();

        // NOT same class
        $memoryChecker = new MemoryChecker();
        $this->global_variable_memory = $memoryChecker->check_memory();


        $this->global_plugin_slug = $this->get_plugin_slug();


        // Adicionando as ações dentro do construtor
        add_action("admin_notices", [$this, "show_dismissible_notification"]);
        //add_action("admin_notices", [$this, "show_dismissible_notification2"]);
        // 2024
        if ($this->global_variable_has_errors)
            add_action("admin_bar_menu", [$this, "add_site_health_link_to_admin_toolbar"], 999);
        add_action("admin_head", [$this, "custom_help_tab"]);

        $memory = $this->global_variable_memory;
        if (
            $memory["free"] < 30 or
            $memory["percent"] > 85 or
            $this->global_variable_has_errors
        ) {
            add_filter("site_health_navigation_tabs", [
                $this,
                "site_health_navigation_tabs",
            ]);
            add_action("site_health_tab_content", [
                $this,
                "site_health_tab_content",
            ]);
        }
    }

    /*
    public function get_plugin_slug() {
        // Get the plugin directory path
        $plugin_dir = plugin_dir_path( __FILE__ );
        debug2($plugin_dir);
        debug2(WP_PLUGIN_DIR);
    
        // Check if the plugin is in the normal plugins directory
        if (strpos($plugin_dir, WP_PLUGIN_DIR) === 0) {
            // Remove the WP_PLUGIN_DIR path from the full URL
            $plugin_slug = str_replace(WP_PLUGIN_DIR . '/', '', $plugin_dir);
        }
        // Check if the plugin is in the mu-plugins directory
        elseif (strpos($plugin_dir, WPMU_PLUGIN_DIR) === 0) {
            // Remove the WPMU_PLUGIN_DIR path from the full URL
            $plugin_slug = str_replace(WPMU_PLUGIN_DIR . '/', '', $plugin_dir);
        } else {
            // If the plugin is not in any expected directory, return an empty string
            return '';
        }
        
        // Trim any trailing slashes that might exist
        $plugin_slug = trim($plugin_slug, '/');

        debug2($plugin_slug);        
        return $plugin_slug;
    }
    */

    public function get_plugin_slug()
    {
        // Get the plugin directory path
        $plugin_dir = plugin_dir_path(__FILE__);

        // Function to get the base directory of the plugin
        function get_base_plugin_dir($dir, $base_dir)
        {
            // Remove the base directory part from the full path
            $relative_path = str_replace($base_dir, '', $dir);
            // Get the first directory in the relative path
            $parts = explode('/', trim($relative_path, '/'));
            return $parts[0];
        }

        // Check if the plugin is in the normal plugins directory
        if (strpos($plugin_dir, WP_PLUGIN_DIR) === 0) {
            $plugin_slug = get_base_plugin_dir($plugin_dir, WP_PLUGIN_DIR);
        }
        // Check if the plugin is in the mu-plugins directory
        elseif (defined('WPMU_PLUGIN_DIR') && strpos($plugin_dir, WPMU_PLUGIN_DIR) === 0) {
            $plugin_slug = get_base_plugin_dir($plugin_dir, WPMU_PLUGIN_DIR);
        } else {
            // If the plugin is not in any expected directory, return an empty string
            return '';
        }

        return $plugin_slug;
    }


    public function setNotificationUrl($notification_url)
    {
        $this->notification_url = $notification_url;
    }

    public function setNotificationUrl2($notification_url2)
    {
        $this->notification_url2 = $notification_url2;
    }

    public function setPluginTextDomain($plugin_text_domain)
    {
        $this->plugin_text_domain = $plugin_text_domain;
    }

    public function setPluginSlug($plugin_slug)
    {
        $this->plugin_slug =  $this->get_plugin_slug();
    }

    public static function get_instance(
        $notification_url,
        $notification_url2
    ) {
        if (self::$instance === null) {
            self::$instance = new self(
                $notification_url,
                $notification_url2,
            );
        }
        return self::$instance;
    }
    //
    /*
    public function check_memory22222()
    {
        try {
            // PHP $memory["limit"]
            if(!function_exists('ini_get')){
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            }
            else{
                $wpmemory["limit"] = (int) ini_get("memory_limit");
            }
            if (!is_numeric($wpmemory["limit"])) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            }
            if ($wpmemory["limit"] > 9999999) {
                // $wpmemory['msg_type'] = 'notok(5)';
                $wpmemory["wp_limit"] =
                    $wpmemory["wp_limit"] / 1024 / 1024;
            }
            // usage
            if(!function_exists('memory_get_usage')){
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            }
            else{
                $wpmemory["usage"] = memory_get_usage();
            }
            if ($wpmemory["usage"] < 1) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            }
            else{
                $wpmemory["usage"] = round($wpmemory["usage"] / 1024 / 1024, 0);
            }
            if (!is_numeric($wpmemory["usage"])) {
                $wpmemory["msg_type"] = "notok";
                return $wpmemory;
            }
            // WP
            if (!defined("WP_MEMORY_LIMIT")) {
                $wpmemory["wp_limit"] = 40;
            //define('WP_MEMORY_LIMIT', '40M');
            } else {
                $wp_memory_limit = WP_MEMORY_LIMIT;
                // $wp_memory_limit = rtrim($wp_memory_limit, 'M');
                $wpmemory["wp_limit"] = (int) $wp_memory_limit;
            }
            $wpmemory["percent"] = $wpmemory["usage"] / $wpmemory["wp_limit"];
            $wpmemory["color"] = "font-weight:normal;";
            if ($wpmemory["percent"] > 0.7) {
                $wpmemory["color"] = "font-weight:bold;color:#E66F00";
            }
            if ($wpmemory["percent"] > 0.85) {
                $wpmemory["color"] = "font-weight:bold;color:red";
            }
            $wpmemory["free"] = $wpmemory["wp_limit"] - $wpmemory["usage"];
            $wpmemory["msg_type"] = "ok";
        } catch (Exception $e) {
            $wpmemory["msg_type"] = "notok";
            return $wpmemory;
        }
        return $wpmemory;
    }
    */



    public function show_dismissible_notification()
    {
        if ($this->is_notification_displayed_today()) {
            return;
        }
        $memory = $this->global_variable_memory;
        if ($memory["free"] > 30 and $wpmemory["percent"] < 85) {
            return;
        }
        $message = esc_attr__("Our plugin", 'restore-classic-widgets');
        $message .= ' (' . $this->plugin_slug . ') ';
        $message .= esc_attr__("cannot function properly because your WordPress Memory Limit is too low. Your site will experience serious issues, even if you deactivate our plugin.", 'restore-classic-widgets');
        $message .=
            '<a href="' .
            esc_url($this->notification_url) .
            '">' .
            " " .
            esc_attr__("Learn more", 'restore-classic-widgets') .
            "</a>";
        echo '<div class="notice notice-error is-dismissible">';
        echo '<p style="color: red;">' . wp_kses_post($message) . "</p>";
        echo "</div>";
    }
    /*
    public function show_dismissible_notification2()
    {
        if ($this->is_notification_displayed_today()) {
            return;
        }
        if ($this->global_variable_has_errors) {
                $message = esc_attr__("Your site has errors.", 'restore-classic-widgets');
                $message .= esc_attr__("Our plugin", 'restore-classic-widgets');
                $message .= ' ('.$this->plugin_slug.') ' ;
                $message .= esc_attr__("can't function as intended. Errors, including JavaScript errors, may lead to visual problems or disrupt functionality, from minor glitches to critical site failures. Promptly address these issues before continuing.", 'restore-classic-widgets');
                $message .=
                '<a href="' .
                esc_url($this->notification_url2) .
                '">' .
                " " .
                esc_attr__("Learn more", 'restore-classic-widgets') .
                "</a>";
            echo '<div class="notice notice-error is-dismissible">';
            //$content_with_formatting = wpautop($content);
            echo '<p style="color: red;">' . wp_kses_post($message) . "</p>";
            echo "</div>";
        }
    }
    */
    // Helper function to check if a notification has been displayed today
    public function is_notification_displayed_today()
    {
        $last_notification_date = get_option("recaptcha_for_all_bill_show_warnings");
        $today = date("Y-m-d");
        return $last_notification_date === $today;
    }
    // Add Tab
    public function site_health_navigation_tabs($tabs)
    {
        // translators: Tab heading for Site Health navigation.
        $tabs["Critical Issues"] = esc_html_x(
            "Critical Issues",
            "Site Health",
            'restore-classic-widgets'
        );
        return $tabs;
    }


    // Add Content
    public function site_health_tab_content($tab)
    {
        if (!function_exists('recaptcha_for_all_bill_strip_strong99')) {
            function recaptcha_for_all_bill_strip_strong99($htmlString)
            {
                // return $htmlString;
                // Use preg_replace para remover as tags <strong>
                $textWithoutStrongTags = preg_replace(
                    "/<strong>(.*?)<\/strong>/i",
                    '$1',
                    $htmlString
                );

                return $textWithoutStrongTags;
            }
        }
        // Do nothing if this is not our tab.
        if ("Critical Issues" !== $tab) {
            return;
        } ?>


        <div class="wrap health-check-body, privacy-settings-body">






            <p style="border: 1px solid #000; padding: 10px;">
                <strong>
                    <?php
                    echo esc_attr__("Displaying the latest recurring errors from your error log file and eventually alert about low WordPress memory limit is a courtesy of plugin", 'restore-classic-widgets');
                    echo ': ' . esc_attr($this->global_plugin_slug) . '. ';
                    echo esc_attr__("Disabling our plugin does not stop the errors from occurring; 
                it simply means you will no longer be notified here that they are happening, but they can still harm your site.", 'restore-classic-widgets');
                    ?>
                </strong>
            </p>

            <h3 style="color: red;">
                <?php
                echo esc_attr__("Potential Problems", 'restore-classic-widgets');
                ?>
            </h3>
            <?php
            $memory = $this->global_variable_memory;
            $wpmemory = $memory;
            if ($memory["free"] < 30 or $wpmemory["percent"] > 85) { ?>
                <h2 style="color: red;">
                    <?php $message = esc_attr__("Low WordPress Memory Limit", 'restore-classic-widgets'); ?>
                </h2>
                <?php
                $mb = "MB";
                echo "<b>";
                echo "WordPress Memory Limit: " .
                    esc_attr($wpmemory["wp_limit"]) .
                    esc_attr($mb) .
                    "&nbsp;&nbsp;&nbsp;  |&nbsp;&nbsp;&nbsp;";
                $perc = $wpmemory["usage"] / $wpmemory["wp_limit"];
                if ($perc > 0.7) {
                    echo '<span style="color:' . esc_attr($wpmemory["color"]) . ';">';
                }
                echo esc_attr__("Your usage now", 'restore-classic-widgets') .
                    ": " .
                    esc_attr($wpmemory["usage"]) .
                    "MB &nbsp;&nbsp;&nbsp;";
                if ($perc > 0.7) {
                    echo "</span>";
                }
                echo "|&nbsp;&nbsp;&nbsp;" .
                    esc_attr__("Total Php Server Memory", 'restore-classic-widgets') .
                    " : " .
                    esc_attr($wpmemory["limit"]) .
                    "MB";
                echo "</b>";
                echo "</center>";
                echo "<hr>";
                $free = $wpmemory["wp_limit"] - $wpmemory["usage"];
                echo '<p>';
                echo esc_attr__("Your WordPress Memory Limit is too low, which can lead to critical issues on your site due to insufficient resources. Promptly address this issue before continuing.", 'restore-classic-widgets');
                echo '</b>';
                ?>
                </b>
                <a href="https://wpmemory.com/fix-low-memory-limit/">
                    <?php
                    echo esc_attr__("Learn More", 'restore-classic-widgets');
                    ?>
                </a>
                </p>
                <br>
            <?php
            }

            // end block memory...

            ?>








            <?php


            // Errors ...



            if ($this->global_variable_has_errors) { ?>
                <h2 style="color: red;">
                    <?php
                    echo esc_attr__("Site Errors", 'restore-classic-widgets');
                    ?>
                </h2>
                <p>
                    <?php
                    echo esc_attr__("Your site has experienced errors for the past 2 days. These errors, including JavaScript issues, can result in visual problems or disrupt functionality, ranging from minor glitches to critical site failures. JavaScript errors can terminate JavaScript execution, leaving all subsequent commands inoperable.", 'restore-classic-widgets');
                    ?>
                    <a href="https://wptoolsplugin.com/site-language-error-can-crash-your-site/">
                        <?php
                        echo esc_attr__("Learn More", 'restore-classic-widgets');
                        ?>
                    </a>
                </p>
    <?php
                $bill_count = 0;
                $bill_folders = [];

                $bill_themePath = get_theme_root();

                $error_log_path = trim(ini_get("error_log"));
                if (
                    !is_null($error_log_path) and $error_log_path != trim(ABSPATH . "error_log")
                ) {
                    $bill_folders[] = $error_log_path;
                }

                $bill_folders[] = ABSPATH . "error_log";
                $bill_folders[] = ABSPATH . "php_errorlog";
                $bill_folders[] = plugin_dir_path(__FILE__) . "/error_log";
                $bill_folders[] = plugin_dir_path(__FILE__) . "/php_errorlog";
                $bill_folders[] = get_theme_root() . "/error_log";
                $bill_folders[] = get_theme_root() . "/php_errorlog";

                // Adicionar caminhos específicos de administração se existirem
                $bill_admin_path = str_replace(
                    get_bloginfo("url") . "/",
                    ABSPATH,
                    get_admin_url()
                );
                $bill_folders[] = $bill_admin_path . "/error_log";
                $bill_folders[] = $bill_admin_path . "/php_errorlog";

                // Adicionar diretórios de plugins
                //$bill_plugins = array_slice(scandir(WPTOOLSPATH), 2);
                $bill_plugins = array_slice(scandir(plugin_dir_path(__FILE__)), 2);
                foreach ($bill_plugins as $bill_plugin) {
                    if (is_dir(plugin_dir_path(__FILE__) . "/" . $bill_plugin)) {
                        $bill_folders[] = plugin_dir_path(__FILE__) . "/" . $bill_plugin . "/error_log";
                        $bill_folders[] = plugin_dir_path(__FILE__) . "/" . $bill_plugin . "/php_errorlog";
                    }
                }


                $bill_themes = array_slice(scandir(get_theme_root()), 2);
                foreach ($bill_themes as $bill_theme) {
                    if (is_dir(get_theme_root() . "/" . $bill_theme)) {
                        $bill_folders[] = get_theme_root() . "/" . $bill_theme . "/error_log";
                        $bill_folders[] = get_theme_root() . "/" . $bill_theme . "/php_errorlog";
                    }
                }


                echo "<br />";
                echo esc_attr__("This is a partial list of the errors found.", 'restore-classic-widgets');
                echo "<br />";
                // Comeca a mostrar erros...
                //
                foreach ($bill_folders as $bill_folder) {
                    $files = glob($bill_folder);
                    if ($files === false) {
                        continue; // skip ...
                    }

                    // foreach (glob($bill_folder) as $bill_filename) 
                    foreach ($files as $bill_filename) {
                        if (strpos($bill_filename, "backup") != true) {
                            echo "<strong>";
                            echo esc_attr($bill_filename);
                            echo "</strong>";
                            $bill_count++;


                            $errorChecker = new ErrorChecker();
                            $marray = $errorChecker->bill_read_file($bill_filename, 3000);

                            //$marray = $this->bill_read_file($bill_filename, 3000);






                            if (gettype($marray) != "array" or count($marray) < 1) {
                                continue;
                            }
                            $total = count($marray);
                            if (count($marray) > 0) {
                                echo '<textarea style="width:99%;" id="anti_hacker" rows="12">';

                                if ($total > 1000) {
                                    $total = 1000;
                                }

                                for ($i = 0; $i < $total; $i++) {
                                    if (strpos(trim($marray[$i]), "[") !== 0) {
                                        continue; // Skip lines without correct date format
                                    }

                                    $logs = [];

                                    $line = trim($marray[$i]);
                                    if (empty($line)) {
                                        continue;
                                    }

                                    //  stack trace
                                    //[30-Sep-2023 11:28:52 UTC] PHP Stack trace:
                                    $pattern = "/PHP Stack trace:/";
                                    if (preg_match($pattern, $line, $matches)) {
                                        continue;
                                    }
                                    $pattern =
                                        "/\d{4}-\w{3}-\d{4} \d{2}:\d{2}:\d{2} UTC\] PHP \d+\./";
                                    if (preg_match($pattern, $line, $matches)) {
                                        continue;
                                    }
                                    //  end stack trace

                                    // Javascript ?
                                    if (strpos($line, "Javascript") !== false) {
                                        $is_javascript = true;
                                    } else {
                                        $is_javascript = false;
                                    }

                                    if ($is_javascript) {
                                        $matches = [];

                                        // die($line);

                                        $apattern = [];
                                        $apattern[] =
                                            "/(Error|Syntax|Type|TypeError|Reference|ReferenceError|Range|Eval|URI|Error .*?): (.*?) - URL: (https?:\/\/\S+).*?Line: (\d+).*?Column: (\d+).*?Error object: ({.*?})/";

                                        //$apattern[] =
                                        //    "/(Error|Syntax|Type|TypeError|Reference|ReferenceError|Range|Eval|URI|Error .*?): (.*?) - URL: (https?:\/\/\S+).*?Line: (\d+)/";


                                        $apattern[] =
                                            "/(SyntaxError|Error|Syntax|Type|TypeError|Reference|ReferenceError|Range|Eval|URI|Error .*?): (.*?) - URL: (https?:\/\/\S+).*?Line: (\d+)/";

                                        // Google Maps !
                                        //$apattern[] = "/Script error(?:\. - URL: (https?:\/\/\S+))?/i";

                                        $pattern = $apattern[0];

                                        for ($j = 0; $j < count($apattern); $j++) {
                                            if (
                                                preg_match($apattern[$j], $line, $matches)
                                            ) {
                                                $pattern = $apattern[$j];
                                                break;
                                            }
                                        }


                                        if (preg_match($pattern, $line, $matches)) {
                                            $matches[1] = str_replace(
                                                "Javascript ",
                                                "",
                                                $matches[1]
                                            );

                                            $filteredDate = strstr(substr($line, 1, 26), ']', true);

                                            // die(var_export(substr($line, 1, 25)));


                                            // $filteredDate = substr($line, 1, 20);



                                            if (count($matches) == 2) {
                                                $log_entry = [
                                                    "Date" => $filteredDate,
                                                    "Message Type" => "Script error",
                                                    "Problem Description" => "N/A",
                                                    "Script URL" => $matches[1],
                                                    "Line" => "N/A",
                                                ];
                                            } else {
                                                $log_entry = [
                                                    "Date" => $filteredDate,
                                                    "Message Type" => $matches[1],
                                                    "Problem Description" => $matches[2],
                                                    "Script URL" => $matches[3],
                                                    "Line" => $matches[4],
                                                ];
                                            }




                                            $script_path = $matches[3];
                                            $script_info = pathinfo($script_path);


                                            // Dividir o nome do script com base em ":"
                                            $parts = explode(":", $script_info["basename"]);

                                            // O nome do script agora está na primeira parte
                                            $scriptName = $parts[0];

                                            $log_entry["Script Name"] = $scriptName; // Get the script name

                                            $log_entry["Script Location"] =
                                                $script_info["dirname"]; // Get the script location

                                            if ($log_entry["Script Location"] == 'http:' or $log_entry["Script Location"] == 'https:')
                                                $log_entry["Script Location"] = $matches[3];













                                            if (
                                                strpos(
                                                    $log_entry["Script URL"],
                                                    "/wp-content/plugins/"
                                                ) !== false
                                            ) {
                                                // O erro ocorreu em um plugin
                                                $parts = explode(
                                                    "/wp-content/plugins/",
                                                    $log_entry["Script URL"]
                                                );
                                                if (count($parts) > 1) {
                                                    $plugin_parts = explode("/", $parts[1]);
                                                    $log_entry["File Type"] = "Plugin";
                                                    $log_entry["Plugin Name"] =
                                                        $plugin_parts[0];
                                                    //   $log_entry["Script Location"] =
                                                    //      "/wp-content/plugins/" .
                                                    //       $plugin_parts[0];
                                                }
                                            } elseif (
                                                strpos(
                                                    $log_entry["Script URL"],
                                                    "/wp-content/themes/"
                                                ) !== false
                                            ) {
                                                // O erro ocorreu em um tema
                                                $parts = explode(
                                                    "/wp-content/themes/",
                                                    $log_entry["Script URL"]
                                                );
                                                if (count($parts) > 1) {
                                                    $theme_parts = explode("/", $parts[1]);
                                                    $log_entry["File Type"] = "Theme";
                                                    $log_entry["Theme Name"] =
                                                        $theme_parts[0];
                                                    // $log_entry["Script Location"] =
                                                    //     "/wp-content/themes/" .
                                                    //     $theme_parts[0];
                                                }
                                            } else {
                                                // Caso não seja um tema nem um plugin, pode ser necessário ajustar o comportamento aqui.
                                                //$log_entry["Script Location"] = $matches[1];
                                            }

                                            // Extrair o nome do script do URL
                                            $script_name = basename(
                                                wp_parse_url(
                                                    $log_entry["Script URL"],
                                                    PHP_URL_PATH
                                                )
                                            );
                                            $log_entry["Script Name"] = $script_name;

                                            //echo $line."\n";





                                            if (isset($log_entry["Date"])) {
                                                echo "DATE: " . esc_html($log_entry["Date"]) . "\n";
                                            }
                                            if (isset($log_entry["Message Type"])) {
                                                echo "MESSAGE TYPE: (Javascript) " . esc_html($log_entry["Message Type"]) . "\n";
                                            }
                                            if (isset($log_entry["Problem Description"])) {
                                                echo "PROBLEM DESCRIPTION: " . esc_html($log_entry["Problem Description"]) . "\n";
                                            }

                                            if (isset($log_entry["Script Name"])) {
                                                echo "SCRIPT NAME: " . esc_html($log_entry["Script Name"]) . "\n";
                                            }
                                            if (isset($log_entry["Line"])) {
                                                echo "LINE: " . esc_html($log_entry["Line"]) . "\n";
                                            }
                                            if (isset($log_entry["Column"])) {
                                                //	echo "COLUMN: {$log_entry['Column']}\n";
                                            }
                                            if (isset($log_entry["Error Object"])) {
                                                //	echo "ERROR OBJECT: {$log_entry['Error Object']}\n";
                                            }
                                            if (isset($log_entry["Script Location"])) {
                                                echo "SCRIPT LOCATION: " . esc_html($log_entry["Script Location"]) . "\n";
                                            }
                                            if (isset($log_entry["Plugin Name"])) {
                                                echo "PLUGIN NAME: " . esc_html($log_entry["Plugin Name"]) . "\n";
                                            }
                                            if (isset($log_entry["Theme Name"])) {
                                                echo "THEME NAME: " . esc_html($log_entry["Theme Name"]) . "\n";
                                            }



                                            echo "------------------------\n";
                                            continue;
                                        } else {
                                            // echo "-----------x-------------\n";
                                            echo esc_html($line);
                                            echo "\n-----------x------------\n";
                                        }
                                        continue;
                                        // END JAVASCRIPT
                                    } else {



                                        // ---- PHP // 


                                        // continue;


                                        $apattern = [];
                                        $apattern[] =
                                            "/^\[.*\] PHP (Warning|Error|Notice|Fatal error|Parse error): (.*) in \/([^ ]+) on line (\d+)/";
                                        $apattern[] =
                                            "/^\[.*\] PHP (Warning|Error|Notice|Fatal error|Parse error): (.*) in \/([^ ]+):(\d+)$/";

                                        $pattern = $apattern[0];

                                        for ($j = 0; $j < count($apattern); $j++) {
                                            if (
                                                preg_match($apattern[$j], $line, $matches)
                                            ) {
                                                $pattern = $apattern[$j];
                                                break;
                                            }
                                        }

                                        if (preg_match($pattern, $line, $matches)) {
                                            //die(var_export($matches));


                                            $filteredDate = strstr(substr($line, 1, 26), ']', true);

                                            $log_entry = [
                                                "Date" => $filteredDate,
                                                "News Type" => $matches[1],
                                                "Problem Description" => recaptcha_for_all_bill_strip_strong99(
                                                    $matches[2]
                                                ),
                                            ];



                                            $script_path = $matches[3];
                                            $script_info = pathinfo($script_path);

                                            // Dividir o nome do script com base em ":"
                                            $parts = explode(":", $script_info["basename"]);

                                            // O nome do script agora está na primeira parte
                                            $scriptName = $parts[0];

                                            $log_entry["Script Name"] = $scriptName; // Get the script name

                                            $log_entry["Script Location"] =
                                                $script_info["dirname"]; // Get the script location

                                            $log_entry["Line"] = $matches[4];



                                            // Check if the "Script Location" contains "/plugins/" or "/themes/"
                                            if (
                                                strpos(
                                                    $log_entry["Script Location"],
                                                    "/plugins/"
                                                ) !== false
                                            ) {
                                                // Extract the plugin name
                                                $parts = explode(
                                                    "/plugins/",
                                                    $log_entry["Script Location"]
                                                );
                                                if (count($parts) > 1) {
                                                    $plugin_parts = explode("/", $parts[1]);
                                                    $log_entry["File Type"] = "Plugin";
                                                    $log_entry["Plugin Name"] =
                                                        $plugin_parts[0];
                                                }
                                            } elseif (
                                                strpos(
                                                    $log_entry["Script Location"],
                                                    "/themes/"
                                                ) !== false
                                            ) {
                                                // Extract the theme name
                                                $parts = explode(
                                                    "/themes/",
                                                    $log_entry["Script Location"]
                                                );
                                                if (count($parts) > 1) {
                                                    $theme_parts = explode("/", $parts[1]);
                                                    $log_entry["File Type"] = "Theme";
                                                    $log_entry["Theme Name"] =
                                                        $theme_parts[0];
                                                }
                                            }
                                        } else {
                                            // stack trace...
                                            $pattern = "/\[.*?\] PHP\s+\d+\.\s+(.*)/";
                                            preg_match($pattern, $line, $matches);

                                            if (!preg_match($pattern, $line)) {
                                                echo "-----------y-------------\n";
                                                echo esc_html($line);
                                                echo "\n-----------y------------\n";
                                            }
                                            continue;
                                        }

                                        //$in_error_block = false; // End the error block
                                        $logs[] = $log_entry; // Add this log entry to the array of logs

                                        foreach ($logs as $log) {
                                            if (isset($log["Date"])) {
                                                echo 'DATE: ' . esc_html($log["Date"]) . "\n";
                                            }
                                            if (isset($log["News Type"])) {
                                                echo 'MESSAGE TYPE: ' . esc_html($log["News Type"]) . "\n";
                                            }
                                            if (isset($log["Problem Description"])) {
                                                echo 'PROBLEM DESCRIPTION: ' . esc_html($log["Problem Description"]) . "\n";
                                            }

                                            // Check if the 'Script Name' key exists before printing
                                            if (isset($log["Script Name"]) && !empty(trim($log["Script Name"]))) {
                                                echo 'SCRIPT NAME: ' . esc_html($log["Script Name"]) . "\n";
                                            }

                                            // Check if the 'Line' key exists before printing
                                            if (isset($log["Line"])) {
                                                echo 'LINE: ' . esc_html($log["Line"]) . "\n";
                                            }

                                            // Check if the 'Script Location' key exists before printing
                                            if (isset($log["Script Location"])) {
                                                echo 'SCRIPT LOCATION: ' . esc_html($log["Script Location"]) . "\n";
                                            }

                                            // Check if the 'File Type' key exists before printing
                                            if (isset($log["File Type"])) {
                                                // echo "FILE TYPE: " . esc_html($log["File Type"]) . "\n";
                                            }

                                            // Check if the 'Plugin Name' key exists before printing
                                            if (isset($log["Plugin Name"]) && !empty(trim($log["Plugin Name"]))) {
                                                echo 'PLUGIN NAME: ' . esc_html($log["Plugin Name"]) . "\n";
                                            }

                                            // Check if the 'Theme Name' key exists before printing
                                            if (isset($log["Theme Name"])) {
                                                echo 'THEME NAME: ' . esc_html($log["Theme Name"]) . "\n";
                                            }

                                            echo "------------------------\n";
                                        }
                                    }
                                    // end if PHP ...
                                } // end for...

                                echo "</textarea>";
                            }
                            echo "<br />";
                        }
                    } // end for next each error_log...
                } // end fo next each folder...


            } // end tem errors...



            echo "</div>";
        } // end function site_health_tab_content($tab)


        //






        public function add_site_health_link_to_admin_toolbar($wp_admin_bar)
        {
            $logourl = plugin_dir_url(__FILE__) . "bell.png";
            $wp_admin_bar->add_node([
                "id" => "site-health",
                "title" =>
                '<span style="background-color: #ff0000; color: #fff; display: flex; align-items: center; padding: 0px 10px  0px 10px; ">' .
                    '<span style="border-radius: 50%; padding: 4px; display: inline-block; width: 20px; height: 20px; text-align: center; font-size: 12px; background-color: #ff0000; background-image: url(\'' .
                    esc_url($logourl) .
                    '\'); background-repeat: no-repeat; background-position: 0 6px; background-size: 20px;"></span> ' .
                    '<span style="background-color: #ff0000; color: #fff;">Site Health Issues</span>' .
                    "</span>",
                "href" => admin_url("site-health.php?tab=Critical+Issues"),
            ]);
        }

        public function custom_help_tab()
        {
            $screen = get_current_screen();
            // Verifique se você está na página desejada
            if ("site-health" === $screen->id) {
                // Adicione uma guia de ajuda
                $message = esc_attr__("These are critical issues that can have a significant impact on your site's performance. They can cause many plugins and functionalities to malfunction and, in some cases, render your site completely inoperative, depending on their severity. Address them promptly.", 'restore-classic-widgets');
                $screen->add_help_tab([
                    "id" => "custom-help-tab",
                    "title" => "Critical Issues",
                    "content" =>
                    "<p>" . esc_attr($message) . "</p>",
                ]);
            }
        }
        // add_action("admin_head", "custom_help_tab");
    } // end class
    /*
$plugin_slug = "database-backup"; // Replace with your actual text domain
$plugin_text_domain = "database-backup"; // Replace with your actual text domain
$notification_url = "https://wpmemory.com/fix-low-memory-limit/";
$notification_url2 =
    "https://billplugin.com/site-language-error-can-crash-your-site/";
*/
    $diagnose_instance = recaptcha_for_all_Bill_Diagnose::get_instance(
        $notification_url,
        $notification_url2,
    );
    update_option("recaptcha_for_all_bill_show_warnings", date("Y-m-d"));
