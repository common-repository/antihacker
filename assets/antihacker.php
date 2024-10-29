<?php /*
Plugin Name: AntiHacker 
Plugin URI: http://antihackerplugin.com
Description: Anti Hacker Plugin. Restrict access to login page to whitelisted IP addresses.
Version: 1.00
Text Domain: anti-hacker
Domain Path: /lang
Author: Bill Minozzi
Author URI: http://billminozzi.com
License:     GPL2
Copyright (c) 2015 Bill Minozzi

 
Antihacker is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.
 
Antihacker is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with Antihacker. If not, see {License URI}.


Permission is hereby granted, free of charge subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/


if (!defined('ABSPATH'))
    exit; // Exit if accessed directly
    
// Add settings link on plugin page
function antihacker_plugin_settings_link($links) { 
  $settings_link = '<a href="options-general.php?page=anti-hacker">Settings</a>'; 
  array_unshift($links, $settings_link); 
  return $links; 
}
 
$plugin = plugin_basename(__FILE__); 
add_filter("plugin_action_links_$plugin", 'antihacker_plugin_settings_link' );

    
require_once (plugin_dir_path(__file__) . "settings/load-plugin.php");
require_once (plugin_dir_path(__file__) . "settings/options/plugin_options_tabbed.php");
    
    
add_filter('contextual_help', 'wptuts_contextual_help', 10, 3);
function wptuts_contextual_help($contextual_help, $screen_id, $screen)
{

    $myhelp = '<br> Improve system security and help prevent unauthorized access to your account by ';
    $myhelp .= 'restrict access to login page to whitelisted IP addresses.';
     
    $screen->add_help_tab(array(
        'id' => 'wptuts-overview-tab',
        'title' => __('Overview', 'plugin_domain'),
        'content' => '<p>' . $myhelp . '</p>',
        ));
    return $contextual_help;
}    
    
   

$my_whitelist = trim(get_option('my_whitelist'));
$my_whitelist = explode(PHP_EOL, $my_whitelist);

$ip = trim(ahfindip());

$admin_email = get_option( 'my_email_to' ); 



if (! whitelisted($ip, $my_whitelist)) {
    
    if(isset($_POST['myemail']))
       {
         $myemail = strtolower(trim($_POST['myemail']));
       }
       else
       {
         $myemail = '';
       }
       

    add_action('login_form', 'email_display');

    add_action('wp_authenticate_user', 'validate_email_field', 10, 2);

    function validate_email_field($user, $password)
    {
        global $myemail;

        if (!is_email($myemail))
            return new WP_Error('wrong_email', 'Please, fill out the email field!');
        else
           {
            
                $args = array(
                );
                
                // The Query
                $user_query = new WP_User_Query( array ( 'orderby' => 'registered', 'order' => 'ASC' ) );
                // User Loop
                if ( ! empty( $user_query->results ) ) {
                	foreach ( $user_query->results as $user ) {
                		// echo '<p>' . $user->user_email . '</p>';
                        
                        if(strtolower(trim($user->user_email)) == $myemail )
                                 return $user;
    
                	}
                } else {
                	// echo 'No users found.';
                }
                   
                    return new WP_Error( 'wrong_email', 'email not found!');
     
            
           } 
            
            
            return $user;

    }
    

    function email_display()
    { ?>
        <!-- <INPUT TYPE=CHECKBOX NAME="my_captcha">Yes, i'm a human! -->
        My Wordpress user email:
        <br />
        <input type="text" id="myemail" name="myemail" value="" placeholder="" size="100" />
        <br />
        <?     }


} /* endif if (! whitelisted($ip, $my_whitelist)) */



function my_detect_plugin_activation()
{

    global $ip;
    global $my_whitelist;
    
    if (empty($my_whitelist)) {

        $return = update_option('my_whitelist', esc_html($ip));

        if (!$return)
            $return = add_option('my_whitelist', esc_html($ip), 'no');


    }
}

register_activation_hook(__file__, 'my_detect_plugin_activation');







add_action('wp_login', 'successful_login');

function successful_login($user_login)
{

    global $my_whitelist;
    global $my_login_only_whitelist;
    global $my_radio_all_logins;
    global $ip;
    global $admin_email;


    $dt = date("Y-m-d H:i:s");
    $dom = $_SERVER['SERVER_NAME'];

    $msg = 'This email was sent from your website '.$dom. ' by the AntiHacker plugin. <br> ';

    $msg .= 'Date : ' . $dt . '<br>';
    $msg .= 'Ip: ' . $ip . '<br>';
    $msg .= 'Domain: ' . $dom . '<br>';
    $msg .= 'Role: ' . $user_login;
    $msg .= '<br>';
    $msg .= 'Add this IP to your withelist to stop this email';  
    
    $email_from = 'wordpress@'.$dom;

    // To send HTML mail, the Content-type header must be set
    $headers = 'MIME-Version: 1.0' . "\r\n";
    $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";

    // Create email headers
    $headers .= "From: ".$email_from. "\r\n" . 'Reply-To: ' . $user_login . "\r\n" .
        'X-Mailer: PHP/' . phpversion();
    
    $to = $admin_email;
    $subject = 'Login at: '.$dom;

    if ( ! whitelisted($ip, $my_whitelist)) {

             wp_mail( $to, $subject, $msg, $headers, '' );

    }
    
    return 1;

}




function whitelisted($ip, $my_whitelist)
{

    for ($i = 0; $i < count($my_whitelist); $i++) {


        if (trim($my_whitelist[$i]) == $ip)
            return 1;

    }
    return 0;

}


function ahfindip()
{

    $ip = '';

    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    $ip = trim($ip);

    if (!empty($ip))
        return $ip;
    else
        return 'unknow';


} ?>