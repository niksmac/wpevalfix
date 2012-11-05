<?php
/**
 * WP Cleaner (Wordpress Fix)
 * Author: Lightrains Technolabs
 * URL: http://blog.lightrains.com/wordpress/fix-wordpress-malware-script-attack/
 * 
 */

ini_set('memory_limit','128M'); // If you have memory_limit problem just adjust to a higher value, like 256M

set_time_limit(0);
ob_start();
// header("Content-type:text/plain");
$root = "./";

$aPattern = array(
"^<\?php\s*\\\$md5\s*=\s*.*create_function\s*\(.*?\);\s*\\\$.*?\)\s*;\s*\?>\s*",
" echo \"<script type=\\\\\"text\/javascript\\\\\" src=\\\\\"http:\/\/.*\.js\\\\\"><\/script>\"; echo \"\";",
"<\?php\s*\@error_reporting\(0\);\s*if\s*\(\!isset\(([\$\w]+)\)\)\s*{[\$]+[^}]+}\s*\?>",
"<\?php\s*\/\*\w+_on\*\/.*\/\*\w+_off\*\/\s*\?>",
"<\?php\s*\/\*god_mode_on\*\/eval\(base64_decode\([\"'][^\"']{255,}[\"']\)\);\s*\/\*god_mode_off\*\/\s*\?>",
"<\?php\s*\?>",
"<IfModule\s*mod_rewrite\.c>\s*RewriteEngine\s*On\s*RewriteCond\s*%\{HTTP_REFERER\}\s*\^\.\*\([^\)]{255,}[google|yahoo|bing|ask|wikipedia|youtube][^\)]{255,}[^<]*<\/IfModule>",
"ErrorDocument\s*(?:400|401|403|404|500)+\s*http:\/\/.*\.\w+",
"^<script>(.*)<\/script>",
"^<\?php\s*\\\$md5\s*=\s*[\"|']\w+[\"|'];\s*\\\$wp_salt\s*=\s*[\w\(\),\"\'\;\$]+\s*\\\$wp_add_filter\s*=\s*create_function\(.*\);\s*\\\$wp_add_filter\(.*\);\s*\?>\s*",
"\s*eval\(base64_decode\([\"'][^\"']{255,}[\"']\)\);",
"if\(!function_exists\([^{]+\s*{\s*function[^}]+\s*}\s*[^\"']+\s*[\"'][^\"']+[\"'];\s*eval\s*\(.*\)\s*;\s*}\s*",
);

$find = '('.implode('|', $aPattern).')';

$except = array("rar", "zip", "mp3", "mp4", "mp3", "mov", "flv", "wmv", "swf", "png", "gif", "jpg", "bmp", "avi");
$only = array("php", "shtml", "html", "htm", "js", "css", "htaccess", "txt");
$infectedFiles = null;
$showOnlyInfectedFiles = true;
$cleanInfected = true;

echo "<h1>Scanning Files...</h1>";
echo "After scanning the files <a href='#infected-files' title='Found Infected Files'>click here to view found Infected files.</a>";

echo "<ol>";
$infectedFiles = scanall($root);
echo "</ol>";

echo "<br /><br /><h1 id='infected-files'>". count($infectedFiles) ." Found Infected Files</h1>";
echo "<ol>";
if(is_array($infectedFiles))
foreach($infectedFiles AS $iFile){
	echo "<li>{$iFile}</li>";
}
echo "</ol>";

/* functions */
function fetchfiles($dir){
global $except, $only;
	$filenames = null;
	if ($handle = opendir($dir)){
		while (false !== ($file = readdir($handle))) 
			if ($file != "." && $file != ".." && !is_dir($dir.$file) && ($dir != "." && $file != basename(__FILE__))){
				$path_parts = pathinfo($file);
				if(isset($path_parts['extension']) && array_search(strtolower($path_parts['extension']), $except) === false)
					if(array_search(strtolower($path_parts['basename']), $only) !== false || array_search(strtolower($path_parts['extension']), $only) !== false || sizeof($only) < 1)
						$filenames[] = $file;
			}
		closedir($handle);
	}

	return $filenames;
}

function fetchfolders($dir){
	$directories = null;
	if ($handle = opendir($dir)) {
		while (false !== ($file = readdir($handle)))
			if ($file != "." && $file != ".." && is_dir($dir.$file))
				$directories[] = $dir.$file;
		closedir($handle);
	}

	return $directories;
}

function scanall($root){
global $find, $infectedFiles, $showOnlyInfectedFiles, $cleanInfected;

	$time_start = microtime_float();
	$root = str_replace("//", "/", $root);
	echo "<li>".$root;
	$directories = fetchfolders($root);

	ob_implicit_flush();
	ob_flush();
	sleep(1);

	if(is_array($directories)){

		// get all files
		if(($tmp = fetchfiles($root)) !== null){
			echo "<ul>";
			$files = $tmp;
			foreach($files AS $file){
				$numMatches = checkMalware($root.$file, $find);
				if(!empty($numMatches)){
					if($cleanInfected)
						cleanInfected($root.$file, $find);

					echo "<li style='background-color:c00'><p style='padding:0 0 0 5px; margin:0; color:#fff'>".$infectedFiles[] = $root.$file;
					echo " - ".(microtime_float() - $time_start)."</p></li>";
				}elseif(!$showOnlyInfectedFiles){
					$infectedFiles[] = $root.$file;
					echo "<li>".$file."</li>"; // $root.$file
				}
			}
			echo "</ul>";
		}

		echo "<ol>";
		foreach($directories AS $dir){
			echo "<li>".$dir;
			 ob_implicit_flush();
			 ob_flush();
			 sleep(1);

			// get all files
			if(($tmp = fetchfiles($dir)) !== null){
				echo "<ul>";
				$files = $tmp;
				foreach($files AS $file){
					if($dir[strlen($dir)-1] === "/") $dir = substr($dir, 0, -1); 
					$numMatches = checkMalware($dir."/".$file, $find);
					if(!empty($numMatches)){
						if($cleanInfected)
							cleanInfected($dir."/".$file, $find);

						echo "<li style='background-color:c00'><p style='padding:0 0 0 5px; margin:0; color:#fff'>".$infectedFiles[] = $dir."/".$file;
						echo " - ".(microtime_float() - $time_start)."</p></li>";
					}elseif(!$showOnlyInfectedFiles){
						$infectedFiles[] = $dir."/".$file;
						echo "<li>".$file."</li>";
					}
				}
				echo "</ul>";
			}

			// gel all directories
			if($root[strlen($root)-1] === "/") $tmp_root = substr($root, 0, -1); 
			if(($tmp = fetchfolders($dir."/")) !== null && $dir !== $tmp_root){
				foreach($tmp AS $d){
					$a = scanall($d."/");
					if(is_array($a))
						array_merge($infectedFiles, $a);
				}

			}
			echo "</li>";
		}
		echo "</ol>";
	}else{
		// get all files
		if(($tmp = fetchfiles($root)) !== null){
			echo "<ul>";
			$files = $tmp;
			foreach($files AS $file){
				$numMatches = checkMalware($root.$file, $find);
				if(!empty($numMatches)){
					if($cleanInfected)
						cleanInfected($root.$file, $find);

					echo "<li style='background-color:c00'><p style='padding:0 0 0 5px; margin:0; color:#fff'>".$infectedFiles[] = $root.$file;
					echo " - ".(microtime_float() - $time_start)."</p></li>";
				}elseif(!$showOnlyInfectedFiles){
					$infectedFiles[] = $root.$file;
					echo "<li>".$file."</li>"; // $root.$file
				}
			}
			echo "</ul>";
		}
	}
	echo "</li>";

 return $infectedFiles;
}

function checkMalware($filename, $find){
	$numMatches = null;
	$handle = fopen($filename, "r");
	if(filesize($filename) > 0){
		$contents = fread($handle, filesize($filename));
		$numMatches = preg_match_all('/'.$find.'/is', $contents, $matches);
	}
	fclose($handle);
	return $numMatches;
}

function cleanInfected($filename, $find){

	$handle = fopen($filename, "r");
	if(filesize($filename) > 0){
		$contents = fread($handle, filesize($filename));
		fclose($handle);

		$handle = fopen($filename, "w");
		$contents = preg_replace('/'.$find.'/is', "", $contents);

		fwrite($handle, $contents);
	}
	fclose($handle);
}

function microtime_float(){
    list($usec, $sec) = explode(" ", microtime());
    return ((float)$usec + (float)$sec);
}

ob_end_flush();
ob_end_flush();