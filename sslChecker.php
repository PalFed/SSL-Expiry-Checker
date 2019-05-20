<?php

if (file_exists(__DIR__."/sslChecker.ini.php")) {
	$config=parse_ini_file(__DIR__."/sslChecker.ini.php");
}
else {
	printError("Error: ".__DIR__."/sslChecker.ini.php not found");
	exit();
}


if (isset($_GET['domain'])) {
	$certDetails=getCertDetails($_GET['domain']);
	if (empty($certDetails)) print json_encode(['expiry'=>'An error occurred', 'daysLeft'=>'?', 'error'=>true]);
	else print json_encode(['expiry'=>date($config['dateFormat'], $certDetails['validTo_time_t']), 'daysLeft'=>$certDetails['validLeft']]);
	exit();
}

?>
<html>
<head>
	<title>SSL Checker</title>
	<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
	<style>
		th, td {border: 1px solid black;padding: 0.2em;}
		tr.error, tr.error a {background: purple; color: white;}
		tr.warn {background: orange;}
		tr.expired, tr.expired a {background: red; color: white;}
		tr.ok {background: lightgreen;}

		/* From https://tobiasahlin.com/spinkit/ */
		.spinner {
		  margin: 0px auto 0;
		  width: 40px;
		  text-align: center;
		}

		.spinner > div {
		  width: 8px;
		  height: 8px;
		  background-color: #333;

		  border-radius: 100%;
		  display: inline-block;
		  -webkit-animation: sk-bouncedelay 1.4s infinite ease-in-out both;
		  animation: sk-bouncedelay 1.4s infinite ease-in-out both;
		}

		.spinner .bounce1 {
		  -webkit-animation-delay: -0.32s;
		  animation-delay: -0.32s;
		}

		.spinner .bounce2 {
		  -webkit-animation-delay: -0.16s;
		  animation-delay: -0.16s;
		}

		@-webkit-keyframes sk-bouncedelay {
		  0%, 80%, 100% { -webkit-transform: scale(0) }
		  40% { -webkit-transform: scale(1.0) }
		}

		@keyframes sk-bouncedelay {
		  0%, 80%, 100% { 
		    -webkit-transform: scale(0);
		    transform: scale(0);
		  } 40% { 
		    -webkit-transform: scale(1.0);
		    transform: scale(1.0);
		  }
		}

	</style>
</head>
<body>
	<h1>SSL Expiry Checker</h1>
<table cellspacing="0" id="domains">
<thead><tr><th>Domain</th><th>Expiry Date</th><th>Days Until Expiry</th></tr></thead>
<tbody>
<?php
foreach ($config['domains'] as $domain) {
	print "<tr class=\"not-loaded\" data-domain=\"".$domain."\">";
	print "<td><a href=\"https://".$domain."\" target=\"_BLANK\" rel=\"noopener nofollow\">".$domain."</a></td>";
	
	print "<td class=\"expiry\">".getSpinnerHTML()."</td>";
	print "<td class=\"days-left\">".getSpinnerHTML()."</td>";
	print "</tr>";
}
?>
</tbody>
</table>

<script type="text/javascript">
$(document).ready(function() {
	$("tr.not-loaded").each(function() {
		var me=$(this);
		$.getJSON("sslchecker.php?domain="+me.data("domain"), function(data) {			
			me.removeClass("not-loaded");
			me.find(".expiry").html(data.expiry);
			me.find(".days-left").html(data.daysLeft);
			if (typeof data.error !== 'undefined') me.addClass("error");
			else if (data.daysLeft<0) me.addClass("expired");
			else if (data.daysLeft<<?php echo $config['warnDays']; ?>) me.addClass("warn");
			else me.addClass("ok");
			sortTable(2);
		});
	});  
});

function sortTable(index) {
	var table = $("#domains")
    var rows = table.find('tr:gt(0)').toArray().sort(comparer(index))
    for (var i = 0; i < rows.length; i++){table.append(rows[i])}

}

function comparer(index) {
    return function(a, b) {
        var valA = getCellValue(a, index), valB = getCellValue(b, index)
        return $.isNumeric(valA) && $.isNumeric(valB) ? valA - valB : valA.toString().localeCompare(valB)
    }
}
function getCellValue(row, index){ return $(row).children('td').eq(index).text() }
</script>

</body></html>

<?php

function getSpinnerHTML() {
	return '<div class="spinner">
  <div class="bounce1"></div>
  <div class="bounce2"></div>
  <div class="bounce3"></div>
</div>';
}

function getCertDetails($domain) {
	$url = "https://".$domain;
    $orignalParse = parse_url($url, PHP_URL_HOST);
    $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE, 'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true)));
    $read = stream_socket_client("ssl://".$orignalParse.":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
    $cert = stream_context_get_params($read);
    $certInfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
    if (empty($certInfo)) return false;

    $certExpiry=strtotime(date('Y-m-d', $certInfo['validTo_time_t'])." 00:00:00");
    $now=strtotime(date('Y-m-d', time())." 00:00:00");
    $certInfo['validLeft']=floor(($certExpiry-$now)/86400);
    
    return $certInfo;
}

function printError($msg) {
		?>
<html>
<head>
	<title>SSL Checker</title>
</head>
<body>
	<h1><?php echo $msg; ?></h1>
</body>
</html>
	<?php
}
