from .base import ModuleTestBase


class TestViewDNS(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://viewdns.info/reversewhois/?q=blacklanternsecurity.com",
            text=web_body,
        )

    def check(self, module_test, events):
        assert any(e.data == "hyperloop.com" and "affiliate" in e.tags for e in events), (
            "Failed to detect affiliate domain"
        )


web_body = """<html>
   <head>
      <meta name="google-site-verification" content="DUBJr87ZeILnfEKxhntAq9XPSZCa2mb3W4FAwXjKpyk" />
      <title>Reverse Whois Lookup - ViewDNS.info</title>
      <meta keywords="viewdns, dns, info, reverse ip, pagerank, portscan, port scan, lookup, records, whois, ipwhois, dnstools, web hosting, hosting, traceroute, dns report, dnsreport, ip location, ip location finder, spam, spam database, dnsbl, propagation, dns propagation checker, checker, china, chinese, firewall, great firewall, is my site down, is site down, site down, down, dns propagate">
      <meta description="This free tool will allow you to find domain names owned by an individual person or company.  Simply enter the email address or name of the person or company to find other domains registered using those same details.">
      <!-- form validation -->
   </head>
   <body bgcolor="#ededed">
      <font face="Verdana">
      <table width="1000" align="center">
         <tr height="62">
            <td align="left" width="400"><a href="/"><img src="/images/viewdns_logo.gif" border="0" width="399" height="42.5" alt="ViewDNS.info - Your one source for DNS related tools!"></a></td>
            <td align="center" valign="middle">
               <script async src="//pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>
               <!-- ViewDNS 468x60 -->
               <ins class="adsbygoogle"
                  style="display:inline-block;width:468px;height:60px"
                  data-ad-client="ca-pub-7431844373287199"
                  data-ad-slot="1039512844"></ins>
               <script>
                  (adsbygoogle = window.adsbygoogle || []).push({});
               </script>
            </td>
         </tr>
      </table>
      <!-- tabs -->
      <!--<div id="header" width="1000" align="center"> -->
      <div id="header">
         <table width="1000" align="center" cellspacing="0" cellpadding="0">
            <tbody>
               <tr>
                  <td>
                     <ul>
                        <li id="selected"><a href="https://viewdns.info/">Tools</a></li>
                        <li id="notselected"><a href="https://viewdns.info/api/">API</a></li>
                        <li id="notselected"><a href="https://viewdns.info/research/">Research</a></li>
                        <li id="notselected"><a href="https://viewdns.info/data/">Data</a></li>
                     </ul>
                  </td>
               </tr>
            </tbody>
         </table>
      </div>
      <!--</div>-->
      <!-- end tabs-->
      <!--<div>-->
      <table width="1000" bgcolor="#FFFFFF" style="border: 1px solid #CCCCCC; padding: 5px" align="center" id="null">
         <tr></tr>
         <tr>
            <td>
               <font size="2">
                  <a href="/" style="color: #00721e;">ViewDNS.info</a> > <a href="/" style="color: #00721e;">Tools</a> >
                  <H1 style="font-size: 16; display: inline;">Reverse Whois Lookup</H1>
                  <br><br>This free tool will allow you to find domain names owned by an individual person or company.  Simply enter the email address or name of the person or company to find other domains registered using those same details. <a href="#" onclick="javascript:document.getElementById('faq').style.visibility = 'visible'; document.getElementById('faq').style.display = 'block';"  style="color: #00721e;">FAQ</a>.<br><br>
                  <div id="faq" style="visibility: hidden; display: none;"><u><b>Frequently Asked Questions</b></u><br>Q. Will this tool return results for all domains including ccTLD's?<br>A. Unfortunately no.  Whilst we do our best to ensure our data is as complete as possible, we are not able to return results for all ccTLD's.  Due to a number of technical limitations with whois data, the results from any Reverse Whois tool should not be considered as exhaustive.<br><br>Q. Is your data live?<br>A. Our data is not live.  We do our best to update the data as often as possible with daily updates for selected TLD's and quarterly updates for others.<br><br>Q. How do I see all records for a specific person/company rather than the limited number you show on your site?<br>A. Please <a href="mailto:feedback@viewdns.info?subject=Reverse Whois" style="color: #00721e;">email us</a> with your request and we'll see what we can do for you.<br><br></div>
                  <form name="reversewhois" action="" method="GET" >Registrant Name or Email Address: <br>
               </font>
               <input name="q" type="text" size="30"><input type="submit" value="GO"></form>
            </td>
         </tr>
         <tr>
            <td>
               <font size="2" face="Courier">Reverse Whois results for blacklanternsecurity.com<br>==============<br><br>There are 20 domains that matched this search query.<br>These are listed below:<br><br>
               <table border="1">
                  <tr>
                     <td>hyperloop.com</td>
                     <td>2003-12-04</td>
                     <td>NETWORK SOLUTIONS, LLC.</td>
                  </tr>
               </table>
               <br>
            </td>
         </tr>
         <tr></tr>
      </table>
      <!--</div>-->
      <table width="1000" align="center" border="0">
         <tr align="center">
            <td align="center">
               <script async src="//pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>
               <!-- viewdns-bottom-linkunit -->
               <ins class="adsbygoogle"
                  style="display:inline-block;width:728px;height:15px"
                  data-ad-client="ca-pub-7431844373287199"
                  data-ad-slot="9102586825"></ins>
               <script>
                  (adsbygoogle = window.adsbygoogle || []).push({});
               </script>
               <br /><br />
               <!-- fb -->
               <div id="fb-root"></div>
               <script>(function(d, s, id) {
                  var js, fjs = d.getElementsByTagName(s)[0];
                  if (d.getElementById(id)) return;
                  js = d.createElement(s); js.id = id;
                  js.src = "//connect.facebook.net/en_US/sdk.js#xfbml=1&appId=187997344602848&version=v2.0";
                  fjs.parentNode.insertBefore(js, fjs);
                  }(document, 'script', 'facebook-jssdk'));
               </script>
               <!-- end fb -->
               <a href="https://twitter.com/viewdns" class="twitter-follow-button" data-show-count="false" align="center">Follow @viewdns</a>
               <script>!function(d,s,id){var js,fjs=d.getElementsByTagName(s)[0];if(!d.getElementById(id)){js=d.createElement(s);js.id=id;js.src="//platform.twitter.com/widgets.js";fjs.parentNode.insertBefore(js,fjs);}}(document,"script","twitter-wjs");</script>
               <div class="fb-like" data-href="https://www.facebook.com/viewdns" data-layout="button" data-action="like" data-show-faces="true" data-share="true"></div>
               <br />
               <font size="1">All content &copy; 2023 ViewDNS.info<br><a href="mailto:feedback@viewdns.info?subject=Feedback" style="color: #00721e;">Feedback / Suggestions / Contact Us</a>&nbsp-&nbsp<a href="https://viewdns.info/privacy.php" style="color: #00721e;">Privacy Policy</a></font>
            </td>
         </tr>
      </table>
      <br />
      <table width="731" align="center" border="0">
         <tr align="center">
            <td align="center">
               <!--INLINE-->
               <script type="text/javascript"><!--
                  google_ad_client = "ca-pub-7431844373287199";
                  /* ViewDNS 728x90 */
                  google_ad_slot = "2958648842";
                  google_ad_width = 728;
                  google_ad_height = 90;
                  google_page_url="http://viewdns.info";
                  //-->
               </script>
               <script type="text/javascript"
                  src="//pagead2.googlesyndication.com/pagead/show_ads.js"></script>
            </td>
         </tr>
      </table>
      <center>
         <br>
         <br>
      </center>
      <!-- page generated in 0.41837406158447 seconds -->
   </body>
</html>"""
