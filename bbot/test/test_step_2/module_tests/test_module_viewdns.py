from .base import ModuleTestBase


class TestViewDNS(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://viewdns.info/reversewhois/?q=blacklanternsecurity.com",
            text=web_body,
        )

    def check(self, module_test, events):
        assert any(
            e.data == "hyperloop.com" and "affiliate" in e.tags for e in events
        ), "Failed to detect affiliate domain"


web_body = """<html>
   <head>
      <meta name="google-site-verification" content="DUBJr87ZeILnfEKxhntAq9XPSZCa2mb3W4FAwXjKpyk" />
      <title>Reverse Whois Lookup - ViewDNS.info</title>
      <meta keywords="viewdns, dns, info, reverse ip, pagerank, portscan, port scan, lookup, records, whois, ipwhois, dnstools, web hosting, hosting, traceroute, dns report, dnsreport, ip location, ip location finder, spam, spam database, dnsbl, propagation, dns propagation checker, checker, china, chinese, firewall, great firewall, is my site down, is site down, site down, down, dns propagate">
      <meta description="This free tool will allow you to find domain names owned by an individual person or company.  Simply enter the email address or name of the person or company to find other domains registered using those same details.">
      <!-- form validation -->
      <script language="JavaScript" type="text/javascript">
         <!--
         /* break us out of any containing iframes */
         if (top != self) { top.location.replace(self.location.href); }
         
         function validate ( form )
         {
           for(v=0; v<form.elements.length; v++)
           {
             //trim element
             if(!String.prototype.trim) {   
               String.prototype.trim = function () {   
                 return this.replace(/^\s+|\s+$/g,'');   
               };   
             } 
             form.elements[v].value = form.elements[v].value.trim();
             
               
               //check for null value
               if (form.elements[v].value == "") 
               {
                 alert( "Value cannot be blank." );
                 form.elements[v].focus();
                 return false ;
               }
               //check if a domain parameter has a .
               if (form.elements[v].name == "domain" || form.elements[v].name == "ip")
               {
                 if (form.elements[v].value.indexOf('.') == -1)
                 {
                     //no . in domain/ip
                     alert("Invalid Domain/IP address.");
                     form.elements[v].focus();
                     return false;
                 }
               }
               //ensure only whitelisted characters have been entered
               if (form.elements[v].name == "asn")
                 var whitelist = /^[0-9]$/;
               else if (form.elements[v].name == "url")
                 return true;
               else
                 var whitelist = /^[0-9a-zA-Z.\-\_]$/;
               var data = form.elements[v].value;
               for (var i=0;i<data.length;i++)
               {
                 var thisChar = data.charAt(i);
                 if (!whitelist.test(thisChar))
                 {
                     alert( "Value contains invalid characters." );
                     form.elements[v].focus();
                     return false;
                 }
               }
           }
          
           return true ;
         }
         //-->
      </script>
      <!-- end form validation -->
      <!-- form validation -->
      <script language="JavaScript" type="text/javascript">
         <!--
         function validateReg ( form )
         {
           for(v=0; v<form.elements.length; v++)
           {
               //check for null value
               if (form.elements[v].name != "site")
               {
                   if (form.elements[v].value == "") 
                   {
                     alert( "Value cannot be blank." );
                     form.elements[v].focus();
                     return false ;
                   }
                 }
                 //make sure password length 8 and passwords match
                 if (document.register.pass1.value != document.register.pass2.value)
                 {
                     alert("Passwords do not match.");
                     return false;
                 }
                 if (document.register.pass1.value.length < 8)
                 {
                     alert("Password must be at least 8 characters.");
                     return false;
                 }       
                 
                 //check email address is valid
                 if (form.elements[v].name == "email")
                 {
                     var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
                 if (!re.test(form.elements[v].value))
                 {
                     alert("Email address is invalid.");
                     return false;
                 }
             }
           }
          
           return true ;
         }
         //-->
      </script>
      <!-- end form validation -->
      <style type="text/css">
         <!--
            .mainlinks { text-decoration: none; color: #000000 }
            -->
      </style>
      <!-- google analytics -->
      <script type="text/javascript">
         var _gaq = _gaq || [];
         _gaq.push(['_setAccount', 'UA-20325459-1']);
         _gaq.push(['_setDomainName', '.viewdns.info']);
         _gaq.push(['_trackPageview']);
         
         (function() {
           var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
           ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';
           var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);
         })();
         gtag('config', 'AW-1024044984');
      </script>
      <!-- /google analytics -->
      <style>
         #header ul {
         list-style: none;
         padding:0;
         padding-bottom: 2px; 
         margin:0;
         }
         #header li {
         float: left;
         border: 1px solid #CCCCCC;
         border-bottom-width: 0;
         margin: 0 0.5em 0 0;
         }
         #header li a {
         padding: 0 1em;
         color: #000000;
         text-decoration: none;
         }
         #header #selected {
         position: relative;
         top: 2px;
         padding-top: 5px;
         padding-bottom:4px;
         background: white;
         font-weight: bold;
         }
         #header #notselected {
         position: relative;
         top: 5px;
         padding-top: 2px;
         padding-bottom: 3px;
         background: #e1eae2;
         }
         body {
         font-family: Verdana, sans-serif;
         }
      </style>
      <link rel="apple-touch-icon" href="/apple-touch-icon.png"/>
      <!-- FBPX -->
      <script>
         !function(f,b,e,v,n,t,s)
         {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
         n.callMethod.apply(n,arguments):n.queue.push(arguments)};
         if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
         n.queue=[];t=b.createElement(e);t.async=!0;
         t.src=v;s=b.getElementsByTagName(e)[0];
         s.parentNode.insertBefore(t,s)}(window, document,'script',
         'https://connect.facebook.net/en_US/fbevents.js');
         fbq('init', '219605381956214');
         fbq('track', 'PageView');
      </script>
      <noscript><img height="1" width="1" style="display:none"
         src="https://www.facebook.com/tr?id=219605381956214&ev=PageView&noscript=1"
         /></noscript>
      <!-- FBPX -->
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
