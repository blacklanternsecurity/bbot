from .base import ModuleTestBase


class TestSkymem(ModuleTestBase):
    targets = ["blacklanternsecurity.com"]

    def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.skymem.info/srch?q=blacklanternsecurity.com",
            text=page_1_body,
        )
        module_test.httpx_mock.add_response(
            url="https://www.skymem.info/domain/5679236812ad5b3f748a413d?p=2",
            text=page_2_body,
        )
        module_test.httpx_mock.add_response(
            url="https://www.skymem.info/domain/5679236812ad5b3f748a413d?p=3",
            text=page_3_body,
        )

    def check(self, module_test, events):
        assert any(e.data == "page1email@blacklanternsecurity.com" for e in events), "Failed to detect first email"
        assert any(e.data == "page2email@blacklanternsecurity.com" for e in events), "Failed to detect second email"
        assert any(e.data == "page3email@blacklanternsecurity.com" for e in events), "Failed to detect third email"


page_1_body = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />    
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails</title>
    <meta property="fb:app_id" content="876814239665436" /> 
    <meta name="keywords" content="email, emails, email list, email marketing, marketing,  contacts, contact">
    <meta name="description" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails">
    <meta name="author" content="Skymem">
    <meta property="og:title" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails" />
    <meta property="og:site_name" content="Skymem web page" />
    <meta property="og:type" content="website" />
    <meta property="og:url" content="http://www.skymem.info/srch?q=blacklanternsecurity.com" />
    <meta property="og:description" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails" />
    <meta property="og:image" content="http://www.skymem.info/images/www2.jpg" />
    <meta property="og:image:type" content="image/jpeg" />
    <meta property="og:image:width" content="400" />
    <meta property="og:image:height" content="300" />
    <meta name="google-site-verification" content="tfut_b-dbvVtExEHbFHdpQirHTtvQLRFmBJOBw38s7w" />
    <meta name="robots" content="noarchive">
    <!-- Material Design for Bootstrap fonts and icons -->
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700|Material+Icons">
<link href="/lib2/mcw/dist/material-components-web.css" rel="stylesheet" />
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/css/bootstrap.min.css" />
<meta name="x-stylesheet-fallback-test" content="" class="sr-only" /><script>!function(a,b,c,d){var e,f=document,g=f.getElementsByTagName("SCRIPT"),h=g[g.length-1].previousElementSibling,i=f.defaultView&&f.defaultView.getComputedStyle?f.defaultView.getComputedStyle(h):h.currentStyle;if(i&&i[a]!==b)for(e=0;e<c.length;e++)f.write('<link href="'+c[e]+'" '+d+"/>")}("position","absolute",["/lib2/bootstrap/dist/css/bootstrap.min.css"], "rel=\u0022stylesheet\u0022 ");</script>
<link rel="stylesheet" href="/lib2/angular-ui-grid/ui-grid.css" />
<link rel="stylesheet" href="/css/site.min.css" />
<script src="/lib2/angular/angular.min.js"></script>
        <script>            
            (function (i, s, o, g, r, a, m) {
                i['GoogleAnalyticsObject'] = r;
                i[r] = i[r] ||
                    function () {
                        (i[r].q = i[r].q || []).push(arguments);
                    }, i[r].l = 1 * new Date();
                a = s.createElement(o),
                    m = s.getElementsByTagName(o)[0];
                a.async = 1;
                a.src = g;
                m.parentNode.insertBefore(a, m);
            })(window, document, 'script', '//www.google-analytics.com/analytics.js', 'ga');
            ga('create', 'UA-177951-20', 'auto');
            ga('send', 'pageview');
        </script>
    <meta name="yandex-verification" content="552f869c3d2c3790" />
    <!-- Bing: Verify ownership for: www.skymem.info -->
    <meta name="msvalidate.01" content="C0E58004DB6ADBA4BDA8A8683D08CEF5" />
    <meta name="exoclick-site-verification" content="a21b82b756cc4c93d048b5d81c98ed70">
<meta name="ahrefs-site-verification" content="2dd82e09740f685c7a184846aa6da037541576526eda4833a0c622189d9a323a">
</head>
<body>
<script>
  window.fbAsyncInit = function() {
    FB.init({
      appId      : '876814239665436',
      xfbml      : true,
      version    : 'v12.0'
    });
    FB.AppEvents.logPageView();
  };
  (function(d, s, id){
     var js, fjs = d.getElementsByTagName(s)[0];
     if (d.getElementById(id)) {return;}
     js = d.createElement(s); js.id = id;
     js.src = "https://connect.facebook.net/en_US/sdk.js";
     fjs.parentNode.insertBefore(js, fjs);
   }(document, 'script', 'facebook-jssdk'));
</script>
<div id="fb-root"></div>
<script async defer crossorigin="anonymous" src="https://connect.facebook.net/en_US/sdk.js#xfbml=1&version=v12.0&appId=876814239665436&autoLogAppEvents=1" nonce="CJ4gP3PN"></script>
    <header>
        <div style="border-bottom:1px solid #ffffff;">
            <nav class="navbar navbar-expand-md navbar-light bg-light" style="border-bottom:1px solid #d8d8d8;background-color: #fff!important;">
                <div class="container">
                    <a class="navbar-brand valign-center text-muted" href="/"><i class="material-icons nav-link-go1">home</i></a>
                    <button class="navbar-toggler collapsed" type="button" data-toggle="collapse" data-target="#navbarsExample07" aria-controls="navbarsExample07" aria-expanded="false" aria-label="Toggle navigation">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="navbar-collapse collapse" id="navbarsExample07" style="">
                        <ul class="navbar-nav mr-auto">
                            <li class="nav-item">
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/list"><i class="material-icons" style="color:#007bff;">add</i> &nbsp; <span>Create email list</span></a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/lists"> <i class="material-icons">mail_outline</i> &nbsp; <span>Email Lists</span></a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/"> <i class="material-icons">search</i> &nbsp; <span></span></a>
                            </li>
                            
                        </ul>
                    </div>
                </div>
            </nav>
        </div>
    </header>
    <main role="main">\
        
<style>
img {
  margin: 0em auto;
  display: inline-block;  
  width: 18px;
}
</style>
<script>
    var EmptyListPackData =  {"DocResRep":{"ItemsUI":null,"UiLimit":{"Throttle":0.15,"MiningInAdCasePer":0,"MiningInNoAdCasePer":100,"ShowAd":false,"EmailShowOnFirstSearchPage":5,"RelatedEmailsMax":100,"RelatedEmailsItemsPerPage":10,"EmailSearchCountLimitOnMore":50,"DomainCountShowOnFirstSearchPage":10,"DomainRelatedLimitOnMore":200,"DomainRelatedItemsPerPage":25,"EmailsOfDomainShowPercentageOfAll":50,"ItemsPerPageOnList":5,"ListIdItemsPerPage":25,"MaxEmailsInTrial":50,"DownloadEmailsCountTrialLimit":30},"ListVersionId":null,"ListName":null,"ListFilter":{"ConditionANDs":[],"NEmailPerDomain":2000000,"EmailsLimitPerList":2000000,"HostLimitPerList":2000000,"EmailsPreviewMaxCount":100,"HostsPreviewMaxCount":5000},"ListPackDesc":null,"ListFilterItems":null,"HostORItems":null,"OtherORItems":null,"FV":null,"DomainCount":0,"EmailCount":0,"TotalNEmails":null,"FoundNEmails":null,"CloneBy":null,"ListInternalType":"Normal","MarketplaceLP":null,"OperationMod":"None","FinishedPercentage":0.0,"ListComplete":null,"ListCompleteStat":null,"TrialEmails":[],"PriceCalc":null,"BuyNowUrl":null,"TotalNDomains":null,"CreatorId":null,"CreatorName":null,"IdEntity":null,"IdDoc":null,"IdDocVer":null,"ExtraElements":null},"DocCollection":"","Resources":""}; 
</script>
<div ng-app="AppMain">
    <div ng-controller="SearchResultCtrl">
        <div class="container">
            
    <form class="form" role="form">
            <div class="input-group input-group-lg mb-3"
                 title="The search lets you find all the email addresses using one given domain name (for example, 'company.com').">
                <input type="text" style="min-width: 200px;" ng-model="Doc.SearchRequest" class="form-control" placeholder="company.com" autofocus />
                <span ng-init="Doc.SearchRequest='blacklanternsecurity.com'"></span>
                <div class="input-group-append">
                    <button type="submit" value="Submit" class="btn btn-primary btn-lg" ng-click="post()">
                        <div class="valign-center">
                            <i class="material-icons md-24">search</i>
                        </div>
                        <span class="d-none d-sm-inline-block"> Find </span> <span class="d-none d-md-inline-block">email </span> <span class="d-none d-lg-inline-block"> addresses</span>
                    </button>
                </div>
            </div>     
            <div style="position:relative; top:-18px;">
                <a href="#a" class="popovers" style="text-decoration:none;"
                   data-toggle="popover" data-trigger="manual" title="New feature in search"
                   data-original-title="New feature in search"
                   data-content="Type first and last name with domain name and we will do our best to find the email of this person. eg. <br /> <a href='/srch?q=david%20baker%20exeloncorp.com&ss=home'><strong>david baker exeloncorp.com</strong></a>">                   
                    <div class="valign-center" title="Type first and last name with domain name and we will do our best to find the email of this person. eg. david baker exeloncorp.com">                        
                        <i class="material-icons md-dark md-18" style="color:#c62a2a">new_releases</i>
                    </div>
                </a>
            </div>
    </form>
            <div style="margin: 0 0; text-align: center;">
            </div>
        <div class="row ">
                <div class="col-sm-8" style="padding-top:20px">
                    <!-- Emails found -------------------------------------------------------------------------- -->
                    <!-- Related emails -------------------------------------------------------------------------- -->
                    <!-- Domain XXX emails found -------------------------------------------------------------------------- -->
                        <div style="padding-bottom:20px">
                            <div class="valign-center text-muted mdc-typography--headline5" title="Domain related to this search result">
                                <!-- <i class="material-icons md-dark md-36">language</i>&nbsp; --> 
                <img style="width: 32px; margin-right:5px;" src="https://s2.googleusercontent.com/s2/favicons?domain=blacklanternsecurity.com&sz=128" />
                                <a href="/srch?q=blacklanternsecurity.com">blacklanternsecurity.com</a>&nbsp;
                                <span title="Press CTRL + mouse click or middle mouse button, to open in background tab. This is a link to external web site of this domene in form https://example.com. If web site in form www.example.com or is not have SSL change to http://www.example.com">
                                    <a href="https://blacklanternsecurity.com" target="_blank">
                                        <i class="material-icons" style="width:20px;font-size: 18px; color:#c1c1c1">outbound_outline</i>
                                    </a>
                                </span>
                                <small><small>(1768 emails)</small></small>
                            </div>
                            <span title="Buy Now all 1768 emails of domain blacklanternsecurity.com">
                                &nbsp;
                                <button type="button" class="btn btn-primary btn-sm" ng-disabled="DisabledBuyNow" ng-click="buyOneDomain('blacklanternsecurity.com')">
                                    <i class="material-icons md-18">arrow_right</i> Buy Now
                                </button>
                            </span>
                            <button class="mdc-icon-button material-icons md-18"
                                    style="color:#aaa"
                                    data-toggle="popover" data-trigger="focus" data-html="true" title="Buy Now"
                                    data-content=" &lt;b&gt;Buy now&lt;/b&gt; all &lt;b&gt;1768&lt;/b&gt; emails of &lt;b&gt;blacklanternsecurity.com&lt;/b&gt; domain.&lt;br /&gt;&#xD;&#xA;                                            &lt;b&gt;Here&lt;/b&gt; is only the preview part of all emails for this domain.&lt;br /&gt;&#xD;&#xA;                                             &lt;b&gt;After &lt;/b&gt; you press &lt;b&gt;Buy now&lt;/b&gt; button we will redirect you to email list with all emails of this domain,&#xD;&#xA;                                                    where you can buy it with PayPal or any of popular credit card or with Bitcoin (see &lt;a href=&#x27;/faq&#x27;&gt;FAQ&lt;/a&gt;) &lt;br /&gt;&lt;br /&gt;&#xD;&#xA;                                            ">
                                help_outline
                            </button>
                            <div ng-show="ShowProgressBar" class="ng-hide">
                                <div class="progress position-relative" style="height: 5px;margin-bottom:2px;">
                                    <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100"
                                         style="width:{{ProgressBarValue}}%;  background-color:rgb(148, 194, 250) !important;"></div>
                                    <span class="justify-content-center d-flex position-absolute w-100"></span>
                                </div>
                            </div>
                            <span hidden ng-init="Doc.DomainEmails.Host='blacklanternsecurity.com'"></span>
                            <span hidden ng-init="Doc.DomainEmails.IdEntity='5679236812ad5b3f748a413d'"></span>
                            <table class="table table-striped  table-sm table-hover table-bordered text-muted">
                                <thead class="table-primary">
                                    <tr class="info">
                                            <th style="width:1%;">#</th>
                                        <th>
                                            <div class="valign-center text-muted" title="Number of domain that filtered at least one email. Other domain is not in this list but it still you can see it in filter.">
                                                <i class="material-icons md-dark">mail_outline</i> &nbsp; Email
                                            </div>
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                            <tr>
                                                <td scope="row">1</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">2</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">3</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">4</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">5</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">6</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">7</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">8</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">9</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">10</td>
                                                <td>
                                                    <a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                </tbody>
                            </table>
                                <a href="/domain/5679236812ad5b3f748a413d?p=2"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
                                <a href="/domain/5679236812ad5b3f748a413d?p=3"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
                        </div>
                    <!-- Related domains -------------------------------------------------------------------------- -->
            <br />
            <br />
            <br />
            <br />
      <div class="fb-comments" data-href="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-width="100%" data-numposts="5"></div>
                </div>
            <div class="col-sm-4" style="padding-top:60px;">
             
<div  style="display:inline-block;vertical-align:top;">
    <div  style="display:inline-block;vertical-align:top;margin-top:-3px;">
        <div class="fb-save" data-uri="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-size="small"></div>        </div>     
    <div  style="display:inline-block;vertical-align:top;margin-top:0px;">
        <div class="fb-like" data-href="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-width="" data-layout="button_count" data-action="like" data-size="small" data-share="true" data-colorscheme="light"></div>
        </div>      
</div>             
<hr />
            
<div class="hidden-xs" style="text-align: left;">
    <div>
        
    </div>
</div>
<br />
<div class="hidden-xs" style="text-align: left;">
    <div>
        <br />
        
    </div>
</div>
<div class="hidden-xs" style="text-align: left;">
    <div>
        <br />
        
    </div>
</div>  
            <br />
            <br />
        </div>
            </div>
        </div>
    </div>
</div>
    </main>
    <footer class="text-muted" style="background-color: #ddd; margin-top: 60px; padding-top: 60px;">
        <div class="container">
            <hr>
            <div class="row">
                <div class="col-md-4">
                    <h4 class="font-weight-light">&copy; Skymem</h4>
                    <ul class="list-unstyled">
                        <li><a href="/">Home</a></li>
                        <li><a href="/list">Create new email list</a></li>
                        <li><a href="/faq">FAQ</a></li>
                        <li><a href="/lists">Email lists</a></li>
                <li>
<a href="#a" class="popovers" style="text-decoration:none;"
                   data-toggle="popover" data-trigger="manual" title="Name Extractor from text."
                   data-original-title="Name Extractor from text."
                   data-content="Try our new tool in (alfa version) for extracting person names from any kind of text.">                   
                    <div class="valign-center" title="Type first and last name with domain name and we will do our best to find the email of this person. eg. david baker exeloncorp.com">                        
                        <i class="material-icons md-dark md-18" style="color:#c62a2a">new_releases</i>
                    </div>
                </a>
                                <a href="http://name.skymem.info"> New Tool: <b>Name Explorer</b></a>
                            </li>
                <li>
                                <a href="http://martext.skymem.info"> MarText</a>
                            </li>
                        <li><a href="/donation">BitCoin Donations</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h4 class="font-weight-light">Contact</h4>
                    <ul class="list-unstyled">
                        <li><a href="/contact">Contact Us</a></li>
                        <li><a href="https://www.facebook.com/Skymem-128969217176249/" target="_blank">Facebook page</a></li>
            <li><a href="https://www.facebook.com/groups/169518103095402" target="_blank">Facebook group</a></li>
            <li><a href="https://twitter.com/skymem" target="_blank">Twitter</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h4 class="font-weight-light">Policies</h4>
                    <ul class="list-unstyled">
                        <li><a href="/dmca-policy">DMCA Policy</a></li>
                        <li><a href="/spam-policy">Spam Policy</a></li>
                        <li><a href="/cookies-policy">Cookies Policy</a></li>
                        <li><a href="/terms">Terms of Service</a></li>
                        <li><a href="/privacy-policy">Privacy Policy</a></li>
                        <li>
                            <a href="http://www1395355448.e-cdn.com" rel="nofollow" target="_blank">Fight Spam!</a>
                        </li>
                    </ul>
                </div>
            </div>
            <br />
        </div>
    </footer>
    
<script src="https://code.jquery.com/jquery-3.4.1.min.js" integrity="sha256-CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=" crossorigin="anonymous">
</script>
<script>(window.jQuery||document.write("\u003Cscript src=\u0022/lib2/jquery/jquery.min.js\u0022 integrity=\u0022sha256-CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=\u0022 crossorigin=\u0022anonymous\u0022\u003E\u003C/script\u003E"));</script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.bundle.min.js" integrity="sha384-xrRywqdh3PHs8keKZN+8zzc5TX0GRTLCcmivcbNJWm2rs5C8PRhcEn3czEjhAO9o" crossorigin="anonymous">
</script>
<script>(window.jQuery && window.jQuery.fn && window.jQuery.fn.modal||document.write("\u003Cscript src=\u0022/lib2/bootstrap/dist/js/bootstrap.bundle.min.js\u0022 integrity=\u0022sha384-xrRywqdh3PHs8keKZN\u002B8zzc5TX0GRTLCcmivcbNJWm2rs5C8PRhcEn3czEjhAO9o\u0022 crossorigin=\u0022anonymous\u0022\u003E\u003C/script\u003E"));</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js" integrity="sha256-VeNaFBVDhoX3H+gJ37DpT/nTuZTdjYro9yBruHjVmoQ=" crossorigin="anonymous"></script>
<script src="/lib2/angular-ui-grid/ui-grid.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/URI.js/1.19.1/URI.min.js"></script>
<script src="/tsscripts/tsc.js?v=8ScpiXoINQWyILwjXqQp3feeposq0Ze9zjhZzJBAxc8"></script>
<script src="/lib2/mcw/dist/material-components-web.min.js"></script>
<script>
    //$(function () {
    //    $('[data-toggle="popover"]').popover();
    //});
    $(function () {
        $("[data-toggle=popover]")
            .popover({ html: true })
            .on("focus", function () {
                $(this).popover("show");
            }).on("focusout", function () {
                var _this = this;
                if (!$(".popover:hover").length) {
                    $(this).popover("hide");
                }
                else {
                    $('.popover').mouseleave(function () {
                        $(_this).popover("hide");
                        $(this).off('mouseleave');
                    });
                }
            });
    });
    $('.popover-dismiss').popover({
        trigger: 'focus', html: true
    });
</script>
<!-- Facebook Pixel Code -->
<!-- End Facebook Pixel Code -->
    
</body>
</html>
"""
page_2_body = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />    
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails</title>
    <meta property="fb:app_id" content="876814239665436" /> 
    <meta name="keywords" content="email, emails, email list, email marketing, marketing,  contacts, contact">
    <meta name="description" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails">
    <meta name="author" content="Skymem">
    <meta property="og:title" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails" />
    <meta property="og:site_name" content="Skymem web page" />
    <meta property="og:type" content="website" />
    <meta property="og:url" content="http://www.skymem.info/srch?q=blacklanternsecurity.com" />
    <meta property="og:description" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails" />
    <meta property="og:image" content="http://www.skymem.info/images/www2.jpg" />
    <meta property="og:image:type" content="image/jpeg" />
    <meta property="og:image:width" content="400" />
    <meta property="og:image:height" content="300" />
    <meta name="google-site-verification" content="tfut_b-dbvVtExEHbFHdpQirHTtvQLRFmBJOBw38s7w" />
    <meta name="robots" content="noarchive">
    <!-- Material Design for Bootstrap fonts and icons -->
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700|Material+Icons">
<link href="/lib2/mcw/dist/material-components-web.css" rel="stylesheet" />
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/css/bootstrap.min.css" />
<meta name="x-stylesheet-fallback-test" content="" class="sr-only" /><script>!function(a,b,c,d){var e,f=document,g=f.getElementsByTagName("SCRIPT"),h=g[g.length-1].previousElementSibling,i=f.defaultView&&f.defaultView.getComputedStyle?f.defaultView.getComputedStyle(h):h.currentStyle;if(i&&i[a]!==b)for(e=0;e<c.length;e++)f.write('<link href="'+c[e]+'" '+d+"/>")}("position","absolute",["/lib2/bootstrap/dist/css/bootstrap.min.css"], "rel=\u0022stylesheet\u0022 ");</script>
<link rel="stylesheet" href="/lib2/angular-ui-grid/ui-grid.css" />
<link rel="stylesheet" href="/css/site.min.css" />
<script src="/lib2/angular/angular.min.js"></script>
        <script>            
            (function (i, s, o, g, r, a, m) {
                i['GoogleAnalyticsObject'] = r;
                i[r] = i[r] ||
                    function () {
                        (i[r].q = i[r].q || []).push(arguments);
                    }, i[r].l = 1 * new Date();
                a = s.createElement(o),
                    m = s.getElementsByTagName(o)[0];
                a.async = 1;
                a.src = g;
                m.parentNode.insertBefore(a, m);
            })(window, document, 'script', '//www.google-analytics.com/analytics.js', 'ga');
            ga('create', 'UA-177951-20', 'auto');
            ga('send', 'pageview');
        </script>
    <meta name="yandex-verification" content="552f869c3d2c3790" />
    <!-- Bing: Verify ownership for: www.skymem.info -->
    <meta name="msvalidate.01" content="C0E58004DB6ADBA4BDA8A8683D08CEF5" />
    <meta name="exoclick-site-verification" content="a21b82b756cc4c93d048b5d81c98ed70">
<meta name="ahrefs-site-verification" content="2dd82e09740f685c7a184846aa6da037541576526eda4833a0c622189d9a323a">
</head>
<body>
<script>
  window.fbAsyncInit = function() {
    FB.init({
      appId      : '876814239665436',
      xfbml      : true,
      version    : 'v12.0'
    });
    FB.AppEvents.logPageView();
  };
  (function(d, s, id){
     var js, fjs = d.getElementsByTagName(s)[0];
     if (d.getElementById(id)) {return;}
     js = d.createElement(s); js.id = id;
     js.src = "https://connect.facebook.net/en_US/sdk.js";
     fjs.parentNode.insertBefore(js, fjs);
   }(document, 'script', 'facebook-jssdk'));
</script>
<div id="fb-root"></div>
<script async defer crossorigin="anonymous" src="https://connect.facebook.net/en_US/sdk.js#xfbml=1&version=v12.0&appId=876814239665436&autoLogAppEvents=1" nonce="CJ4gP3PN"></script>
    <header>
        <div style="border-bottom:1px solid #ffffff;">
            <nav class="navbar navbar-expand-md navbar-light bg-light" style="border-bottom:1px solid #d8d8d8;background-color: #fff!important;">
                <div class="container">
                    <a class="navbar-brand valign-center text-muted" href="/"><i class="material-icons nav-link-go1">home</i></a>
                    <button class="navbar-toggler collapsed" type="button" data-toggle="collapse" data-target="#navbarsExample07" aria-controls="navbarsExample07" aria-expanded="false" aria-label="Toggle navigation">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="navbar-collapse collapse" id="navbarsExample07" style="">
                        <ul class="navbar-nav mr-auto">
                            <li class="nav-item">
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/list"><i class="material-icons" style="color:#007bff;">add</i> &nbsp; <span>Create email list</span></a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/lists"> <i class="material-icons">mail_outline</i> &nbsp; <span>Email Lists</span></a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/"> <i class="material-icons">search</i> &nbsp; <span></span></a>
                            </li>
                            
                        </ul>
                    </div>
                </div>
            </nav>
        </div>
    </header>
    <main role="main">\
        
<style>
img {
  margin: 0em auto;
  display: inline-block;  
  width: 18px;
}
</style>
<script>
    var EmptyListPackData =  {"DocResRep":{"ItemsUI":null,"UiLimit":{"Throttle":0.15,"MiningInAdCasePer":0,"MiningInNoAdCasePer":100,"ShowAd":false,"EmailShowOnFirstSearchPage":5,"RelatedEmailsMax":100,"RelatedEmailsItemsPerPage":10,"EmailSearchCountLimitOnMore":50,"DomainCountShowOnFirstSearchPage":10,"DomainRelatedLimitOnMore":200,"DomainRelatedItemsPerPage":25,"EmailsOfDomainShowPercentageOfAll":50,"ItemsPerPageOnList":5,"ListIdItemsPerPage":25,"MaxEmailsInTrial":50,"DownloadEmailsCountTrialLimit":30},"ListVersionId":null,"ListName":null,"ListFilter":{"ConditionANDs":[],"NEmailPerDomain":2000000,"EmailsLimitPerList":2000000,"HostLimitPerList":2000000,"EmailsPreviewMaxCount":100,"HostsPreviewMaxCount":5000},"ListPackDesc":null,"ListFilterItems":null,"HostORItems":null,"OtherORItems":null,"FV":null,"DomainCount":0,"EmailCount":0,"TotalNEmails":null,"FoundNEmails":null,"CloneBy":null,"ListInternalType":"Normal","MarketplaceLP":null,"OperationMod":"None","FinishedPercentage":0.0,"ListComplete":null,"ListCompleteStat":null,"TrialEmails":[],"PriceCalc":null,"BuyNowUrl":null,"TotalNDomains":null,"CreatorId":null,"CreatorName":null,"IdEntity":null,"IdDoc":null,"IdDocVer":null,"ExtraElements":null},"DocCollection":"","Resources":""}; 
</script>
<div ng-app="AppMain">
    <div ng-controller="SearchResultCtrl">
        <div class="container">
            
    <form class="form" role="form">
            <div class="input-group input-group-lg mb-3"
                 title="The search lets you find all the email addresses using one given domain name (for example, 'company.com').">
                <input type="text" style="min-width: 200px;" ng-model="Doc.SearchRequest" class="form-control" placeholder="company.com" autofocus />
                <span ng-init="Doc.SearchRequest='blacklanternsecurity.com'"></span>
                <div class="input-group-append">
                    <button type="submit" value="Submit" class="btn btn-primary btn-lg" ng-click="post()">
                        <div class="valign-center">
                            <i class="material-icons md-24">search</i>
                        </div>
                        <span class="d-none d-sm-inline-block"> Find </span> <span class="d-none d-md-inline-block">email </span> <span class="d-none d-lg-inline-block"> addresses</span>
                    </button>
                </div>
            </div>     
            <div style="position:relative; top:-18px;">
                <a href="#a" class="popovers" style="text-decoration:none;"
                   data-toggle="popover" data-trigger="manual" title="New feature in search"
                   data-original-title="New feature in search"
                   data-content="Type first and last name with domain name and we will do our best to find the email of this person. eg. <br /> <a href='/srch?q=david%20baker%20exeloncorp.com&ss=home'><strong>david baker exeloncorp.com</strong></a>">                   
                    <div class="valign-center" title="Type first and last name with domain name and we will do our best to find the email of this person. eg. david baker exeloncorp.com">                        
                        <i class="material-icons md-dark md-18" style="color:#c62a2a">new_releases</i>
                    </div>
                </a>
            </div>
    </form>
            <div style="margin: 0 0; text-align: center;">
            </div>
        <div class="row ">
                <div class="col-sm-8" style="padding-top:20px">
                    <!-- Emails found -------------------------------------------------------------------------- -->
                    <!-- Related emails -------------------------------------------------------------------------- -->
                    <!-- Domain XXX emails found -------------------------------------------------------------------------- -->
                        <div style="padding-bottom:20px">
                            <div class="valign-center text-muted mdc-typography--headline5" title="Domain related to this search result">
                                <!-- <i class="material-icons md-dark md-36">language</i>&nbsp; --> 
                <img style="width: 32px; margin-right:5px;" src="https://s2.googleusercontent.com/s2/favicons?domain=blacklanternsecurity.com&sz=128" />
                                <a href="/srch?q=blacklanternsecurity.com">blacklanternsecurity.com</a>&nbsp;
                                <span title="Press CTRL + mouse click or middle mouse button, to open in background tab. This is a link to external web site of this domene in form https://example.com. If web site in form www.example.com or is not have SSL change to http://www.example.com">
                                    <a href="https://blacklanternsecurity.com" target="_blank">
                                        <i class="material-icons" style="width:20px;font-size: 18px; color:#c1c1c1">outbound_outline</i>
                                    </a>
                                </span>
                                <small><small>(1768 emails)</small></small>
                            </div>
                            <span title="Buy Now all 1768 emails of domain blacklanternsecurity.com">
                                &nbsp;
                                <button type="button" class="btn btn-primary btn-sm" ng-disabled="DisabledBuyNow" ng-click="buyOneDomain('blacklanternsecurity.com')">
                                    <i class="material-icons md-18">arrow_right</i> Buy Now
                                </button>
                            </span>
                            <button class="mdc-icon-button material-icons md-18"
                                    style="color:#aaa"
                                    data-toggle="popover" data-trigger="focus" data-html="true" title="Buy Now"
                                    data-content=" &lt;b&gt;Buy now&lt;/b&gt; all &lt;b&gt;1768&lt;/b&gt; emails of &lt;b&gt;blacklanternsecurity.com&lt;/b&gt; domain.&lt;br /&gt;&#xD;&#xA;                                            &lt;b&gt;Here&lt;/b&gt; is only the preview part of all emails for this domain.&lt;br /&gt;&#xD;&#xA;                                             &lt;b&gt;After &lt;/b&gt; you press &lt;b&gt;Buy now&lt;/b&gt; button we will redirect you to email list with all emails of this domain,&#xD;&#xA;                                                    where you can buy it with PayPal or any of popular credit card or with Bitcoin (see &lt;a href=&#x27;/faq&#x27;&gt;FAQ&lt;/a&gt;) &lt;br /&gt;&lt;br /&gt;&#xD;&#xA;                                            ">
                                help_outline
                            </button>
                            <div ng-show="ShowProgressBar" class="ng-hide">
                                <div class="progress position-relative" style="height: 5px;margin-bottom:2px;">
                                    <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100"
                                         style="width:{{ProgressBarValue}}%;  background-color:rgb(148, 194, 250) !important;"></div>
                                    <span class="justify-content-center d-flex position-absolute w-100"></span>
                                </div>
                            </div>
                            <span hidden ng-init="Doc.DomainEmails.Host='blacklanternsecurity.com'"></span>
                            <span hidden ng-init="Doc.DomainEmails.IdEntity='5679236812ad5b3f748a413d'"></span>
                            <table class="table table-striped  table-sm table-hover table-bordered text-muted">
                                <thead class="table-primary">
                                    <tr class="info">
                                            <th style="width:1%;">#</th>
                                        <th>
                                            <div class="valign-center text-muted" title="Number of domain that filtered at least one email. Other domain is not in this list but it still you can see it in filter.">
                                                <i class="material-icons md-dark">mail_outline</i> &nbsp; Email
                                            </div>
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                            <tr>
                                                <td scope="row">1</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">2</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">3</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">4</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">5</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">6</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">7</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">8</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">9</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">10</td>
                                                <td>
                                                    <a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                </tbody>
                            </table>
                                <a href="/domain/5679236812ad5b3f748a413d?p=2"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
                                <a href="/domain/5679236812ad5b3f748a413d?p=3"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
                        </div>
                    <!-- Related domains -------------------------------------------------------------------------- -->
            <br />
            <br />
            <br />
            <br />
      <div class="fb-comments" data-href="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-width="100%" data-numposts="5"></div>
                </div>
            <div class="col-sm-4" style="padding-top:60px;">
             
<div  style="display:inline-block;vertical-align:top;">
    <div  style="display:inline-block;vertical-align:top;margin-top:-3px;">
        <div class="fb-save" data-uri="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-size="small"></div>        </div>     
    <div  style="display:inline-block;vertical-align:top;margin-top:0px;">
        <div class="fb-like" data-href="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-width="" data-layout="button_count" data-action="like" data-size="small" data-share="true" data-colorscheme="light"></div>
        </div>      
</div>             
<hr />
            
<div class="hidden-xs" style="text-align: left;">
    <div>
        
    </div>
</div>
<br />
<div class="hidden-xs" style="text-align: left;">
    <div>
        <br />
        
    </div>
</div>
<div class="hidden-xs" style="text-align: left;">
    <div>
        <br />
        
    </div>
</div>  
            <br />
            <br />
        </div>
            </div>
        </div>
    </div>
</div>
    </main>
    <footer class="text-muted" style="background-color: #ddd; margin-top: 60px; padding-top: 60px;">
        <div class="container">
            <hr>
            <div class="row">
                <div class="col-md-4">
                    <h4 class="font-weight-light">&copy; Skymem</h4>
                    <ul class="list-unstyled">
                        <li><a href="/">Home</a></li>
                        <li><a href="/list">Create new email list</a></li>
                        <li><a href="/faq">FAQ</a></li>
                        <li><a href="/lists">Email lists</a></li>
                <li>
<a href="#a" class="popovers" style="text-decoration:none;"
                   data-toggle="popover" data-trigger="manual" title="Name Extractor from text."
                   data-original-title="Name Extractor from text."
                   data-content="Try our new tool in (alfa version) for extracting person names from any kind of text.">                   
                    <div class="valign-center" title="Type first and last name with domain name and we will do our best to find the email of this person. eg. david baker exeloncorp.com">                        
                        <i class="material-icons md-dark md-18" style="color:#c62a2a">new_releases</i>
                    </div>
                </a>
                                <a href="http://name.skymem.info"> New Tool: <b>Name Explorer</b></a>
                            </li>
                <li>
                                <a href="http://martext.skymem.info"> MarText</a>
                            </li>
                        <li><a href="/donation">BitCoin Donations</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h4 class="font-weight-light">Contact</h4>
                    <ul class="list-unstyled">
                        <li><a href="/contact">Contact Us</a></li>
                        <li><a href="https://www.facebook.com/Skymem-128969217176249/" target="_blank">Facebook page</a></li>
            <li><a href="https://www.facebook.com/groups/169518103095402" target="_blank">Facebook group</a></li>
            <li><a href="https://twitter.com/skymem" target="_blank">Twitter</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h4 class="font-weight-light">Policies</h4>
                    <ul class="list-unstyled">
                        <li><a href="/dmca-policy">DMCA Policy</a></li>
                        <li><a href="/spam-policy">Spam Policy</a></li>
                        <li><a href="/cookies-policy">Cookies Policy</a></li>
                        <li><a href="/terms">Terms of Service</a></li>
                        <li><a href="/privacy-policy">Privacy Policy</a></li>
                        <li>
                            <a href="http://www1395355448.e-cdn.com" rel="nofollow" target="_blank">Fight Spam!</a>
                        </li>
                    </ul>
                </div>
            </div>
            <br />
        </div>
    </footer>
    
<script src="https://code.jquery.com/jquery-3.4.1.min.js" integrity="sha256-CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=" crossorigin="anonymous">
</script>
<script>(window.jQuery||document.write("\u003Cscript src=\u0022/lib2/jquery/jquery.min.js\u0022 integrity=\u0022sha256-CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=\u0022 crossorigin=\u0022anonymous\u0022\u003E\u003C/script\u003E"));</script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.bundle.min.js" integrity="sha384-xrRywqdh3PHs8keKZN+8zzc5TX0GRTLCcmivcbNJWm2rs5C8PRhcEn3czEjhAO9o" crossorigin="anonymous">
</script>
<script>(window.jQuery && window.jQuery.fn && window.jQuery.fn.modal||document.write("\u003Cscript src=\u0022/lib2/bootstrap/dist/js/bootstrap.bundle.min.js\u0022 integrity=\u0022sha384-xrRywqdh3PHs8keKZN\u002B8zzc5TX0GRTLCcmivcbNJWm2rs5C8PRhcEn3czEjhAO9o\u0022 crossorigin=\u0022anonymous\u0022\u003E\u003C/script\u003E"));</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js" integrity="sha256-VeNaFBVDhoX3H+gJ37DpT/nTuZTdjYro9yBruHjVmoQ=" crossorigin="anonymous"></script>
<script src="/lib2/angular-ui-grid/ui-grid.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/URI.js/1.19.1/URI.min.js"></script>
<script src="/tsscripts/tsc.js?v=8ScpiXoINQWyILwjXqQp3feeposq0Ze9zjhZzJBAxc8"></script>
<script src="/lib2/mcw/dist/material-components-web.min.js"></script>
<script>
    //$(function () {
    //    $('[data-toggle="popover"]').popover();
    //});
    $(function () {
        $("[data-toggle=popover]")
            .popover({ html: true })
            .on("focus", function () {
                $(this).popover("show");
            }).on("focusout", function () {
                var _this = this;
                if (!$(".popover:hover").length) {
                    $(this).popover("hide");
                }
                else {
                    $('.popover').mouseleave(function () {
                        $(_this).popover("hide");
                        $(this).off('mouseleave');
                    });
                }
            });
    });
    $('.popover-dismiss').popover({
        trigger: 'focus', html: true
    });
</script>
<!-- Facebook Pixel Code -->
<!-- End Facebook Pixel Code -->
    
</body>
</html>"""
page_3_body = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />    
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails</title>
    <meta property="fb:app_id" content="876814239665436" /> 
    <meta name="keywords" content="email, emails, email list, email marketing, marketing,  contacts, contact">
    <meta name="description" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails">
    <meta name="author" content="Skymem">
    <meta property="og:title" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails" />
    <meta property="og:site_name" content="Skymem web page" />
    <meta property="og:type" content="website" />
    <meta property="og:url" content="http://www.skymem.info/srch?q=blacklanternsecurity.com" />
    <meta property="og:description" content="q=blacklanternsecurity.com - blacklanternsecurity.com=1768 emails" />
    <meta property="og:image" content="http://www.skymem.info/images/www2.jpg" />
    <meta property="og:image:type" content="image/jpeg" />
    <meta property="og:image:width" content="400" />
    <meta property="og:image:height" content="300" />
    <meta name="google-site-verification" content="tfut_b-dbvVtExEHbFHdpQirHTtvQLRFmBJOBw38s7w" />
    <meta name="robots" content="noarchive">
    <!-- Material Design for Bootstrap fonts and icons -->
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700|Material+Icons">
<link href="/lib2/mcw/dist/material-components-web.css" rel="stylesheet" />
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/css/bootstrap.min.css" />
<meta name="x-stylesheet-fallback-test" content="" class="sr-only" /><script>!function(a,b,c,d){var e,f=document,g=f.getElementsByTagName("SCRIPT"),h=g[g.length-1].previousElementSibling,i=f.defaultView&&f.defaultView.getComputedStyle?f.defaultView.getComputedStyle(h):h.currentStyle;if(i&&i[a]!==b)for(e=0;e<c.length;e++)f.write('<link href="'+c[e]+'" '+d+"/>")}("position","absolute",["/lib2/bootstrap/dist/css/bootstrap.min.css"], "rel=\u0022stylesheet\u0022 ");</script>
<link rel="stylesheet" href="/lib2/angular-ui-grid/ui-grid.css" />
<link rel="stylesheet" href="/css/site.min.css" />
<script src="/lib2/angular/angular.min.js"></script>
        <script>            
            (function (i, s, o, g, r, a, m) {
                i['GoogleAnalyticsObject'] = r;
                i[r] = i[r] ||
                    function () {
                        (i[r].q = i[r].q || []).push(arguments);
                    }, i[r].l = 1 * new Date();
                a = s.createElement(o),
                    m = s.getElementsByTagName(o)[0];
                a.async = 1;
                a.src = g;
                m.parentNode.insertBefore(a, m);
            })(window, document, 'script', '//www.google-analytics.com/analytics.js', 'ga');
            ga('create', 'UA-177951-20', 'auto');
            ga('send', 'pageview');
        </script>
    <meta name="yandex-verification" content="552f869c3d2c3790" />
    <!-- Bing: Verify ownership for: www.skymem.info -->
    <meta name="msvalidate.01" content="C0E58004DB6ADBA4BDA8A8683D08CEF5" />
    <meta name="exoclick-site-verification" content="a21b82b756cc4c93d048b5d81c98ed70">
<meta name="ahrefs-site-verification" content="2dd82e09740f685c7a184846aa6da037541576526eda4833a0c622189d9a323a">
</head>
<body>
<script>
  window.fbAsyncInit = function() {
    FB.init({
      appId      : '876814239665436',
      xfbml      : true,
      version    : 'v12.0'
    });
    FB.AppEvents.logPageView();
  };
  (function(d, s, id){
     var js, fjs = d.getElementsByTagName(s)[0];
     if (d.getElementById(id)) {return;}
     js = d.createElement(s); js.id = id;
     js.src = "https://connect.facebook.net/en_US/sdk.js";
     fjs.parentNode.insertBefore(js, fjs);
   }(document, 'script', 'facebook-jssdk'));
</script>
<div id="fb-root"></div>
<script async defer crossorigin="anonymous" src="https://connect.facebook.net/en_US/sdk.js#xfbml=1&version=v12.0&appId=876814239665436&autoLogAppEvents=1" nonce="CJ4gP3PN"></script>
    <header>
        <div style="border-bottom:1px solid #ffffff;">
            <nav class="navbar navbar-expand-md navbar-light bg-light" style="border-bottom:1px solid #d8d8d8;background-color: #fff!important;">
                <div class="container">
                    <a class="navbar-brand valign-center text-muted" href="/"><i class="material-icons nav-link-go1">home</i></a>
                    <button class="navbar-toggler collapsed" type="button" data-toggle="collapse" data-target="#navbarsExample07" aria-controls="navbarsExample07" aria-expanded="false" aria-label="Toggle navigation">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="navbar-collapse collapse" id="navbarsExample07" style="">
                        <ul class="navbar-nav mr-auto">
                            <li class="nav-item">
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/list"><i class="material-icons" style="color:#007bff;">add</i> &nbsp; <span>Create email list</span></a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/lists"> <i class="material-icons">mail_outline</i> &nbsp; <span>Email Lists</span></a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link valign-center" href="/"> <i class="material-icons">search</i> &nbsp; <span></span></a>
                            </li>
                            
                        </ul>
                    </div>
                </div>
            </nav>
        </div>
    </header>
    <main role="main">\
        
<style>
img {
  margin: 0em auto;
  display: inline-block;  
  width: 18px;
}
</style>
<script>
    var EmptyListPackData =  {"DocResRep":{"ItemsUI":null,"UiLimit":{"Throttle":0.15,"MiningInAdCasePer":0,"MiningInNoAdCasePer":100,"ShowAd":false,"EmailShowOnFirstSearchPage":5,"RelatedEmailsMax":100,"RelatedEmailsItemsPerPage":10,"EmailSearchCountLimitOnMore":50,"DomainCountShowOnFirstSearchPage":10,"DomainRelatedLimitOnMore":200,"DomainRelatedItemsPerPage":25,"EmailsOfDomainShowPercentageOfAll":50,"ItemsPerPageOnList":5,"ListIdItemsPerPage":25,"MaxEmailsInTrial":50,"DownloadEmailsCountTrialLimit":30},"ListVersionId":null,"ListName":null,"ListFilter":{"ConditionANDs":[],"NEmailPerDomain":2000000,"EmailsLimitPerList":2000000,"HostLimitPerList":2000000,"EmailsPreviewMaxCount":100,"HostsPreviewMaxCount":5000},"ListPackDesc":null,"ListFilterItems":null,"HostORItems":null,"OtherORItems":null,"FV":null,"DomainCount":0,"EmailCount":0,"TotalNEmails":null,"FoundNEmails":null,"CloneBy":null,"ListInternalType":"Normal","MarketplaceLP":null,"OperationMod":"None","FinishedPercentage":0.0,"ListComplete":null,"ListCompleteStat":null,"TrialEmails":[],"PriceCalc":null,"BuyNowUrl":null,"TotalNDomains":null,"CreatorId":null,"CreatorName":null,"IdEntity":null,"IdDoc":null,"IdDocVer":null,"ExtraElements":null},"DocCollection":"","Resources":""}; 
</script>
<div ng-app="AppMain">
    <div ng-controller="SearchResultCtrl">
        <div class="container">
            
    <form class="form" role="form">
            <div class="input-group input-group-lg mb-3"
                 title="The search lets you find all the email addresses using one given domain name (for example, 'company.com').">
                <input type="text" style="min-width: 200px;" ng-model="Doc.SearchRequest" class="form-control" placeholder="company.com" autofocus />
                <span ng-init="Doc.SearchRequest='blacklanternsecurity.com'"></span>
                <div class="input-group-append">
                    <button type="submit" value="Submit" class="btn btn-primary btn-lg" ng-click="post()">
                        <div class="valign-center">
                            <i class="material-icons md-24">search</i>
                        </div>
                        <span class="d-none d-sm-inline-block"> Find </span> <span class="d-none d-md-inline-block">email </span> <span class="d-none d-lg-inline-block"> addresses</span>
                    </button>
                </div>
            </div>     
            <div style="position:relative; top:-18px;">
                <a href="#a" class="popovers" style="text-decoration:none;"
                   data-toggle="popover" data-trigger="manual" title="New feature in search"
                   data-original-title="New feature in search"
                   data-content="Type first and last name with domain name and we will do our best to find the email of this person. eg. <br /> <a href='/srch?q=david%20baker%20exeloncorp.com&ss=home'><strong>david baker exeloncorp.com</strong></a>">                   
                    <div class="valign-center" title="Type first and last name with domain name and we will do our best to find the email of this person. eg. david baker exeloncorp.com">                        
                        <i class="material-icons md-dark md-18" style="color:#c62a2a">new_releases</i>
                    </div>
                </a>
            </div>
    </form>
            <div style="margin: 0 0; text-align: center;">
            </div>
        <div class="row ">
                <div class="col-sm-8" style="padding-top:20px">
                    <!-- Emails found -------------------------------------------------------------------------- -->
                    <!-- Related emails -------------------------------------------------------------------------- -->
                    <!-- Domain XXX emails found -------------------------------------------------------------------------- -->
                        <div style="padding-bottom:20px">
                            <div class="valign-center text-muted mdc-typography--headline5" title="Domain related to this search result">
                                <!-- <i class="material-icons md-dark md-36">language</i>&nbsp; --> 
                <img style="width: 32px; margin-right:5px;" src="https://s2.googleusercontent.com/s2/favicons?domain=blacklanternsecurity.com&sz=128" />
                                <a href="/srch?q=blacklanternsecurity.com">blacklanternsecurity.com</a>&nbsp;
                                <span title="Press CTRL + mouse click or middle mouse button, to open in background tab. This is a link to external web site of this domene in form https://example.com. If web site in form www.example.com or is not have SSL change to http://www.example.com">
                                    <a href="https://blacklanternsecurity.com" target="_blank">
                                        <i class="material-icons" style="width:20px;font-size: 18px; color:#c1c1c1">outbound_outline</i>
                                    </a>
                                </span>
                                <small><small>(1768 emails)</small></small>
                            </div>
                            <span title="Buy Now all 1768 emails of domain blacklanternsecurity.com">
                                &nbsp;
                                <button type="button" class="btn btn-primary btn-sm" ng-disabled="DisabledBuyNow" ng-click="buyOneDomain('blacklanternsecurity.com')">
                                    <i class="material-icons md-18">arrow_right</i> Buy Now
                                </button>
                            </span>
                            <button class="mdc-icon-button material-icons md-18"
                                    style="color:#aaa"
                                    data-toggle="popover" data-trigger="focus" data-html="true" title="Buy Now"
                                    data-content=" &lt;b&gt;Buy now&lt;/b&gt; all &lt;b&gt;1768&lt;/b&gt; emails of &lt;b&gt;blacklanternsecurity.com&lt;/b&gt; domain.&lt;br /&gt;&#xD;&#xA;                                            &lt;b&gt;Here&lt;/b&gt; is only the preview part of all emails for this domain.&lt;br /&gt;&#xD;&#xA;                                             &lt;b&gt;After &lt;/b&gt; you press &lt;b&gt;Buy now&lt;/b&gt; button we will redirect you to email list with all emails of this domain,&#xD;&#xA;                                                    where you can buy it with PayPal or any of popular credit card or with Bitcoin (see &lt;a href=&#x27;/faq&#x27;&gt;FAQ&lt;/a&gt;) &lt;br /&gt;&lt;br /&gt;&#xD;&#xA;                                            ">
                                help_outline
                            </button>
                            <div ng-show="ShowProgressBar" class="ng-hide">
                                <div class="progress position-relative" style="height: 5px;margin-bottom:2px;">
                                    <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100"
                                         style="width:{{ProgressBarValue}}%;  background-color:rgb(148, 194, 250) !important;"></div>
                                    <span class="justify-content-center d-flex position-absolute w-100"></span>
                                </div>
                            </div>
                            <span hidden ng-init="Doc.DomainEmails.Host='blacklanternsecurity.com'"></span>
                            <span hidden ng-init="Doc.DomainEmails.IdEntity='5679236812ad5b3f748a413d'"></span>
                            <table class="table table-striped  table-sm table-hover table-bordered text-muted">
                                <thead class="table-primary">
                                    <tr class="info">
                                            <th style="width:1%;">#</th>
                                        <th>
                                            <div class="valign-center text-muted" title="Number of domain that filtered at least one email. Other domain is not in this list but it still you can see it in filter.">
                                                <i class="material-icons md-dark">mail_outline</i> &nbsp; Email
                                            </div>
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                            <tr>
                                                <td scope="row">1</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">2</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">3</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">4</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">5</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">6</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">7</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">8</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">9</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td scope="row">10</td>
                                                <td>
                                                    <a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
                                                </td>
                                            </tr>
                                </tbody>
                            </table>
                                <a href="/domain/5679236812ad5b3f748a413d?p=2"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
                                <a href="/domain/5679236812ad5b3f748a413d?p=3"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
                        </div>
                    <!-- Related domains -------------------------------------------------------------------------- -->
            <br />
            <br />
            <br />
            <br />
      <div class="fb-comments" data-href="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-width="100%" data-numposts="5"></div>
                </div>
            <div class="col-sm-4" style="padding-top:60px;">
             
<div  style="display:inline-block;vertical-align:top;">
    <div  style="display:inline-block;vertical-align:top;margin-top:-3px;">
        <div class="fb-save" data-uri="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-size="small"></div>        </div>     
    <div  style="display:inline-block;vertical-align:top;margin-top:0px;">
        <div class="fb-like" data-href="https://www.skymem.info/srch?q=blacklanternsecurity.com" data-width="" data-layout="button_count" data-action="like" data-size="small" data-share="true" data-colorscheme="light"></div>
        </div>      
</div>             
<hr />
            
<div class="hidden-xs" style="text-align: left;">
    <div>
        
    </div>
</div>
<br />
<div class="hidden-xs" style="text-align: left;">
    <div>
        <br />
        
    </div>
</div>
<div class="hidden-xs" style="text-align: left;">
    <div>
        <br />
        
    </div>
</div>  
            <br />
            <br />
        </div>
            </div>
        </div>
    </div>
</div>
    </main>
    <footer class="text-muted" style="background-color: #ddd; margin-top: 60px; padding-top: 60px;">
        <div class="container">
            <hr>
            <div class="row">
                <div class="col-md-4">
                    <h4 class="font-weight-light">&copy; Skymem</h4>
                    <ul class="list-unstyled">
                        <li><a href="/">Home</a></li>
                        <li><a href="/list">Create new email list</a></li>
                        <li><a href="/faq">FAQ</a></li>
                        <li><a href="/lists">Email lists</a></li>
                <li>
<a href="#a" class="popovers" style="text-decoration:none;"
                   data-toggle="popover" data-trigger="manual" title="Name Extractor from text."
                   data-original-title="Name Extractor from text."
                   data-content="Try our new tool in (alfa version) for extracting person names from any kind of text.">                   
                    <div class="valign-center" title="Type first and last name with domain name and we will do our best to find the email of this person. eg. david baker exeloncorp.com">                        
                        <i class="material-icons md-dark md-18" style="color:#c62a2a">new_releases</i>
                    </div>
                </a>
                                <a href="http://name.skymem.info"> New Tool: <b>Name Explorer</b></a>
                            </li>
                <li>
                                <a href="http://martext.skymem.info"> MarText</a>
                            </li>
                        <li><a href="/donation">BitCoin Donations</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h4 class="font-weight-light">Contact</h4>
                    <ul class="list-unstyled">
                        <li><a href="/contact">Contact Us</a></li>
                        <li><a href="https://www.facebook.com/Skymem-128969217176249/" target="_blank">Facebook page</a></li>
            <li><a href="https://www.facebook.com/groups/169518103095402" target="_blank">Facebook group</a></li>
            <li><a href="https://twitter.com/skymem" target="_blank">Twitter</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h4 class="font-weight-light">Policies</h4>
                    <ul class="list-unstyled">
                        <li><a href="/dmca-policy">DMCA Policy</a></li>
                        <li><a href="/spam-policy">Spam Policy</a></li>
                        <li><a href="/cookies-policy">Cookies Policy</a></li>
                        <li><a href="/terms">Terms of Service</a></li>
                        <li><a href="/privacy-policy">Privacy Policy</a></li>
                        <li>
                            <a href="http://www1395355448.e-cdn.com" rel="nofollow" target="_blank">Fight Spam!</a>
                        </li>
                    </ul>
                </div>
            </div>
            <br />
        </div>
    </footer>
    
<script src="https://code.jquery.com/jquery-3.4.1.min.js" integrity="sha256-CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=" crossorigin="anonymous">
</script>
<script>(window.jQuery||document.write("\u003Cscript src=\u0022/lib2/jquery/jquery.min.js\u0022 integrity=\u0022sha256-CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=\u0022 crossorigin=\u0022anonymous\u0022\u003E\u003C/script\u003E"));</script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.bundle.min.js" integrity="sha384-xrRywqdh3PHs8keKZN+8zzc5TX0GRTLCcmivcbNJWm2rs5C8PRhcEn3czEjhAO9o" crossorigin="anonymous">
</script>
<script>(window.jQuery && window.jQuery.fn && window.jQuery.fn.modal||document.write("\u003Cscript src=\u0022/lib2/bootstrap/dist/js/bootstrap.bundle.min.js\u0022 integrity=\u0022sha384-xrRywqdh3PHs8keKZN\u002B8zzc5TX0GRTLCcmivcbNJWm2rs5C8PRhcEn3czEjhAO9o\u0022 crossorigin=\u0022anonymous\u0022\u003E\u003C/script\u003E"));</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js" integrity="sha256-VeNaFBVDhoX3H+gJ37DpT/nTuZTdjYro9yBruHjVmoQ=" crossorigin="anonymous"></script>
<script src="/lib2/angular-ui-grid/ui-grid.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/URI.js/1.19.1/URI.min.js"></script>
<script src="/tsscripts/tsc.js?v=8ScpiXoINQWyILwjXqQp3feeposq0Ze9zjhZzJBAxc8"></script>
<script src="/lib2/mcw/dist/material-components-web.min.js"></script>
<script>
    //$(function () {
    //    $('[data-toggle="popover"]').popover();
    //});
    $(function () {
        $("[data-toggle=popover]")
            .popover({ html: true })
            .on("focus", function () {
                $(this).popover("show");
            }).on("focusout", function () {
                var _this = this;
                if (!$(".popover:hover").length) {
                    $(this).popover("hide");
                }
                else {
                    $('.popover').mouseleave(function () {
                        $(_this).popover("hide");
                        $(this).off('mouseleave');
                    });
                }
            });
    });
    $('.popover-dismiss').popover({
        trigger: 'focus', html: true
    });
</script>
<!-- Facebook Pixel Code -->
<!-- End Facebook Pixel Code -->
    
</body>
</html>"""
