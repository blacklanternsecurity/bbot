from subprocess import CompletedProcess
from .base import ModuleTestBase


class Testwpscan(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wpscan"]

    wpscan_output_json = """{
  "banner": {
    "description": "WordPress Security Scanner by the WPScan Team",
    "version": "3.8.25",
    "authors": [
      "@_WPScan_",
      "@ethicalhack3r",
      "@erwan_lr",
      "@firefart"
    ],
    "sponsor": "Sponsored by Automattic - https://automattic.com/"
  },
  "start_time": 1717183319,
  "start_memory": 49950720,
  "target_url": "http://127.0.0.1:8888/",
  "target_ip": "172.29.64.1",
  "effective_url": "http://127.0.0.1:8888/",
  "interesting_findings": [
    {
      "url": "http://127.0.0.1:8888/",
      "to_s": "Headers",
      "type": "headers",
      "found_by": "Headers (Passive Detection)",
      "confidence": 100,
      "confirmed_by": {

      },
      "references": {

      },
      "interesting_entries": [
        "Server: Apache/2.4.38 (Debian)",
        "X-Powered-By: PHP/7.1.33"
      ]
    },
    {
      "url": "http://127.0.0.1:8888/xmlrpc.php",
      "to_s": "XML-RPC seems to be enabled: http://127.0.0.1:8888/xmlrpc.php",
      "type": "xmlrpc",
      "found_by": "Direct Access (Aggressive Detection)",
      "confidence": 100,
      "confirmed_by": {

      },
      "references": {
        "url": [
          "http://codex.wordpress.org/XML-RPC_Pingback_API"
        ],
        "metasploit": [
          "auxiliary/scanner/http/wordpress_ghost_scanner",
          "auxiliary/dos/http/wordpress_xmlrpc_dos",
          "auxiliary/scanner/http/wordpress_xmlrpc_login",
          "auxiliary/scanner/http/wordpress_pingback_access"
        ]
      },
      "interesting_entries": [

      ]
    },
    {
      "url": "http://127.0.0.1:8888/readme.html",
      "to_s": "WordPress readme found: http://127.0.0.1:8888/readme.html",
      "type": "readme",
      "found_by": "Direct Access (Aggressive Detection)",
      "confidence": 100,
      "confirmed_by": {

      },
      "references": {

      },
      "interesting_entries": [
        "/wp-admin/",
        "/wp-admin/admin-ajax.php",
        " "
      ]
    },
    {
      "url": "http://127.0.0.1:8888/wp-cron.php",
      "to_s": "The external WP-Cron seems to be enabled: http://127.0.0.1:8888/wp-cron.php",
      "type": "wp_cron",
      "found_by": "Direct Access (Aggressive Detection)",
      "confidence": 60,
      "confirmed_by": {

      },
      "references": {
        "url": [
          "https://www.iplocation.net/defend-wordpress-from-ddos",
          "https://github.com/wpscanteam/wpscan/issues/1299"
        ]
      },
      "interesting_entries": [

      ]
    }
  ],
  "version": {
    "number": "5.3",
    "release_date": "2019-11-12",
    "status": "insecure",
    "found_by": "Emoji Settings (Passive Detection)",
    "confidence": 100,
    "interesting_entries": [
      "http://127.0.0.1:8888/, Match: 'wp-includes\\/js\\/wp-emoji-release.min.js?ver=5.3'"
    ],
    "confirmed_by": {
      "Meta Generator (Passive Detection)": {
        "confidence": 60,
        "interesting_entries": [
          "http://127.0.0.1:8888/, Match: 'WordPress 5.3'"
        ]
      }
    },
    "vulnerabilities": [
      {
        "title": "WordPress <= 5.3 - Authenticated Improper Access Controls in REST API",
        "fixed_in": "5.3.1",
        "references": {
          "cve": [
            "2019-20043",
            "2019-16788"
          ],
          "url": [
            "https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw"
          ],
          "wpvulndb": [
            "4a6de154-5fbd-4c80-acd3-8902ee431bd8"
          ]
        }
      },
      {
        "title": "WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links",
        "fixed_in": "5.3.1",
        "references": {
          "cve": [
            "2019-20042"
          ],
          "url": [
            "https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/",
            "https://hackerone.com/reports/509930",
            "https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7"
          ],
          "wpvulndb": [
            "23553517-34e3-40a9-a406-f3ffbe9dd265"
          ]
        }
      },
      {
        "title": "WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content",
        "fixed_in": "5.3.1",
        "references": {
          "cve": [
            "2019-16781",
            "2019-16780"
          ],
          "url": [
            "https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v"
          ],
          "wpvulndb": [
            "be794159-4486-4ae1-a5cc-5c190e5ddf5f"
          ]
        }
      },
      {
        "title": "WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass",
        "fixed_in": "5.3.1",
        "references": {
          "cve": [
            "2019-20041"
          ],
          "url": [
            "https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/",
            "https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53"
          ],
          "wpvulndb": [
            "8fac612b-95d2-477a-a7d6-e5ec0bb9ca52"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated",
        "fixed_in": "5.3.3",
        "references": {
          "cve": [
            "2020-11027"
          ],
          "url": [
            "https://wordpress.org/news/2020/04/wordpress-5-4-1/",
            "https://core.trac.wordpress.org/changeset/47634/",
            "https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw"
          ],
          "wpvulndb": [
            "7db191c0-d112-4f08-a419-a1cd81928c4e"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.1 - Unauthenticated Users View Private Posts",
        "fixed_in": "5.3.3",
        "references": {
          "cve": [
            "2020-11028"
          ],
          "url": [
            "https://wordpress.org/news/2020/04/wordpress-5-4-1/",
            "https://core.trac.wordpress.org/changeset/47635/",
            "https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w"
          ],
          "wpvulndb": [
            "d1e1ba25-98c9-4ae7-8027-9632fb825a56"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer",
        "fixed_in": "5.3.3",
        "references": {
          "cve": [
            "2020-11025"
          ],
          "url": [
            "https://wordpress.org/news/2020/04/wordpress-5-4-1/",
            "https://core.trac.wordpress.org/changeset/47633/",
            "https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c"
          ],
          "wpvulndb": [
            "4eee26bd-a27e-4509-a3a5-8019dd48e429"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Search Block",
        "fixed_in": "5.3.3",
        "references": {
          "cve": [
            "2020-11030"
          ],
          "url": [
            "https://wordpress.org/news/2020/04/wordpress-5-4-1/",
            "https://core.trac.wordpress.org/changeset/47636/",
            "https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-vccm-6gmc-qhjh"
          ],
          "wpvulndb": [
            "e4bda91b-067d-45e4-a8be-672ccf8b1a06"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache",
        "fixed_in": "5.3.3",
        "references": {
          "cve": [
            "2020-11029"
          ],
          "url": [
            "https://wordpress.org/news/2020/04/wordpress-5-4-1/",
            "https://core.trac.wordpress.org/changeset/47637/",
            "https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c"
          ],
          "wpvulndb": [
            "e721d8b9-a38f-44ac-8520-b4a9ed6a5157"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads",
        "fixed_in": "5.3.3",
        "references": {
          "cve": [
            "2020-11026"
          ],
          "url": [
            "https://wordpress.org/news/2020/04/wordpress-5-4-1/",
            "https://core.trac.wordpress.org/changeset/47638/",
            "https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2",
            "https://hackerone.com/reports/179695"
          ],
          "wpvulndb": [
            "55438b63-5fc9-4812-afc4-2f1eff800d5f"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.2 - Authenticated XSS in Block Editor",
        "fixed_in": "5.3.4",
        "references": {
          "cve": [
            "2020-4046"
          ],
          "url": [
            "https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rpwf-hrh2-39jf",
            "https://pentest.co.uk/labs/research/subtle-stored-xss-wordpress-core/"
          ],
          "youtube": [
            "https://www.youtube.com/watch?v=tCh7Y8z8fb4"
          ],
          "wpvulndb": [
            "831e4a94-239c-4061-b66e-f5ca0dbb84fa"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.2 - Authenticated XSS via Media Files",
        "fixed_in": "5.3.4",
        "references": {
          "cve": [
            "2020-4047"
          ],
          "url": [
            "https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27"
          ],
          "wpvulndb": [
            "741d07d1-2476-430a-b82f-e1228a9343a4"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.2 - Open Redirection",
        "fixed_in": "5.3.4",
        "references": {
          "cve": [
            "2020-4048"
          ],
          "url": [
            "https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/",
            "https://github.com/WordPress/WordPress/commit/10e2a50c523cf0b9785555a688d7d36a40fbeccf",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5"
          ],
          "wpvulndb": [
            "12855f02-432e-4484-af09-7d0fbf596909"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.2 - Authenticated Stored XSS via Theme Upload",
        "fixed_in": "5.3.4",
        "references": {
          "cve": [
            "2020-4049"
          ],
          "exploitdb": [
            "48770"
          ],
          "url": [
            "https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p",
            "https://hackerone.com/reports/406289"
          ],
          "wpvulndb": [
            "d8addb42-e70b-4439-b828-fd0697e5d9d4"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.2 - Misuse of set-screen-option Leading to Privilege Escalation",
        "fixed_in": "5.3.4",
        "references": {
          "cve": [
            "2020-4050"
          ],
          "url": [
            "https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/",
            "https://github.com/WordPress/WordPress/commit/dda0ccdd18f6532481406cabede19ae2ed1f575d",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc"
          ],
          "wpvulndb": [
            "b6f69ff1-4c11-48d2-b512-c65168988c45"
          ]
        }
      },
      {
        "title": "WordPress < 5.4.2 - Disclosure of Password-Protected Page/Post Comments",
        "fixed_in": "5.3.4",
        "references": {
          "cve": [
            "2020-25286"
          ],
          "url": [
            "https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/",
            "https://github.com/WordPress/WordPress/commit/c075eec24f2f3214ab0d0fb0120a23082e6b1122"
          ],
          "wpvulndb": [
            "eea6dbf5-e298-44a7-9b0d-f078ad4741f9"
          ]
        }
      },
      {
        "title": "WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure",
        "fixed_in": "5.3.7",
        "references": {
          "cve": [
            "2021-29450"
          ],
          "url": [
            "https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/",
            "https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html",
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pmmh-2f36-wvhq",
            "https://core.trac.wordpress.org/changeset/50717/"
          ],
          "youtube": [
            "https://www.youtube.com/watch?v=J2GXmxAdNWs"
          ],
          "wpvulndb": [
            "6a3ec618-c79e-4b9c-9020-86b157458ac5"
          ]
        }
      },
      {
        "title": "WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer",
        "fixed_in": "5.3.8",
        "references": {
          "cve": [
            "2020-36326",
            "2018-19296"
          ],
          "url": [
            "https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62",
            "https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/",
            "https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9",
            "https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/"
          ],
          "youtube": [
            "https://www.youtube.com/watch?v=HaW15aMzBUM"
          ],
          "wpvulndb": [
            "4cd46653-4470-40ff-8aac-318bee2f998d"
          ]
        }
      },
      {
        "title": "WordPress < 5.8.2 - Expired DST Root CA X3 Certificate",
        "fixed_in": "5.3.10",
        "references": {
          "url": [
            "https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/",
            "https://core.trac.wordpress.org/ticket/54207"
          ],
          "wpvulndb": [
            "cc23344a-5c91-414a-91e3-c46db614da8d"
          ]
        }
      },
      {
        "title": "WordPress < 5.8 - Plugin Confusion",
        "fixed_in": "5.8",
        "references": {
          "cve": [
            "2021-44223"
          ],
          "url": [
            "https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/"
          ],
          "wpvulndb": [
            "95e01006-84e4-4e95-b5d7-68ea7b5aa1a8"
          ]
        }
      },
      {
        "title": "WordPress < 5.8.3 - SQL Injection via WP_Query",
        "fixed_in": "5.3.11",
        "references": {
          "cve": [
            "2022-21661"
          ],
          "url": [
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84",
            "https://hackerone.com/reports/1378209"
          ],
          "wpvulndb": [
            "7f768bcf-ed33-4b22-b432-d1e7f95c1317"
          ]
        }
      },
      {
        "title": "WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs",
        "fixed_in": "5.3.11",
        "references": {
          "cve": [
            "2022-21662"
          ],
          "url": [
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w",
            "https://hackerone.com/reports/425342",
            "https://blog.sonarsource.com/wordpress-stored-xss-vulnerability"
          ],
          "wpvulndb": [
            "dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8"
          ]
        }
      },
      {
        "title": "WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query",
        "fixed_in": "5.3.11",
        "references": {
          "cve": [
            "2022-21664"
          ],
          "url": [
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86"
          ],
          "wpvulndb": [
            "24462ac4-7959-4575-97aa-a6dcceeae722"
          ]
        }
      },
      {
        "title": "WordPress < 5.8.3 - Super Admin Object Injection in Multisites",
        "fixed_in": "5.3.11",
        "references": {
          "cve": [
            "2022-21663"
          ],
          "url": [
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h",
            "https://hackerone.com/reports/541469"
          ],
          "wpvulndb": [
            "008c21ab-3d7e-4d97-b6c3-db9d83f390a7"
          ]
        }
      },
      {
        "title": "WordPress < 5.9.2 - Prototype Pollution in jQuery",
        "fixed_in": "5.3.12",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/"
          ],
          "wpvulndb": [
            "1ac912c1-5e29-41ac-8f76-a062de254c09"
          ]
        }
      },
      {
        "title": "WP < 6.0.2 - Reflected Cross-Site Scripting",
        "fixed_in": "5.3.13",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/"
          ],
          "wpvulndb": [
            "622893b0-c2c4-4ee7-9fa1-4cecef6e36be"
          ]
        }
      },
      {
        "title": "WP < 6.0.2 - Authenticated Stored Cross-Site Scripting",
        "fixed_in": "5.3.13",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/"
          ],
          "wpvulndb": [
            "3b1573d4-06b4-442b-bad5-872753118ee0"
          ]
        }
      },
      {
        "title": "WP < 6.0.2 - SQLi via Link API",
        "fixed_in": "5.3.13",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/"
          ],
          "wpvulndb": [
            "601b0bf9-fed2-4675-aec7-fed3156a022f"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Stored XSS via wp-mail.php",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283"
          ],
          "wpvulndb": [
            "713bdc8b-ab7c-46d7-9847-305344a579c4"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Open Redirect via wp_nonce_ays",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095"
          ],
          "wpvulndb": [
            "926cd097-b36f-4d26-9c51-0dfab11c301b"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Email Address Disclosure via wp-mail.php",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44"
          ],
          "wpvulndb": [
            "c5675b59-4b1d-4f64-9876-068e05145431"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Reflected XSS via SQLi in Media Library",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc"
          ],
          "wpvulndb": [
            "cfd8b50d-16aa-4319-9c2d-b227365c2156"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - CSRF in wp-trackback.php",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0"
          ],
          "wpvulndb": [
            "b60a6557-ae78-465c-95bc-a78cf74a6dd0"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Stored XSS via the Customizer",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef"
          ],
          "wpvulndb": [
            "2787684c-aaef-4171-95b4-ee5048c74218"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Stored XSS via Comment Editing",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955"
          ],
          "wpvulndb": [
            "02d76d8e-9558-41a5-bdb6-3957dc31563b"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Content from Multipart Emails Leaked",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8"
          ],
          "wpvulndb": [
            "3f707e05-25f0-4566-88ed-d8d0aff3a872"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - SQLi in WP_Date_Query",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f"
          ],
          "wpvulndb": [
            "1da03338-557f-4cb6-9a65-3379df4cce47"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Stored XSS via RSS Widget",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492"
          ],
          "wpvulndb": [
            "58d131f5-f376-4679-b604-2b888de71c5b"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e"
          ],
          "wpvulndb": [
            "b27a8711-a0c0-4996-bd6a-01734702913e"
          ]
        }
      },
      {
        "title": "WP < 6.0.3 - Multiple Stored XSS via Gutenberg",
        "fixed_in": "5.3.14",
        "references": {
          "url": [
            "https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/",
            "https://github.com/WordPress/gutenberg/pull/45045/files"
          ],
          "wpvulndb": [
            "f513c8f6-2e1c-45ae-8a58-36b6518e2aa9"
          ]
        }
      },
      {
        "title": "WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding",
        "fixed_in": null,
        "references": {
          "cve": [
            "2022-3590"
          ],
          "url": [
            "https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/"
          ],
          "wpvulndb": [
            "c8814e6e-78b3-4f63-a1d3-6906a84c1f11"
          ]
        }
      },
      {
        "title": "WP < 6.2.1 - Directory Traversal via Translation Files",
        "fixed_in": "5.3.15",
        "references": {
          "cve": [
            "2023-2745"
          ],
          "url": [
            "https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/"
          ],
          "wpvulndb": [
            "2999613a-b8c8-4ec0-9164-5dfe63adf6e6"
          ]
        }
      },
      {
        "title": "WP < 6.2.1 - Thumbnail Image Update via CSRF",
        "fixed_in": "5.3.15",
        "references": {
          "url": [
            "https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/"
          ],
          "wpvulndb": [
            "a03d744a-9839-4167-a356-3e7da0f1d532"
          ]
        }
      },
      {
        "title": "WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery",
        "fixed_in": "5.3.15",
        "references": {
          "url": [
            "https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/"
          ],
          "wpvulndb": [
            "3b574451-2852-4789-bc19-d5cc39948db5"
          ]
        }
      },
      {
        "title": "WP < 6.2.2 - Shortcode Execution in User Generated Data",
        "fixed_in": "5.3.15",
        "references": {
          "url": [
            "https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/",
            "https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/"
          ],
          "wpvulndb": [
            "ef289d46-ea83-4fa5-b003-0352c690fd89"
          ]
        }
      },
      {
        "title": "WP < 6.2.1 - Contributor+ Content Injection",
        "fixed_in": "5.3.15",
        "references": {
          "url": [
            "https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/"
          ],
          "wpvulndb": [
            "1527ebdb-18bc-4f9d-9c20-8d729a628670"
          ]
        }
      },
      {
        "title": "WP < 6.3.2 - Denial of Service via Cache Poisoning",
        "fixed_in": "5.3.16",
        "references": {
          "url": [
            "https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/"
          ],
          "wpvulndb": [
            "6d80e09d-34d5-4fda-81cb-e703d0e56e4f"
          ]
        }
      },
      {
        "title": "WP < 6.3.2 - Subscriber+ Arbitrary Shortcode Execution",
        "fixed_in": "5.3.16",
        "references": {
          "url": [
            "https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/"
          ],
          "wpvulndb": [
            "3615aea0-90aa-4f9a-9792-078a90af7f59"
          ]
        }
      },
      {
        "title": "WP < 6.3.2 - Contributor+ Comment Disclosure",
        "fixed_in": "5.3.16",
        "references": {
          "cve": [
            "2023-39999"
          ],
          "url": [
            "https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/"
          ],
          "wpvulndb": [
            "d35b2a3d-9b41-4b4f-8e87-1b8ccb370b9f"
          ]
        }
      },
      {
        "title": "WP < 6.3.2 - Unauthenticated Post Author Email Disclosure",
        "fixed_in": "5.3.16",
        "references": {
          "cve": [
            "2023-5561"
          ],
          "url": [
            "https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/",
            "https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/"
          ],
          "wpvulndb": [
            "19380917-4c27-4095-abf1-eba6f913b441"
          ]
        }
      },
      {
        "title": "WordPress < 6.4.3 - Deserialization of Untrusted Data",
        "fixed_in": "5.3.17",
        "references": {
          "url": [
            "https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/"
          ],
          "wpvulndb": [
            "5e9804e5-bbd4-4836-a5f0-b4388cc39225"
          ]
        }
      },
      {
        "title": "WordPress < 6.4.3 - Admin+ PHP File Upload",
        "fixed_in": "5.3.17",
        "references": {
          "url": [
            "https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/"
          ],
          "wpvulndb": [
            "a8e12fbe-c70b-4078-9015-cf57a05bdd4a"
          ]
        }
      }
    ]
  },
  "main_theme": null,
  "plugins": {
    "social-warfare": {
      "slug": "social-warfare",
      "location": "http://127.0.0.1:8888/wp-content/plugins/social-warfare/",
      "latest_version": "4.4.6.3",
      "last_updated": "2024-04-07T19:32:00.000Z",
      "outdated": true,
      "readme_url": null,
      "directory_listing": null,
      "error_log_url": null,
      "found_by": "Comment (Passive Detection)",
      "confidence": 30,
      "interesting_entries": [

      ],
      "confirmed_by": {

      },
      "vulnerabilities": [
        {
          "title": "Social Warfare <= 3.5.2 - Unauthenticated Arbitrary Settings Update",
          "fixed_in": "3.5.3",
          "references": {
            "cve": [
              "2019-9978"
            ],
            "url": [
              "https://wordpress.org/support/topic/malware-into-new-update/",
              "https://www.wordfence.com/blog/2019/03/unpatched-zero-day-vulnerability-in-social-warfare-plugin-exploited-in-the-wild/",
              "https://threatpost.com/wordpress-plugin-removed-after-zero-day-discovered/143051/",
              "https://twitter.com/warfareplugins/status/1108826025188909057",
              "https://www.wordfence.com/blog/2019/03/recent-social-warfare-vulnerability-allowed-remote-code-execution/"
            ],
            "wpvulndb": [
              "32085d2d-1235-42b4-baeb-bc43172a4972"
            ]
          }
        },
        {
          "title": "Social Warfare <= 3.5.2 - Unauthenticated Remote Code Execution (RCE)",
          "fixed_in": "3.5.3",
          "references": {
            "url": [
              "https://www.webarxsecurity.com/social-warfare-vulnerability/"
            ],
            "wpvulndb": [
              "7b412469-cc03-4899-b397-38580ced5618"
            ]
          }
        },
        {
          "title": "Social Warfare < 4.3.1 - Subscriber+ Post Meta Deletion",
          "fixed_in": "4.3.1",
          "references": {
            "cve": [
              "2023-0402"
            ],
            "wpvulndb": [
              "5116068f-4b84-42ad-a88d-03e46096b41c"
            ]
          }
        },
        {
          "title": "Social Warfare < 4.4.0 - Post Meta Deletion via CSRF",
          "fixed_in": "4.4.0",
          "references": {
            "cve": [
              "2023-0403"
            ],
            "wpvulndb": [
              "7140abf5-5966-4361-bd51-ee29d3071a30"
            ]
          }
        },
        {
          "title": "Social Sharing Plugin - Social Warfare < 4.4.4 - Authenticated (Contributor+) Stored Cross-Site Scripting via Shortcode",
          "fixed_in": "4.4.4",
          "references": {
            "cve": [
              "2023-4842"
            ],
            "url": [
              "https://www.wordfence.com/threat-intel/vulnerabilities/id/8f5b9aff-0833-4887-ae59-df5bc88c7f91"
            ],
            "wpvulndb": [
              "ab221b58-369e-4010-ae36-be099b2f4c9b"
            ]
          }
        },
        {
          "title": "Social Sharing Plugin – Social Warfare < 4.4.6.2 - Authenticated(Contributor+) Stored Cross-Site Scripting via Shortcode",
          "fixed_in": "4.4.6.2",
          "references": {
            "cve": [
              "2024-1959"
            ],
            "url": [
              "https://www.wordfence.com/threat-intel/vulnerabilities/id/1016f16c-0ab2-4cac-a7a5-8d93a37e7894"
            ],
            "wpvulndb": [
              "26ad138e-990a-4401-84e4-ea694ccf6e7f"
            ]
          }
        },
        {
          "title": "Social Sharing Plugin – Social Warfare < 4.4.6 - Cross-Site Request Forgery",
          "fixed_in": "4.4.6",
          "references": {
            "cve": [
              "2024-34825"
            ],
            "url": [
              "https://www.wordfence.com/threat-intel/vulnerabilities/id/f105bee6-21b2-4014-bb0a-9e53c49e29b0"
            ],
            "wpvulndb": [
              "acb8b33c-6b74-4d65-a3a5-5cad0c1ea8b0"
            ]
          }
        }
      ],
      "version": {
        "number": "3.5.2",
        "confidence": 100,
        "found_by": "Comment (Passive Detection)",
        "interesting_entries": [
          "http://127.0.0.1:8888/, Match: 'Social Warfare v3.5.2'"
        ],
        "confirmed_by": {
          "Readme - Stable Tag (Aggressive Detection)": {
            "confidence": 80,
            "interesting_entries": [
              "http://127.0.0.1:8888/wp-content/plugins/social-warfare/readme.txt"
            ]
          },
          "Readme - ChangeLog Section (Aggressive Detection)": {
            "confidence": 50,
            "interesting_entries": [
              "http://127.0.0.1:8888/wp-content/plugins/social-warfare/readme.txt"
            ]
          }
        }
      }
    }
  },
  "config_backups": {

  },
  "vuln_api": {
    "plan": "free",
    "requests_done_during_scan": 0,
    "requests_remaining": 15
  },
  "stop_time": 1717183322,
  "elapsed": 3,
  "requests_done": 169,
  "cached_requests": 6,
  "data_sent": 59178,
  "data_sent_humanised": "57.791 KB",
  "data_received": 313184,
  "data_received_humanised": "305.844 KB",
  "used_memory": 225398784,
  "used_memory_humanised": "214.957 MB"
}"""

    async def setup_after_prep(self, module_test):
        async def wpscan_mock_run(*command, **kwargs):
            return CompletedProcess(command, 0, self.wpscan_output_json, "")

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run", wpscan_mock_run)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        vulnerabilities = [e for e in events if e.type == "VULNERABILITY"]
        technologies = [e for e in events if e.type == "TECHNOLOGY"]
        assert len(findings) == 1
        assert len(vulnerabilities) == 59
        assert len(technologies) == 4
