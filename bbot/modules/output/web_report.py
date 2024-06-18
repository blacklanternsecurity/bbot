from bbot.modules.output.base import BaseOutputModule
import markdown
import html


class web_report(BaseOutputModule):
    watched_events = ["URL", "TECHNOLOGY", "FINDING", "VULNERABILITY", "VHOST"]
    meta = {
        "description": "Create a markdown report with web assets",
        "created_date": "2023-02-08",
        "author": "@liquidsec",
    }
    options = {
        "output_file": "",
        "css_theme_file": "https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.1.0/github-markdown.min.css",
    }
    options_desc = {"output_file": "Output to file", "css_theme_file": "CSS theme URL for HTML output"}
    deps_pip = ["markdown~=3.4.3"]

    async def setup(self):
        html_css_file = self.config.get("css_theme_file", "")

        self.html_header = f"""
        <!DOCTYPE html>
        <html>
        <head>
        <link rel="stylesheet" href="{html_css_file}">
        </head>
        <body>
        """

        self.html_footer = "</body></html>"
        self.web_assets = {}
        self.markdown = ""

        self._prep_output_dir("web_report.html")
        return True

    async def handle_event(self, event):
        if event.type == "URL":
            parsed = event.parsed_url
            host = f"{parsed.scheme}://{parsed.netloc}/"
            if host not in self.web_assets.keys():
                self.web_assets[host] = {"URL": []}
            parent_chain = []

            current_parent = event.parent
            while not current_parent.type == "SCAN":
                parent_chain.append(
                    f" ({current_parent.module})---> [{current_parent.type}]:{html.escape(current_parent.pretty_string)}"
                )
                current_parent = current_parent.parent

            parent_chain.reverse()
            parent_chain_text = (
                "".join(parent_chain)
                + f" ({event.module})---> "
                + f"[{event.type}]:{html.escape(event.pretty_string)}"
            )
            self.web_assets[host]["URL"].append(f"**{html.escape(event.data)}**: {parent_chain_text}")

        else:
            current_parent = event.parent
            parsed = None
            while 1:
                if current_parent.type == "URL":
                    parsed = current_parent.parsed_url
                    break
                current_parent = current_parent.parent
                if current_parent.parent.type == "SCAN":
                    break
            if parsed:
                host = f"{parsed.scheme}://{parsed.netloc}/"
                if host not in self.web_assets.keys():
                    self.web_assets[host] = {"URL": []}
                if event.type not in self.web_assets[host].keys():
                    self.web_assets[host][event.type] = [html.escape(event.pretty_string)]
                else:
                    self.web_assets[host][event.type].append(html.escape(event.pretty_string))

    async def report(self):
        for host in self.web_assets.keys():
            self.markdown += f"# {host}\n\n"

            for event_type in self.web_assets[host].keys():
                self.markdown += f"### {event_type}\n"
                dedupe = []
                for e in self.web_assets[host][event_type]:
                    if e in dedupe:
                        continue
                    dedupe.append(e)
                    self.markdown += f"\n* {e}\n"
                self.markdown += "\n"

        if self.file is not None:
            self.file.write(self.html_header)
            self.file.write(markdown.markdown(self.markdown))
            self.file.write(self.html_footer)
            self.file.flush()
            self.info(f"Web Report saved to {self.output_file}")
